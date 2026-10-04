"""Container and Image Scanner implementation.

Inspects OCI/Docker container image archives and Dockerfiles statically,
extracting operating system identification, OS packages, and application dependencies,
and constructing a unified Container Dependency Graph without executing any image code.
"""

from __future__ import annotations

import io
import logging
import tarfile
import tempfile
import uuid
from pathlib import Path

from vuln_ai.container.archive import SafeArchiveReader
from vuln_ai.container.dockerfile import parse_dockerfile_file
from vuln_ai.container.graph import build_container_dependency_graph
from vuln_ai.container.manifest import to_container_image
from vuln_ai.container.models import (
    ContainerImage,
    DockerfileDocument,
    OSPackage,
)
from vuln_ai.container.os_detect import detect_os_from_files
from vuln_ai.container.os_packages import extract_os_packages_from_files
from vuln_ai.container.source import LocalOCIArchiveSource
from vuln_ai.core.graph import DependencyGraph
from vuln_ai.core.models import DetectedComponent
from vuln_ai.scanners.cargo_scanner import CargoLockScanner
from vuln_ai.scanners.npm_scanner import NpmLockScanner
from vuln_ai.scanners.pnpm_scanner import PnpmLockScanner
from vuln_ai.scanners.poetry_scanner import PoetryLockScanner
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.scanners.uv_scanner import UvLockScanner

logger = logging.getLogger(__name__)

# Known OS release / package database paths
_OS_IDENT_PATHS = {
    "/etc/os-release",
    "/usr/lib/os-release",
    "/etc/debian_version",
    "/etc/alpine-release",
    "/etc/redhat-release",
    "/etc/centos-release",
    "/etc/fedora-release",
    "/etc/system-release",
}

_OS_PKG_DB_PATHS = {
    "/var/lib/dpkg/status",
    "/var/lib/dpkg/status-old",
    "/lib/apk/db/installed",
    "/etc/apk/installed",
}

_APP_MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "Cargo.toml",
    "Cargo.lock",
}


def _create_app_scanner_registry() -> ScannerRegistry:
    """Build a standard scanner registry with all application lockfile/manifest scanners."""
    registry = ScannerRegistry()
    registry.register(PythonScanner())
    registry.register(PoetryLockScanner())
    registry.register(UvLockScanner())
    registry.register(NpmLockScanner())
    registry.register(PnpmLockScanner())
    registry.register(CargoLockScanner())
    return registry


class ContainerImageScanner:
    """Performs static security inspection of container image archives and Dockerfiles."""

    def __init__(self, archive_reader: SafeArchiveReader | None = None) -> None:
        self.reader = archive_reader or SafeArchiveReader()
        self.app_scanner_registry = _create_app_scanner_registry()

    def scan_archive(
        self,
        archive_path: Path | str,
        image_id: str | None = None,
    ) -> tuple[ContainerImage, list[OSPackage], list[DetectedComponent], DependencyGraph]:
        """Scan a local OCI or Docker archive tarball.

        Returns:
            (ContainerImage, list[OSPackage], list[DetectedComponent], DependencyGraph)
        """
        path = Path(archive_path)
        if not path.is_file():
            raise FileNotFoundError(f"Image archive not found: {path}")

        actual_image_id = image_id or str(uuid.uuid4())

        # 0-1. Acquire + parse via ImageSource abstraction (static local archive only)
        source = LocalOCIArchiveSource(path, reader=self.reader)
        parsed_manifest = source.parse()
        image = to_container_image(parsed_manifest, actual_image_id, str(path))

        # 2. Inspect filesystem across layers to collect OS info, OS pkgs, and App files
        os_files: dict[str, bytes] = {}
        os_pkgs: list[OSPackage] = []
        app_files_by_layer: list[
            tuple[str, str, bytes]
        ] = []  # (layer_digest, path_in_container, content)

        with tarfile.open(path, mode="r:*") as root_tar:
            all_root_members = {m.name.lstrip("./"): m for m in root_tar.getmembers()}

            for layer in image.layers:
                layer_source = layer.source.lstrip("./")
                layer_member = all_root_members.get(layer_source)
                if not layer_member:
                    continue

                layer_stream = root_tar.extractfile(layer_member)
                if not layer_stream:
                    continue

                layer_bytes = layer_stream.read()
                layer.size_bytes = len(layer_bytes)

                # Inspect inner layer tarball
                try:
                    with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as inner_tar:
                        for inner_m in inner_tar:
                            if not inner_m.isreg():
                                continue

                            clean_path = "/" + inner_m.name.lstrip("./")

                            # Check for OS release identification files
                            if clean_path in _OS_IDENT_PATHS:
                                f = inner_tar.extractfile(inner_m)
                                if f:
                                    os_files[clean_path] = f.read()

                            # Check for OS package databases
                            elif clean_path in _OS_PKG_DB_PATHS or (
                                "rpm" in clean_path and clean_path.endswith("manifest")
                            ):
                                f = inner_tar.extractfile(inner_m)
                                if f:
                                    content = f.read()
                                    extracted = extract_os_packages_from_files(
                                        {clean_path: content},
                                        layer_digest=layer.digest,
                                    )
                                    os_pkgs.extend(extracted)

                            # Check for Application dependency manifests & lockfiles
                            file_name = Path(clean_path).name
                            if file_name in _APP_MANIFEST_NAMES:
                                f = inner_tar.extractfile(inner_m)
                                if f:
                                    app_files_by_layer.append((layer.digest, clean_path, f.read()))
                except Exception as e:
                    logger.debug("Layer %s could not be opened as tar: %s", layer.digest, e)

        # 3. Detect OS from collected release files
        detected_os = detect_os_from_files(os_files)
        image.operating_system = detected_os
        image.os = detected_os.name

        # Deduplicate OS packages by (ecosystem, name, version)
        seen_pkg_keys: set[tuple[str, str, str]] = set()
        deduped_os_pkgs: list[OSPackage] = []
        for pkg in os_pkgs:
            key = (pkg.ecosystem.value, pkg.name.lower(), pkg.version)
            if key not in seen_pkg_keys:
                seen_pkg_keys.add(key)
                deduped_os_pkgs.append(pkg)

        # Convert OS packages to standard DetectedComponent
        all_components: list[DetectedComponent] = [
            p.to_detected_component() for p in deduped_os_pkgs
        ]

        # 4. Process Application Dependency files using existing ScannerRegistry
        app_graphs: list[DependencyGraph] = []
        if app_files_by_layer:
            with tempfile.TemporaryDirectory(prefix="vuln_ai_container_scan_") as tmp_dir:
                tmp_path = Path(tmp_dir)
                file_layer_map: dict[str, str] = {}
                cont_path_map: dict[str, str] = {}

                for l_digest, cont_path, content in app_files_by_layer:
                    # Write file into temporary directory replicating its relative path
                    rel_path = cont_path.lstrip("/")
                    target_file = tmp_path / rel_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    target_file.write_bytes(content)
                    file_layer_map[str(target_file)] = l_digest
                    file_layer_map[rel_path] = l_digest
                    file_layer_map[cont_path] = l_digest
                    cont_path_map[str(target_file)] = cont_path
                    cont_path_map[rel_path] = cont_path

                # Find all directories that contain application manifest files
                manifest_dirs: set[Path] = set()
                if any((tmp_path / name).is_file() for name in _APP_MANIFEST_NAMES):
                    manifest_dirs.add(tmp_path)
                for f in tmp_path.rglob("*"):
                    if f.is_file() and f.name in _APP_MANIFEST_NAMES:
                        manifest_dirs.add(f.parent)

                # Scan each directory containing manifests
                for m_dir in sorted(manifest_dirs):
                    app_graph = self.app_scanner_registry.scan_graph(m_dir)
                    app_graphs.append(app_graph)

                    # Extract components from graph and annotate with layer & container path
                    for node in app_graph.nodes.values():
                        comp = node.to_component()
                        # Resolve container path and layer
                        matched_layer = None
                        matched_cont_path = None
                        for path_key, ldigest in file_layer_map.items():
                            if node.source_file and (
                                path_key in node.source_file or node.source_file.endswith(path_key)
                            ):
                                matched_layer = ldigest
                                matched_cont_path = cont_path_map.get(path_key)
                                break

                        meta = dict(comp.metadata)
                        if matched_layer:
                            meta["container_layer"] = matched_layer
                        meta["container_image"] = image.reference
                        if matched_cont_path:
                            comp.source_file = matched_cont_path
                            meta["container_path"] = matched_cont_path
                        elif node.source_file:
                            meta["container_path"] = node.source_file
                        comp.metadata = meta
                        all_components.append(comp)

        # 5. Build unified Container Dependency Graph
        container_graph = build_container_dependency_graph(
            image=image,
            os_packages=deduped_os_pkgs,
            app_graphs=app_graphs,
        )

        return image, deduped_os_pkgs, all_components, container_graph

    def scan_dockerfile(
        self,
        dockerfile_path: Path | str,
    ) -> DockerfileDocument:
        """Scan a Dockerfile statically, returning its complete AST and findings."""
        return parse_dockerfile_file(dockerfile_path)
