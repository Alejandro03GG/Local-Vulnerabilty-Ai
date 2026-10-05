"""Cargo lockfile scanner for Rust projects.

Parses Cargo.lock and Cargo.toml to resolve exact crate versions,
direct vs transitive dependencies, and graph edges.
Supports multiple versions of the same crate simultaneously.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Any

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyScope,
    DependencyType,
)
from vuln_ai.core.models import DetectedComponent, Ecosystem, normalize_component_name

logger = logging.getLogger(__name__)

_MAX_LOCKFILE_SIZE = 25 * 1024 * 1024


class CargoLockScanner:
    """Scanner for Cargo.lock files."""

    @property
    def name(self) -> str:
        return "Cargo Lock Scanner"

    @property
    def ecosystem(self) -> str:
        return "cargo"

    def can_scan(self, project_path: Path) -> bool:
        """Check if project contains Cargo.lock or Cargo.toml."""
        try:
            return (project_path / "Cargo.lock").is_file() or (
                project_path / "Cargo.toml"
            ).is_file()
        except OSError:
            return False

    def scan(self, project_path: Path) -> list[DetectedComponent]:
        """Scan project and return resolved components."""
        graph = self.scan_graph(project_path)
        return graph.resolve_components()


    def _locate_cargo_lock(self, project_path: Path, *, max_up: int = 4) -> Path | None:
        """Find Cargo.lock in project_path or a limited number of parent directories."""
        current = project_path.resolve()
        for _ in range(max_up + 1):
            candidate = current / "Cargo.lock"
            if candidate.is_file():
                return candidate
            if current.parent == current:
                break
            current = current.parent
        return None

    def scan_graph(self, project_path: Path) -> DependencyGraph:
        """Parse Cargo.lock and construct full DependencyGraph."""
        graph = DependencyGraph()
        lock_file = self._locate_cargo_lock(project_path) or (project_path / "Cargo.lock")
        manifest_file = project_path / "Cargo.toml"

        direct_crates: set[str] = set()
        dev_crates: set[str] = set()
        root_package_names: set[str] = set()

        if manifest_file.is_file():
            graph.manifests_detected.append("Cargo.toml")
            direct_crates, dev_crates, root_pkg = self._parse_cargo_toml(manifest_file)
            if root_pkg:
                root_package_names.add(normalize_component_name(root_pkg))

        if not lock_file.is_file():
            # Manifest-only fallback
            if manifest_file.is_file():
                self._populate_manifest_only(graph, manifest_file, direct_crates, dev_crates)
            return graph

        graph.lockfiles_detected.append("Cargo.lock")

        try:
            size = lock_file.stat().st_size
            if size > _MAX_LOCKFILE_SIZE:
                logger.error("Lockfile %s exceeds maximum size (%d bytes)", lock_file, size)
                return graph
            content = lock_file.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", lock_file, exc)
            return graph

        packages = data.get("package", [])
        if not isinstance(packages, list):
            return graph

        # First pass: walk sourceless (path/workspace) packages to discover direct edges.
        # H23: only skip the scanned crate's own [package].name as a "root". Other
        # sourceless lock entries are path members and MUST keep their lock versions.
        direct_crate_versions: dict[str, str | None] = {}
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            if not name:
                continue
            if "source" not in pkg:
                # Dependencies of path/workspace members are direct when declared by a root.
                norm_pkg = normalize_component_name(name)
                if norm_pkg in root_package_names:
                    for dep_entry in pkg.get("dependencies", []):
                        c_name, c_ver = self._parse_cargo_dependency_string(str(dep_entry))
                        norm_c = normalize_component_name(c_name)
                        direct_crates.add(norm_c)
                        if c_ver:
                            direct_crate_versions[norm_c] = c_ver

        # Second pass: build nodes and edges
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue

            norm_name = normalize_component_name(name)
            # Skip the root project itself if it matches the workspace crate
            if norm_name in root_package_names and "source" not in pkg:
                continue

            is_direct = False
            if norm_name in direct_crates or norm_name in dev_crates:
                req_ver = direct_crate_versions.get(norm_name)
                if req_ver:
                    is_direct = str(version) == req_ver or str(version).startswith(
                        req_ver.split(".")[0]
                    )
                else:
                    is_direct = True

            is_dev = norm_name in dev_crates
            scope = DependencyScope.DEV if is_dev else DependencyScope.RUNTIME

            metadata: dict[str, Any] = {}
            if "source" in pkg:
                metadata["source"] = pkg["source"]
            if "checksum" in pkg:
                metadata["checksum"] = pkg["checksum"]

            node = DependencyNode.create(
                name=name,
                version=str(version),
                ecosystem=Ecosystem.CARGO,
                source_file=str(lock_file),
                is_direct=is_direct,
                scope=scope,
                manifest_source=str(manifest_file)
                if is_direct and manifest_file.is_file()
                else None,
                lockfile_source=str(lock_file),
                metadata=metadata,
            )
            graph.add_node(node)

            # Record child dependencies (edges)
            for dep_entry in pkg.get("dependencies", []):
                child_name, child_ver = self._parse_cargo_dependency_string(str(dep_entry))
                edge = DependencyEdge(
                    parent_name=name,
                    parent_version=str(version),
                    child_name=child_name,
                    child_version=child_ver,
                    scope=scope,
                )
                graph.add_edge(edge)

        # If direct_crates was empty, mark roots with no incoming edges
        if not direct_crates and graph.nodes:
            incoming = {normalize_component_name(e.child_name) for e in graph.edges}
            for node in graph.nodes.values():
                if normalize_component_name(node.name) not in incoming:
                    node.is_direct = True
                    node.dependency_type = DependencyType.DIRECT

        return graph

    def _parse_cargo_toml(self, manifest_path: Path) -> tuple[set[str], set[str], str | None]:
        """Extract declared dependencies and package name from Cargo.toml."""
        direct: set[str] = set()
        dev: set[str] = set()
        root_name: str | None = None

        try:
            content = manifest_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", manifest_path, exc)
            return direct, dev, root_name

        root_name = data.get("package", {}).get("name")

        for k in data.get("dependencies", {}):
            direct.add(normalize_component_name(k))
        for k in data.get("dev-dependencies", {}):
            dev.add(normalize_component_name(k))
        for k in data.get("build-dependencies", {}):
            direct.add(normalize_component_name(k))

        # Check [workspace.dependencies]
        ws_deps = data.get("workspace", {}).get("dependencies", {})
        if isinstance(ws_deps, dict):
            for k in ws_deps:
                direct.add(normalize_component_name(k))

        return direct, dev, root_name

    def _populate_manifest_only(
        self,
        graph: DependencyGraph,
        manifest_path: Path,
        direct: set[str],
        dev: set[str],
    ) -> None:
        """Create unpinned components from Cargo.toml when Cargo.lock is absent."""
        try:
            content = manifest_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s for unpinned components: %s", manifest_path, exc)
            return

        for section_name, scope in [
            ("dependencies", DependencyScope.RUNTIME),
            ("dev-dependencies", DependencyScope.DEV),
            ("build-dependencies", DependencyScope.RUNTIME),
        ]:
            section = data.get(section_name, {})
            if not isinstance(section, dict):
                continue
            for name, spec in section.items():
                constraint = None
                resolved_version = None
                if isinstance(spec, str):
                    constraint = spec
                elif isinstance(spec, dict):
                    constraint = spec.get("version")
                    if not constraint and isinstance(spec.get("path"), str):
                        resolved_version = self._resolve_path_dependency_version(
                            manifest_path, spec["path"]
                        )
                        if resolved_version:
                            constraint = resolved_version

                node = DependencyNode.create(
                    name=name,
                    version=resolved_version,
                    ecosystem=Ecosystem.CARGO,
                    source_file=str(manifest_path),
                    is_direct=True,
                    scope=scope,
                    manifest_source=str(manifest_path),
                    version_constraint=constraint,
                )
                graph.add_node(node)


    @staticmethod
    def _resolve_path_dependency_version(manifest_path: Path, path_spec: str) -> str | None:
        """Resolve version for a Cargo path dependency by reading its Cargo.toml.

        Static parse only — never executes cargo/build scripts.
        """
        try:
            dep_manifest = (manifest_path.parent / path_spec / "Cargo.toml").resolve()
            # Contain reads to the scanned project tree when possible.
            project_root = manifest_path.parent.resolve()
            if project_root not in dep_manifest.parents and dep_manifest.parent != project_root:
                # Allow sibling paths under a shared workspace parent (one level up).
                workspace_root = project_root.parent
                if workspace_root not in dep_manifest.parents and dep_manifest.parent != workspace_root:
                    logger.debug("Refusing path dependency outside workspace tree: %s", dep_manifest)
                    return None
            if not dep_manifest.is_file():
                return None
            data = tomllib.loads(dep_manifest.read_text(encoding="utf-8"))
            version = data.get("package", {}).get("version")
            return str(version) if version else None
        except Exception as exc:
            logger.debug("Failed to resolve path dependency version for %s: %s", path_spec, exc)
            return None

    @staticmethod
    def _parse_cargo_dependency_string(dep_str: str) -> tuple[str, str | None]:
        """Parse dependency string from Cargo.lock.

        Formats:
          "serde_derive 1.0.197"
          "rand"
          "syn 2.0.48 (registry+https://...)"
        """
        parts = dep_str.strip().split()
        if not parts:
            return "", None
        name = parts[0]
        version = None
        if len(parts) >= 2 and not parts[1].startswith("("):
            version = parts[1]
        return name, version
