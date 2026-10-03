"""Image source abstraction for static container artifact inspection.

Separates image acquisition from inspection. This stage implements the
safe local archive source; daemon/registry sources are reserved for later
stages and must never execute container workloads.
"""

from __future__ import annotations

import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from vuln_ai.container.archive import SafeArchiveReader
from vuln_ai.container.manifest import (
    ParsedManifest,
    parse_docker_archive_manifest,
    parse_oci_index_or_manifest,
)
from vuln_ai.container.models import ImageLayer


@dataclass(frozen=True)
class ImageInspectionSummary:
    """High-level metadata obtained without executing image content."""

    source_type: str
    path: str
    reference: str | None = None
    digest: str | None = None
    architecture: str | None = None
    os: str | None = None
    layer_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ImageSource(Protocol):
    """Protocol for static image acquisition backends."""

    def inspect(self) -> ImageInspectionSummary:
        """Return lightweight metadata about the image artifact."""
        ...

    def get_manifest(self) -> bytes:
        """Return raw manifest bytes (Docker manifest.json or OCI index/manifest)."""
        ...

    def get_config(self) -> bytes | None:
        """Return image config JSON bytes when available."""
        ...

    def get_layers(self) -> list[ImageLayer]:
        """Return ordered layer descriptors without extracting filesystem content."""
        ...

    def parse(self) -> ParsedManifest:
        """Parse the artifact into a normalized ParsedManifest."""
        ...


class LocalOCIArchiveSource:
    """Static reader for local Docker save / OCI layout archives (.tar).

    Never invokes docker/podman and never executes archive contents.
    """

    def __init__(
        self,
        archive_path: Path | str,
        reader: SafeArchiveReader | None = None,
    ) -> None:
        self.path = Path(archive_path)
        self.reader = reader or SafeArchiveReader()
        self._manifest_bytes: bytes | None = None
        self._config_bytes: bytes | None = None
        self._source_type: str = "unknown"
        self._parsed: ParsedManifest | None = None

    def _ensure_loaded(self) -> None:
        if self._parsed is not None:
            return
        if not self.path.is_file():
            raise FileNotFoundError(f"Image archive not found: {self.path}")

        # Security pass before format detection
        list(self.reader.inspect_members(self.path))

        with tarfile.open(self.path, mode="r:*") as root_tar:
            member_names = {m.name.lstrip("./"): m for m in root_tar.getmembers()}

            if "manifest.json" in member_names:
                self._source_type = "docker_archive"
                manifest_member = member_names["manifest.json"]
                extracted = root_tar.extractfile(manifest_member)
                self._manifest_bytes = extracted.read() if extracted else b"[]"

                try:
                    doc_manifest = json.loads(self._manifest_bytes.decode("utf-8"))
                    if isinstance(doc_manifest, list) and doc_manifest:
                        cfg_path = str(doc_manifest[0].get("Config", "")).lstrip("./")
                        if cfg_path and cfg_path in member_names:
                            cfg_extracted = root_tar.extractfile(member_names[cfg_path])
                            self._config_bytes = cfg_extracted.read() if cfg_extracted else None
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError, IndexError):
                    self._config_bytes = None

                self._parsed = parse_docker_archive_manifest(
                    manifest_bytes=self._manifest_bytes,
                    config_bytes=self._config_bytes,
                    archive_path=str(self.path),
                )
            elif "index.json" in member_names or "oci-layout" in member_names:
                self._source_type = "oci_archive"
                idx_member = member_names.get("index.json")
                if idx_member is not None:
                    extracted = root_tar.extractfile(idx_member)
                    index_bytes = extracted.read() if extracted else b"{}"
                else:
                    index_bytes = b"{}"

                manifest_bytes = index_bytes
                config_bytes: bytes | None = None
                try:
                    index_doc = json.loads(index_bytes.decode("utf-8"))
                    manifests = index_doc.get("manifests") if isinstance(index_doc, dict) else None
                    if isinstance(manifests, list) and manifests:
                        digest = str(manifests[0].get("digest") or "")
                        if digest.startswith("sha256:"):
                            blob_path = f"blobs/sha256/{digest[7:]}"
                            blob_member = member_names.get(blob_path)
                            if blob_member is not None:
                                blob_extracted = root_tar.extractfile(blob_member)
                                if blob_extracted is not None:
                                    manifest_bytes = blob_extracted.read()
                                    manifest_doc = json.loads(manifest_bytes.decode("utf-8"))
                                    cfg = (
                                        manifest_doc.get("config")
                                        if isinstance(manifest_doc, dict)
                                        else None
                                    )
                                    if isinstance(cfg, dict):
                                        cfg_digest = str(cfg.get("digest") or "")
                                        if cfg_digest.startswith("sha256:"):
                                            cfg_path = f"blobs/sha256/{cfg_digest[7:]}"
                                            cfg_member = member_names.get(cfg_path)
                                            if cfg_member is not None:
                                                cfg_extracted = root_tar.extractfile(cfg_member)
                                                config_bytes = (
                                                    cfg_extracted.read() if cfg_extracted else None
                                                )
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError, IndexError):
                    config_bytes = None

                self._manifest_bytes = manifest_bytes
                self._config_bytes = config_bytes
                self._parsed = parse_oci_index_or_manifest(
                    index_or_manifest_bytes=manifest_bytes,
                    config_bytes=config_bytes,
                    archive_path=str(self.path),
                )
            else:
                self._source_type = "filesystem_archive"
                self._manifest_bytes = (
                    b'[{"RepoTags": ["local-archive:latest"], "Layers": ["rootfs.tar"]}]'
                )
                self._parsed = parse_docker_archive_manifest(
                    manifest_bytes=self._manifest_bytes,
                    archive_path=str(self.path),
                )

    def inspect(self) -> ImageInspectionSummary:
        parsed = self.parse()
        return ImageInspectionSummary(
            source_type=self._source_type,
            path=str(self.path),
            reference=parsed.reference,
            digest=parsed.digest,
            architecture=parsed.architecture,
            os=parsed.os,
            layer_count=len(parsed.layers),
            metadata={"created_at": parsed.created_at.isoformat()},
        )

    def get_manifest(self) -> bytes:
        self._ensure_loaded()
        assert self._manifest_bytes is not None
        return self._manifest_bytes

    def get_config(self) -> bytes | None:
        self._ensure_loaded()
        return self._config_bytes

    def get_layers(self) -> list[ImageLayer]:
        return list(self.parse().layers)

    def parse(self) -> ParsedManifest:
        self._ensure_loaded()
        assert self._parsed is not None
        return self._parsed


class DockerDaemonSource:
    """Placeholder for future docker daemon acquisition (not implemented in Etapa 17)."""

    def __init__(self, reference: str) -> None:
        self.reference = reference

    def inspect(self) -> ImageInspectionSummary:
        raise NotImplementedError(
            "DockerDaemonSource is not implemented. Use LocalOCIArchiveSource with a "
            "static archive exported via `docker save` outside of vuln-ai."
        )

    def get_manifest(self) -> bytes:
        raise NotImplementedError("DockerDaemonSource is not implemented in Etapa 17.")

    def get_config(self) -> bytes | None:
        raise NotImplementedError("DockerDaemonSource is not implemented in Etapa 17.")

    def get_layers(self) -> list[ImageLayer]:
        raise NotImplementedError("DockerDaemonSource is not implemented in Etapa 17.")

    def parse(self) -> ParsedManifest:
        raise NotImplementedError("DockerDaemonSource is not implemented in Etapa 17.")


class OCIRegistrySource:
    """Placeholder for future OCI registry acquisition (no credential storage)."""

    def __init__(self, reference: str) -> None:
        self.reference = reference

    def inspect(self) -> ImageInspectionSummary:
        raise NotImplementedError(
            "OCIRegistrySource is not implemented. Export the image to a local archive "
            "and scan with LocalOCIArchiveSource. Credentials must never be persisted."
        )

    def get_manifest(self) -> bytes:
        raise NotImplementedError("OCIRegistrySource is not implemented in Etapa 17.")

    def get_config(self) -> bytes | None:
        raise NotImplementedError("OCIRegistrySource is not implemented in Etapa 17.")

    def get_layers(self) -> list[ImageLayer]:
        raise NotImplementedError("OCIRegistrySource is not implemented in Etapa 17.")

    def parse(self) -> ParsedManifest:
        raise NotImplementedError("OCIRegistrySource is not implemented in Etapa 17.")
