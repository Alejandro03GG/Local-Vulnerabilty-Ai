"""Parsers for OCI and Docker Image manifests and configurations.

Supports:
- Docker Image Archives (docker save format with manifest.json)
- OCI Image Layout Archives (oci-layout + index.json + blobs)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from vuln_ai.container.models import ContainerImage, ImageLayer

logger = logging.getLogger(__name__)


class ManifestParseError(Exception):
    """Raised when an image manifest is malformed, invalid JSON, or unsupported."""

    pass


@dataclass
class ParsedManifest:
    """Internal representation of a parsed image manifest and config."""

    reference: str
    digest: str
    architecture: str
    os: str
    created_at: datetime
    layers: list[ImageLayer]
    config_data: dict[str, Any]
    source_type: str
    raw_manifest: dict[str, Any]


def compute_sha256(data: bytes) -> str:
    """Compute canonical sha256:<hex> string."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def parse_iso_datetime(dt_str: str | None) -> datetime:
    """Safely parse ISO datetime string, falling back to UTC now."""
    if not dt_str:
        return datetime.now(UTC)
    try:
        # Replace trailing Z with +00:00 for fromisoformat
        clean = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return datetime.now(UTC)


def parse_docker_archive_manifest(
    manifest_bytes: bytes,
    config_bytes: bytes | None = None,
    archive_path: str = "",
) -> ParsedManifest:
    """Parse a Docker archive manifest.json and config file."""
    try:
        raw_manifest_list = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as e:
        raise ManifestParseError(f"Failed to parse Docker manifest.json as JSON: {e}") from e

    if not isinstance(raw_manifest_list, list) or len(raw_manifest_list) == 0:
        raise ManifestParseError("Docker manifest.json must be a non-empty list of image items")

    image_item = raw_manifest_list[0]
    if not isinstance(image_item, dict):
        raise ManifestParseError("Invalid image entry in Docker manifest.json")

    repo_tags = image_item.get("RepoTags") or []
    reference = repo_tags[0] if (isinstance(repo_tags, list) and repo_tags) else "unknown:latest"
    layer_tar_paths = image_item.get("Layers") or []
    if not isinstance(layer_tar_paths, list):
        layer_tar_paths = []

    config_data: dict[str, Any] = {}
    if config_bytes:
        try:
            config_data = json.loads(config_bytes.decode("utf-8"))
        except Exception as e:
            logger.warning("Could not parse Docker image config JSON: %s", e)

    arch = config_data.get("architecture") or "amd64"
    os_name = config_data.get("os") or "linux"
    created_dt = parse_iso_datetime(config_data.get("created"))

    history = config_data.get("history") or []
    diff_ids = config_data.get("rootfs", {}).get("diff_ids", [])

    # Compute manifest digest from manifest payload
    manifest_digest = compute_sha256(manifest_bytes)

    # Build layers
    layers: list[ImageLayer] = []
    # Match history commands to non-empty layers
    non_empty_history = [h for h in history if not h.get("empty_layer", False)]

    for idx, layer_path in enumerate(layer_tar_paths):
        # Extract digest from diff_ids if available, or generate deterministic identifier
        diff_id = diff_ids[idx] if idx < len(diff_ids) else f"layer-{idx}"
        layer_digest = diff_id if diff_id.startswith("sha256:") else f"sha256:{diff_id}"

        cmd = None
        if idx < len(non_empty_history):
            cmd = non_empty_history[idx].get("created_by")

        layers.append(
            ImageLayer(
                digest=layer_digest,
                index=idx,
                size_bytes=0,
                media_type="application/vnd.docker.image.rootfs.diff.tar",
                command=cmd,
                source=str(layer_path),
                metadata={"diff_id": diff_id},
            )
        )

    return ParsedManifest(
        reference=reference,
        digest=manifest_digest,
        architecture=arch,
        os=os_name,
        created_at=created_dt,
        layers=layers,
        config_data=config_data,
        source_type="docker_archive",
        raw_manifest=image_item,
    )


def parse_oci_index_or_manifest(
    index_or_manifest_bytes: bytes,
    config_bytes: bytes | None = None,
    archive_path: str = "",
) -> ParsedManifest:
    """Parse an OCI index.json or OCI Image Manifest."""
    try:
        raw_data = json.loads(index_or_manifest_bytes.decode("utf-8"))
    except Exception as e:
        raise ManifestParseError(f"Failed to parse OCI data as JSON: {e}") from e

    if not isinstance(raw_data, dict):
        raise ManifestParseError("OCI manifest must be a JSON dictionary")

    # Check if index.json
    manifests = raw_data.get("manifests")
    if manifests and isinstance(manifests, list):
        first_manifest = manifests[0]
        reference = first_manifest.get("annotations", {}).get(
            "org.opencontainers.image.ref.name", "oci-image:latest"
        )
        manifest_digest = first_manifest.get("digest") or compute_sha256(index_or_manifest_bytes)
        layers_desc = []
    else:
        # Standard OCI Image Manifest
        reference = raw_data.get("annotations", {}).get(
            "org.opencontainers.image.ref.name", "oci-image:latest"
        )
        manifest_digest = compute_sha256(index_or_manifest_bytes)
        layers_desc = raw_data.get("layers") or []

    config_data: dict[str, Any] = {}
    if config_bytes:
        with contextlib.suppress(Exception):
            config_data = json.loads(config_bytes.decode("utf-8"))

    arch = config_data.get("architecture") or "amd64"
    os_name = config_data.get("os") or "linux"
    created_dt = parse_iso_datetime(config_data.get("created"))
    history = config_data.get("history") or []
    non_empty_history = [h for h in history if not h.get("empty_layer", False)]

    layers: list[ImageLayer] = []
    for idx, ldesc in enumerate(layers_desc):
        ldigest = ldesc.get("digest") or f"sha256:layer-{idx}"
        lsize = ldesc.get("size") or 0
        lmedia = ldesc.get("mediaType") or "application/vnd.oci.image.layer.v1.tar+gzip"
        cmd = None
        if idx < len(non_empty_history):
            cmd = non_empty_history[idx].get("created_by")

        layers.append(
            ImageLayer(
                digest=ldigest,
                index=idx,
                size_bytes=lsize,
                media_type=lmedia,
                command=cmd,
                source=f"blobs/{ldigest.replace(':', '/')}",
                metadata={"media_type": lmedia},
            )
        )

    return ParsedManifest(
        reference=reference,
        digest=manifest_digest,
        architecture=arch,
        os=os_name,
        created_at=created_dt,
        layers=layers,
        config_data=config_data,
        source_type="oci_archive",
        raw_manifest=raw_data,
    )


def to_container_image(
    parsed: ParsedManifest,
    image_id: str,
    source_path: str,
) -> ContainerImage:
    """Convert ParsedManifest into the canonical ContainerImage domain model."""
    return ContainerImage(
        id=image_id,
        reference=parsed.reference,
        digest=parsed.digest,
        architecture=parsed.architecture,
        os=parsed.os,
        created_at=parsed.created_at,
        source_type=parsed.source_type,
        source_path=source_path,
        layers=parsed.layers,
        metadata={"config": parsed.config_data},
    )
