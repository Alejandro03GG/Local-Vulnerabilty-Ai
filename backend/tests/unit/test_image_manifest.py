"""Unit tests for Docker and OCI manifest parsers."""

from __future__ import annotations

import json

import pytest

from vuln_ai.container.manifest import (
    ManifestParseError,
    compute_sha256,
    parse_docker_archive_manifest,
    parse_iso_datetime,
    parse_oci_index_or_manifest,
    to_container_image,
)


def test_compute_sha256():
    """Verify compute_sha256 produces valid sha256: hex string."""
    digest = compute_sha256(b"hello world")
    assert digest.startswith("sha256:")
    assert len(digest) == 71  # "sha256:" (7) + 64 hex chars


def test_parse_docker_archive_manifest_valid():
    """Verify standard Docker manifest.json with config is parsed correctly."""
    manifest_data = [
        {
            "Config": "c123.json",
            "RepoTags": ["myapp:1.0.0"],
            "Layers": ["layer1.tar", "layer2.tar"],
        }
    ]
    manifest_bytes = json.dumps(manifest_data).encode("utf-8")

    config_data = {
        "architecture": "arm64",
        "os": "linux",
        "created": "2026-03-01T15:30:00Z",
        "rootfs": {"diff_ids": ["sha256:aaa", "sha256:bbb"]},
        "history": [
            {"created_by": "ENV FOO=bar", "empty_layer": True},
            {"created_by": "RUN apt-get update", "empty_layer": False},
            {"created_by": "COPY . /app", "empty_layer": False},
        ],
    }
    config_bytes = json.dumps(config_data).encode("utf-8")

    parsed = parse_docker_archive_manifest(manifest_bytes, config_bytes)
    assert parsed.reference == "myapp:1.0.0"
    assert parsed.architecture == "arm64"
    assert parsed.os == "linux"
    assert parsed.source_type == "docker_archive"
    assert len(parsed.layers) == 2
    assert parsed.layers[0].digest == "sha256:aaa"
    assert parsed.layers[0].index == 0
    assert parsed.layers[0].command == "RUN apt-get update"
    assert parsed.layers[1].digest == "sha256:bbb"
    assert parsed.layers[1].index == 1
    assert parsed.layers[1].command == "COPY . /app"

    # Convert to ContainerImage
    img = to_container_image(parsed, "img-123", "/path/to/archive.tar")
    assert img.id == "img-123"
    assert img.reference == "myapp:1.0.0"
    assert img.architecture == "arm64"


def test_parse_docker_archive_manifest_malformed():
    """Verify malformed JSON or empty list raises ManifestParseError."""
    with pytest.raises(ManifestParseError, match="Failed to parse"):
        parse_docker_archive_manifest(b"not json")

    with pytest.raises(ManifestParseError, match="must be a non-empty list"):
        parse_docker_archive_manifest(b"[]")

    with pytest.raises(ManifestParseError, match="Invalid image entry"):
        parse_docker_archive_manifest(b'["not a dict"]')


def test_parse_docker_archive_manifest_missing_optional():
    """Verify fallback values when config is omitted or incomplete."""
    manifest_bytes = json.dumps([{"RepoTags": []}]).encode("utf-8")
    parsed = parse_docker_archive_manifest(manifest_bytes, None)
    assert parsed.reference == "unknown:latest"
    assert parsed.architecture == "amd64"
    assert parsed.os == "linux"
    assert len(parsed.layers) == 0


def test_parse_oci_index_valid():
    """Verify standard OCI index.json parsing."""
    index_data = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:11112222",
                "size": 1234,
                "annotations": {"org.opencontainers.image.ref.name": "alpine:3.19"},
            }
        ],
    }
    index_bytes = json.dumps(index_data).encode("utf-8")
    parsed = parse_oci_index_or_manifest(index_bytes)
    assert parsed.reference == "alpine:3.19"
    assert parsed.digest == "sha256:11112222"
    assert parsed.source_type == "oci_archive"


def test_parse_oci_manifest_valid():
    """Verify standard OCI image manifest with layers is parsed."""
    manifest_data = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:layer1digest",
                "size": 54321,
            }
        ],
        "annotations": {"org.opencontainers.image.ref.name": "test-oci:latest"},
    }
    manifest_bytes = json.dumps(manifest_data).encode("utf-8")
    parsed = parse_oci_index_or_manifest(manifest_bytes)
    assert parsed.reference == "test-oci:latest"
    assert len(parsed.layers) == 1
    assert parsed.layers[0].digest == "sha256:layer1digest"
    assert parsed.layers[0].size_bytes == 54321


def test_parse_oci_malformed():
    """Verify malformed JSON raises ManifestParseError."""
    with pytest.raises(ManifestParseError):
        parse_oci_index_or_manifest(b"{not-valid-json}")

    with pytest.raises(ManifestParseError, match="must be a JSON dictionary"):
        parse_oci_index_or_manifest(b'["list-not-dict"]')


def test_parse_iso_datetime():
    """Verify safe ISO datetime parsing."""
    dt = parse_iso_datetime("2026-03-01T12:00:00Z")
    assert dt.year == 2026
    assert dt.month == 3
    # Invalid returns current UTC datetime without crashing
    fallback = parse_iso_datetime("invalid-date")
    assert fallback is not None
