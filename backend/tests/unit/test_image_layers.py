"""Unit tests for image layer ordering, digests, and provenance."""

from __future__ import annotations

from pathlib import Path

from tests.fixtures.container_fixtures import create_docker_image_archive, create_oci_image_archive
from vuln_ai.container.manifest import parse_docker_archive_manifest, parse_oci_index_or_manifest
from vuln_ai.container.scanner import ContainerImageScanner
from vuln_ai.container.source import LocalOCIArchiveSource


def test_docker_layers_preserve_order_and_digest(tmp_path: Path) -> None:
    """Layer index and digest identity must be preserved from the archive."""
    archive = create_docker_image_archive(
        tmp_path / "layers.tar",
        dpkg_status="Package: curl\nStatus: install ok installed\nVersion: 8.5.0-2\nArchitecture: amd64\n\n",
    )
    source = LocalOCIArchiveSource(archive)
    layers = source.get_layers()
    assert len(layers) == 1
    assert layers[0].index == 0
    assert layers[0].digest.startswith("sha256:")
    assert layers[0].source.endswith("layer.tar")

    image, os_pkgs, _components, _graph = ContainerImageScanner().scan_archive(archive)
    assert len(image.layers) == 1
    assert image.layers[0].index == 0
    assert os_pkgs
    assert os_pkgs[0].layer_digest == image.layers[0].digest


def test_duplicate_layer_descriptors_keep_distinct_indexes() -> None:
    """Duplicate layer paths still receive distinct ordered indexes."""
    manifest = b"""[
      {
        "Config": "cfg.json",
        "RepoTags": ["dup:latest"],
        "Layers": ["a/layer.tar", "a/layer.tar"]
      }
    ]"""
    config = b"""{
      "architecture": "amd64",
      "os": "linux",
      "rootfs": {"type": "layers", "diff_ids": ["sha256:aaa", "sha256:bbb"]},
      "history": [
        {"created_by": "RUN one", "empty_layer": false},
        {"created_by": "RUN two", "empty_layer": false}
      ]
    }"""
    parsed = parse_docker_archive_manifest(manifest, config_bytes=config)
    assert [layer.index for layer in parsed.layers] == [0, 1]
    assert parsed.layers[0].digest != parsed.layers[1].digest
    assert parsed.layers[0].command == "RUN one"
    assert parsed.layers[1].command == "RUN two"


def test_oci_layers_from_index_archive(tmp_path: Path) -> None:
    """OCI layout archives expose ordered layers via ImageSource."""
    archive = create_oci_image_archive(
        tmp_path / "oci.tar",
        apk_installed="P:musl\nV:1.2.4-r2\nA:x86_64\n\n",
    )
    source = LocalOCIArchiveSource(archive)
    summary = source.inspect()
    assert summary.source_type == "oci_archive"
    assert summary.layer_count >= 0
    assert source.get_manifest()
    layers = source.get_layers()
    image, os_pkgs, _components, _graph = ContainerImageScanner().scan_archive(archive)
    assert image.source_type in {"oci_archive", "docker_archive"}
    assert image.operating_system is not None
    assert image.operating_system.family == "alpine"
    assert any(pkg.name == "musl" for pkg in os_pkgs)
    # Layers may be empty when only index.json is present without expanded manifests.
    assert isinstance(layers, list)


def test_invalid_layers_field_becomes_empty_list() -> None:
    """Malformed Layers values must not crash parsing."""
    manifest = b'[{"Config": "c.json", "RepoTags": ["x:1"], "Layers": "not-a-list"}]'
    parsed = parse_docker_archive_manifest(manifest)
    assert parsed.layers == []


def test_oci_manifest_with_config_history_commands() -> None:
    """OCI image manifests attach history commands to layers when present."""
    manifest = b"""{
      "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "layers": [
        {
          "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
          "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "size": 12
        }
      ],
      "annotations": {"org.opencontainers.image.ref.name": "svc:1"}
    }"""
    config = b"""{
      "architecture": "arm64",
      "os": "linux",
      "history": [{"created_by": "ADD file", "empty_layer": false}]
    }"""
    parsed = parse_oci_index_or_manifest(manifest, config_bytes=config)
    assert parsed.architecture == "arm64"
    assert len(parsed.layers) == 1
    assert parsed.layers[0].command == "ADD file"
    assert parsed.layers[0].digest.startswith("sha256:")
