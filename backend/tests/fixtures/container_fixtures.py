"""Test fixtures and helpers for container and image testing."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path


def create_dummy_tar_bytes(files: dict[str, bytes | str]) -> bytes:
    """Create in-memory tarball bytes from a dictionary of relative paths and contents."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for filename, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def create_docker_image_archive(
    destination: Path,
    reference: str = "debian-test:latest",
    os_release: str = 'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION_CODENAME="bookworm"\n',
    dpkg_status: str | None = None,
    apk_installed: str | None = None,
    app_files: dict[str, str] | None = None,
) -> Path:
    """Create a fully valid Docker archive (.tar) on disk."""
    layer_files: dict[str, bytes | str] = {
        "etc/os-release": os_release,
    }

    if dpkg_status:
        layer_files["var/lib/dpkg/status"] = dpkg_status
    if apk_installed:
        layer_files["lib/apk/db/installed"] = apk_installed
    if app_files:
        for path_k, content_v in app_files.items():
            layer_files[path_k.lstrip("/")] = content_v

    layer_tar_bytes = create_dummy_tar_bytes(layer_files)
    layer_path = "layer1/layer.tar"

    config_dict = {
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-01-01T12:00:00Z",
        "history": [{"created_by": "RUN apt-get update", "empty_layer": False}],
        "rootfs": {
            "type": "layers",
            "diff_ids": [
                "sha256:1111222233334444555566667777888899990000aaaa11112222333344445555"
            ],
        },
    }
    config_bytes = json.dumps(config_dict).encode("utf-8")
    config_filename = "c1a2b3c4.json"

    manifest_list = [
        {
            "Config": config_filename,
            "RepoTags": [reference],
            "Layers": [layer_path],
        }
    ]
    manifest_bytes = json.dumps(manifest_list).encode("utf-8")

    with tarfile.open(destination, mode="w") as root_tar:
        # 1. manifest.json
        info_m = tarfile.TarInfo(name="manifest.json")
        info_m.size = len(manifest_bytes)
        root_tar.addfile(info_m, io.BytesIO(manifest_bytes))

        # 2. Config JSON
        info_c = tarfile.TarInfo(name=config_filename)
        info_c.size = len(config_bytes)
        root_tar.addfile(info_c, io.BytesIO(config_bytes))

        # 3. Layer tar
        info_l = tarfile.TarInfo(name=layer_path)
        info_l.size = len(layer_tar_bytes)
        root_tar.addfile(info_l, io.BytesIO(layer_tar_bytes))

    return destination


def create_oci_image_archive(
    destination: Path,
    reference: str = "alpine-test:latest",
    os_release: str = 'ID=alpine\nNAME="Alpine Linux"\nVERSION_ID="3.19.1"\n',
    apk_installed: str | None = None,
) -> Path:
    """Create a valid OCI layout archive (.tar) on disk."""
    layer_files = {
        "etc/os-release": os_release,
    }
    if apk_installed:
        layer_files["lib/apk/db/installed"] = apk_installed

    layer_bytes = create_dummy_tar_bytes(layer_files)
    layer_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    layer_blob_path = f"blobs/sha256/{layer_digest[7:]}"

    config_dict = {
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-01-01T12:00:00Z",
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }
    config_bytes = json.dumps(config_dict).encode("utf-8")
    config_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    config_blob_path = f"blobs/sha256/{config_digest[7:]}"

    manifest_dict = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": len(layer_bytes),
            }
        ],
        "annotations": {
            "org.opencontainers.image.ref.name": reference,
        },
    }
    manifest_bytes = json.dumps(manifest_dict).encode("utf-8")
    manifest_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    manifest_blob_path = f"blobs/sha256/{manifest_digest[7:]}"

    index_dict = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": len(manifest_bytes),
                "annotations": {"org.opencontainers.image.ref.name": reference},
            }
        ],
    }
    index_bytes = json.dumps(index_dict).encode("utf-8")
    layout_bytes = json.dumps({"imageLayoutVersion": "1.0.0"}).encode("utf-8")

    with tarfile.open(destination, mode="w") as root_tar:
        for name, data in [
            ("oci-layout", layout_bytes),
            ("index.json", index_bytes),
            (manifest_blob_path, manifest_bytes),
            (config_blob_path, config_bytes),
            (layer_blob_path, layer_bytes),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            root_tar.addfile(info, io.BytesIO(data))

    return destination
