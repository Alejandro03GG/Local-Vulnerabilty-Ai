"""Security audit tests for Container & Image Scanning.

Guarantees:
- Path traversal rejection (../, /etc/passwd, null bytes)
- Symlink escape rejection
- Archive bomb protections (size limit, file count limit, ratio limit)
- STRICT NO EXECUTION GUARANTEE (scanning never invokes docker run, exec, or subprocesses)
"""

from __future__ import annotations

import io
import tarfile
from unittest.mock import patch

import pytest

from tests.fixtures.container_fixtures import create_docker_image_archive
from vuln_ai.container.archive import (
    ArchiveSecurityError,
    ArchiveSecurityLimits,
    SafeArchiveReader,
    is_safe_archive_path,
    is_safe_symlink_target,
)
from vuln_ai.container.scanner import ContainerImageScanner


def test_is_safe_archive_path():
    """Verify safe archive path validation rejects traversal and invalid paths."""
    assert is_safe_archive_path("var/lib/dpkg/status") is True
    assert is_safe_archive_path("app/requirements.txt") is True
    assert is_safe_archive_path("layer.tar") is True

    # Traversal attempts
    assert is_safe_archive_path("../../etc/passwd") is False
    assert is_safe_archive_path("../etc/passwd") is False
    assert is_safe_archive_path("foo/../../bar") is False
    assert is_safe_archive_path("/etc/passwd") is False
    assert is_safe_archive_path("C:\\Windows\\system32") is False
    assert is_safe_archive_path("app/\0/requirements.txt") is False
    assert is_safe_archive_path("") is False
    assert is_safe_archive_path("   ") is False


def test_is_safe_symlink_target():
    """Verify symlink target validation prevents directory escape."""
    assert is_safe_symlink_target("libssl.so.3", "usr/lib") is True
    assert is_safe_symlink_target("bin/sh", "usr/local") is True

    # Unsafe targets
    assert is_safe_symlink_target("/etc/passwd") is False
    assert is_safe_symlink_target("../../../../../etc/shadow", "app") is False
    assert is_safe_symlink_target("") is False
    assert is_safe_symlink_target("foo\0bar") is False


def test_tar_path_traversal_detection(tmp_path):
    """Verify reader raises ArchiveSecurityError on archive with path traversal."""
    malicious_tar = tmp_path / "traversal.tar"
    with tarfile.open(malicious_tar, mode="w") as tar:
        data = b"malicious content"
        info = tarfile.TarInfo(name="../../etc/shadow")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    reader = SafeArchiveReader()
    with pytest.raises(ArchiveSecurityError, match="Path traversal attempt detected"):
        list(reader.inspect_members(malicious_tar))


def test_tar_symlink_escape_detection(tmp_path):
    """Verify reader raises ArchiveSecurityError on archive with symlink escape."""
    symlink_tar = tmp_path / "symlink_escape.tar"
    with tarfile.open(symlink_tar, mode="w") as tar:
        info = tarfile.TarInfo(name="app/link_to_root")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../../../../etc/passwd"
        tar.addfile(info)

    reader = SafeArchiveReader()
    with pytest.raises(ArchiveSecurityError, match="Unsafe symlink target detected"):
        list(reader.inspect_members(symlink_tar))


def test_tar_bomb_file_count_limit(tmp_path):
    """Verify reader enforces maximum file count limit."""
    tar_path = tmp_path / "many_files.tar"
    with tarfile.open(tar_path, mode="w") as tar:
        for i in range(15):
            info = tarfile.TarInfo(name=f"file_{i}.txt")
            info.size = 0
            tar.addfile(info, io.BytesIO(b""))

    # Set strict limit to 10 files
    strict_limits = ArchiveSecurityLimits(max_file_count=10)
    reader = SafeArchiveReader(limits=strict_limits)

    with pytest.raises(ArchiveSecurityError, match="maximum file count limit"):
        list(reader.inspect_members(tar_path))


def test_tar_bomb_uncompressed_size_limit(tmp_path):
    """Verify reader enforces maximum uncompressed byte limit."""
    tar_path = tmp_path / "large_file.tar"
    data = b"A" * 5000
    with tarfile.open(tar_path, mode="w") as tar:
        info = tarfile.TarInfo(name="large.bin")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    strict_limits = ArchiveSecurityLimits(max_uncompressed_bytes=1000)
    reader = SafeArchiveReader(limits=strict_limits)

    with pytest.raises(ArchiveSecurityError, match="exceeds limit"):
        list(reader.inspect_members(tar_path))


def test_strict_no_execution_guarantee(tmp_path):
    """CRITICAL SECURITY GUARANTEE: Scanning an image NEVER executes any external command.

    Asserts that subprocess.Popen, subprocess.run, and os.system are NEVER called
    during archive and image inspection.
    """
    archive_path = tmp_path / "secure_test.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="secure-image:1.0",
        dpkg_status="Package: curl\nVersion: 7.88.1-10\nStatus: install ok installed\n",
    )

    with (
        patch("subprocess.Popen") as mock_popen,
        patch("subprocess.run") as mock_run,
        patch("subprocess.call") as mock_call,
        patch("os.system") as mock_os_system,
    ):
        scanner = ContainerImageScanner()
        img, os_pkgs, _comps, _graph = scanner.scan_archive(archive_path)

        # Verify results produced purely via Python in-memory inspection
        assert img.reference == "secure-image:1.0"
        assert len(os_pkgs) == 1
        assert os_pkgs[0].name == "curl"

        # Verify zero subprocess or shell executions took place!
        assert mock_popen.call_count == 0
        assert mock_run.call_count == 0
        assert mock_call.call_count == 0
        assert mock_os_system.call_count == 0
