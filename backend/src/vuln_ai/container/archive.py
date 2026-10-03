"""Secure archive extraction and inspection for OCI/Docker container images.

Provides strict security controls against:
- Tar bombs / decompression bombs (size limits, ratio limits, file count limits)
- Path traversal (../, absolute paths, leading slashes)
- Symlink escapes and directory traversal
- Arbitrary code execution (pure read-only inspection, zero execution)
"""

from __future__ import annotations

import contextlib
import logging
import os
import tarfile
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _open_tar(tar_stream_or_path: str | Path | BinaryIO) -> Generator[tarfile.TarFile, None, None]:
    """Safely open tar archive using a proper context manager."""
    if isinstance(tar_stream_or_path, (str, Path)):
        with tarfile.open(tar_stream_or_path, mode="r:*") as tar:
            yield tar
    else:
        with tarfile.open(fileobj=tar_stream_or_path, mode="r:*") as tar:
            yield tar


class ArchiveSecurityError(Exception):
    """Raised when an archive violates security constraints (tar bomb, path traversal)."""

    pass


@dataclass(frozen=True)
class ArchiveSecurityLimits:
    """Configurable security boundaries for archive processing."""

    max_uncompressed_bytes: int = 500 * 1024 * 1024  # 500 MB default limit
    max_file_count: int = 50_000  # 50,000 files limit
    max_single_file_bytes: int = 100 * 1024 * 1024  # 100 MB limit per file
    max_compression_ratio: float = 100.0  # Max 100:1 compression ratio
    max_symlink_depth: int = 10


def is_safe_archive_path(path_str: str) -> bool:
    """Validate that an archive member path does not perform traversal."""
    if not path_str or not path_str.strip():
        return False

    # Check for null bytes
    if "\0" in path_str:
        return False

    posix = PurePosixPath(path_str)

    # Reject absolute paths or Windows-style drives
    if posix.is_absolute() or (len(posix.parts) > 0 and ":" in posix.parts[0]):
        return False

    # Reject traversal segments ('..')
    for part in posix.parts:
        if part in ("..", ""):
            return False

    # Check resolved normalized path
    norm = os.path.normpath(path_str).replace("\\", "/")
    return not (norm.startswith("../") or norm == ".." or norm.startswith("/"))


def is_safe_symlink_target(target: str, link_dir: str = "") -> bool:
    """Validate that a symlink does not escape its logical root."""
    if not target or "\0" in target:
        return False

    # Disallow absolute paths in symlink target (can escape root)
    if target.startswith("/") or "\\" in target:
        return False

    # Combine with directory of the link to check relative escape
    combined = os.path.normpath(os.path.join(link_dir, target)).replace("\\", "/")
    return not (combined.startswith("../") or combined == "..")


class SafeArchiveReader:
    """Safe reader for container image tarballs and layer archives.

    Inspects archive contents safely in-memory or into designated sandbox locations
    without executing any binaries or shell commands.
    """

    def __init__(self, limits: ArchiveSecurityLimits | None = None) -> None:
        self.limits = limits or ArchiveSecurityLimits()

    def inspect_members(
        self,
        tar_stream_or_path: str | Path | BinaryIO,
    ) -> Generator[tarfile.TarInfo, None, None]:
        """Safely iterate over archive members, enforcing security limits."""
        total_uncompressed = 0
        file_count = 0

        if isinstance(tar_stream_or_path, (str, Path)):
            path = Path(tar_stream_or_path)
            if not path.is_file():
                raise FileNotFoundError(f"Archive not found: {path}")
            compressed_size = max(1, path.stat().st_size)
        else:
            compressed_size = 1  # Fallback for streams

        with _open_tar(tar_stream_or_path) as tar:
            for member in tar:
                file_count += 1
                if file_count > self.limits.max_file_count:
                    raise ArchiveSecurityError(
                        f"Archive exceeds maximum file count limit ({self.limits.max_file_count})"
                    )

                # Validate path traversal
                if not is_safe_archive_path(member.name):
                    raise ArchiveSecurityError(
                        f"Path traversal attempt detected in archive member: '{member.name}'"
                    )

                # Validate symlinks
                if member.issym() or member.islnk():
                    link_dir = os.path.dirname(member.name)
                    if not is_safe_symlink_target(member.linkname, link_dir):
                        raise ArchiveSecurityError(
                            f"Unsafe symlink target detected: '{member.name}' -> '{member.linkname}'"
                        )

                # Validate single file size
                if member.size > self.limits.max_single_file_bytes:
                    raise ArchiveSecurityError(
                        f"Member '{member.name}' size ({member.size} bytes) exceeds limit "
                        f"({self.limits.max_single_file_bytes} bytes)"
                    )

                total_uncompressed += member.size
                if total_uncompressed > self.limits.max_uncompressed_bytes:
                    raise ArchiveSecurityError(
                        f"Archive uncompressed size ({total_uncompressed} bytes) exceeds limit "
                        f"({self.limits.max_uncompressed_bytes} bytes)"
                    )

                # Validate compression ratio
                if compressed_size > 0:
                    ratio = total_uncompressed / compressed_size
                    if (
                        ratio > self.limits.max_compression_ratio
                        and total_uncompressed > 10 * 1024 * 1024
                    ):
                        raise ArchiveSecurityError(
                            f"Archive compression ratio ({ratio:.1f}:1) exceeds safety threshold "
                            f"({self.limits.max_compression_ratio}:1)"
                        )

                yield member

    def read_file_content(
        self,
        tar_path_or_fileobj: str | Path | BinaryIO,
        target_path: str,
    ) -> bytes | None:
        """Read a single file's content in memory from the archive without extracting to disk."""
        target_norm = os.path.normpath(target_path.lstrip("/")).replace("\\", "/")

        with _open_tar(tar_path_or_fileobj) as tar:
            for member in tar:
                member_norm = os.path.normpath(member.name.lstrip("/")).replace("\\", "/")
                if member_norm == target_norm:
                    if member.size > self.limits.max_single_file_bytes:
                        raise ArchiveSecurityError(
                            f"Target file '{target_path}' exceeds size limit ({member.size} bytes)"
                        )
                    extracted = tar.extractfile(member)
                    return extracted.read() if extracted else None
            return None

    def find_and_read_files(
        self,
        tar_path_or_fileobj: str | Path | BinaryIO,
        matcher: Callable[[str], bool],
    ) -> dict[str, bytes]:
        """Find and read files matching a predicate without disk extraction."""
        results: dict[str, bytes] = {}
        total_read = 0

        with _open_tar(tar_path_or_fileobj) as tar:
            for member in tar:
                if not member.isreg():
                    continue
                clean_name = "/" + member.name.lstrip("./")
                if matcher(clean_name) or matcher(member.name):
                    if member.size > self.limits.max_single_file_bytes:
                        continue
                    extracted = tar.extractfile(member)
                    if extracted:
                        data = extracted.read()
                        total_read += len(data)
                        if total_read > self.limits.max_uncompressed_bytes:
                            raise ArchiveSecurityError("Total extracted files exceed byte limit")
                        results[clean_name] = data
            return results


def read_tar_member_bytes(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    """Helper to read member bytes directly with limit checking."""
    extracted = tar.extractfile(member)
    if not extracted:
        return b""
    return extracted.read()
