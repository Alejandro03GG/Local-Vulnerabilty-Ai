"""Safe recursive discovery of project roots that contain supported manifests."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Directory names skipped during recursive discovery (never descended into).
DEFAULT_EXCLUDE_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "target",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "vendor",
        ".idea",
        ".vscode",
        "coverage",
        "htmlcov",
    }
)

# Filenames that identify a scannable project root.
MANIFEST_MARKERS: frozenset[str] = frozenset(
    {
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "package.json",
        "Cargo.lock",
        "Cargo.toml",
    }
)


def discover_project_roots(
    root: Path,
    *,
    max_depth: int = 6,
    exclude_dir_names: frozenset[str] = DEFAULT_EXCLUDE_DIR_NAMES,
) -> list[Path]:
    """Return directories under ``root`` that contain supported manifests.

    Always includes ``root`` itself first. Never follows symlinks. Skips common
    dependency/cache directories. Depth is relative to ``root`` (0 = root only).
    """
    root = root.resolve()
    found: list[Path] = []
    seen: set[Path] = set()

    def _consider(directory: Path) -> None:
        resolved = directory.resolve()
        if resolved in seen:
            return
        if any((directory / marker).is_file() for marker in MANIFEST_MARKERS):
            seen.add(resolved)
            found.append(directory)

    _consider(root)

    def _walk(current: Path, depth: int) -> None:
        if depth >= max_depth:
            return
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name.lower())
        except OSError as exc:
            logger.debug("Skipping unreadable directory %s: %s", current, exc)
            return

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            if entry.name in exclude_dir_names or entry.name.startswith("."):
                # Still allow scanning a hidden project root only when explicitly
                # provided as ``root``; do not descend into dot-dirs.
                continue
            _consider(entry)
            _walk(entry, depth + 1)

    _walk(root, 0)
    return found
