"""Abstract base for project scanners.

Any new scanner (Node, Docker, SBOM, etc.) should implement this protocol.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from vuln_ai.core.models import DetectedComponent


@runtime_checkable
class ProjectScanner(Protocol):
    """Interface for project scanners."""

    @property
    def name(self) -> str:
        """Human-readable name of this scanner."""
        ...

    @property
    def ecosystem(self) -> str:
        """Ecosystem this scanner targets (e.g., 'pypi', 'npm')."""
        ...

    def can_scan(self, project_path: Path) -> bool:
        """Return True if this scanner can handle the given project.

        Should check for the presence of ecosystem-specific files
        (e.g., requirements.txt, package.json).
        """
        ...

    def scan(self, project_path: Path) -> list[DetectedComponent]:
        """Scan a project and return detected components.

        Args:
            project_path: Root directory of the project.

        Returns:
            List of detected software components.
        """
        ...
