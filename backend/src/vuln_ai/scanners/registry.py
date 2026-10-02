"""Registry for project scanners."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.core.models import DetectedComponent
from vuln_ai.scanners.base import ProjectScanner


class ScannerRegistry:
    """Registry for scanner implementations."""

    def __init__(self) -> None:
        self._scanners: list[ProjectScanner] = []

    def register(self, scanner: ProjectScanner) -> None:
        """Register a project scanner."""
        self._scanners.append(scanner)

    def get_scanners_for(self, project_path: Path) -> list[ProjectScanner]:
        """Return all scanners that can handle the given project."""
        return [s for s in self._scanners if s.can_scan(project_path)]

    def scan_all(self, project_path: Path) -> list[DetectedComponent]:
        """Run all applicable scanners and return combined results."""
        components: list[DetectedComponent] = []
        seen: set[tuple[str, str | None, str]] = set()

        for scanner in self.get_scanners_for(project_path):
            for component in scanner.scan(project_path):
                # Deduplicate by (name, version, source_file)
                key = (component.name, component.version, component.source_file)
                if key not in seen:
                    seen.add(key)
                    components.append(component)

        return components

    def list_scanners(self) -> list[ProjectScanner]:
        """List all registered scanners."""
        return list(self._scanners)

    def __len__(self) -> int:
        return len(self._scanners)
