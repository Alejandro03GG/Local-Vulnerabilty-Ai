"""Registry for vulnerability sources.

Allows registering and discovering vulnerability sources
without hard-coding them in the core engine.
"""

from __future__ import annotations

from vuln_ai.sources.base import VulnerabilitySource


class SourceRegistry:
    """Registry for vulnerability source implementations."""

    def __init__(self) -> None:
        self._sources: dict[str, VulnerabilitySource] = {}

    def register(self, source: VulnerabilitySource) -> None:
        """Register a vulnerability source."""
        self._sources[source.name] = source

    def get(self, name: str) -> VulnerabilitySource | None:
        """Get a source by name."""
        return self._sources.get(name)

    def list_sources(self) -> list[VulnerabilitySource]:
        """List all registered sources."""
        return list(self._sources.values())

    def __len__(self) -> int:
        return len(self._sources)

    def __contains__(self, name: str) -> bool:
        return name in self._sources
