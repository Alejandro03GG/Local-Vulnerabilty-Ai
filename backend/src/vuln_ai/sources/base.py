"""Abstract base for vulnerability sources.

Any new vulnerability source (NVD, OSV, GitHub Advisory, etc.)
should implement this protocol.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vuln_ai.core.models import SyncResult, VulnerabilityRecord


@runtime_checkable
class VulnerabilitySource(Protocol):
    """Interface for vulnerability data sources."""

    @property
    def name(self) -> str:
        """Human-readable name of this source."""
        ...

    @property
    def source_type(self) -> str:
        """Type identifier for this source (e.g., 'kev', 'nvd', 'osv')."""
        ...

    @property
    def url(self) -> str:
        """Primary URL for this source."""
        ...

    async def sync(self) -> SyncResult:
        """Download and return vulnerability records from this source.

        Returns:
            SyncResult with the parsed records and status.
        """
        ...

    async def search(
        self,
        component: str,
        vendor: str | None = None,
        product: str | None = None,
    ) -> list[VulnerabilityRecord]:
        """Search for vulnerabilities matching a component.

        This searches against already-synced local data.
        Call sync() first to populate the data.

        Args:
            component: Normalized component/package name.
            vendor: Optional vendor name filter.
            product: Optional product name filter.

        Returns:
            List of matching vulnerability records.
        """
        ...
