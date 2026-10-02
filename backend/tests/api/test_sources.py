"""Tests for sources API endpoints."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.api.deps import get_source_registry
from vuln_ai.api.main import app
from vuln_ai.core.models import SyncResult, VulnerabilityRecord
from vuln_ai.db.repositories import SourceRepository
from vuln_ai.sources.base import VulnerabilitySource
from vuln_ai.sources.registry import SourceRegistry


class DummyMockSource(VulnerabilitySource):
    def __init__(self, name: str = "Mock KEV", should_succeed: bool = True):
        self._name = name
        self._should_succeed = should_succeed
        self._records = [
            VulnerabilityRecord(
                cve_id="CVE-2024-7777",
                source_name=name,
                vendor_project="TestVendor",
                product="TestProduct",
                vulnerability_name="Test Flaw",
            )
        ]

    @property
    def name(self) -> str:
        return self._name

    @property
    def source_type(self) -> str:
        return "mock_type"

    @property
    def url(self) -> str:
        return "https://example.com/feed.json"

    @property
    def records(self) -> list[VulnerabilityRecord]:
        return self._records

    async def sync(self) -> SyncResult:
        if self._should_succeed:
            return SyncResult(
                source_name=self.name,
                success=True,
                records_synced=len(self._records),
                records_total=len(self._records),
                duration_seconds=0.05,
            )
        return SyncResult(
            source_name=self.name,
            success=False,
            error="Connection timeout",
            duration_seconds=0.05,
        )


async def test_list_sources(api_client: AsyncClient, db_session: AsyncSession):
    """GET /api/v1/sources returns registered sources."""
    response = await api_client.get("/api/v1/sources")
    assert response.status_code == 200
    items = response.json()
    assert len(items) >= 1
    assert any(s["name"] == "CISA KEV" for s in items)


async def test_get_source_status(api_client: AsyncClient, db_session: AsyncSession):
    """GET /api/v1/sources/{id}/status returns source status."""
    source_repo = SourceRepository(db_session)
    source, _ = await source_repo.get_or_create(name="Status Source", source_type="test")

    response = await api_client.get(f"/api/v1/sources/{source.id}/status")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == source.id
    assert data["name"] == "Status Source"


async def test_get_source_status_not_found(api_client: AsyncClient):
    """GET /api/v1/sources/{missing}/status returns 404."""
    response = await api_client.get("/api/v1/sources/missing-id/status")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SOURCE_NOT_FOUND"


async def test_sync_source_success(api_client: AsyncClient, db_session: AsyncSession):
    """POST /api/v1/sources/{id}/sync downloads and persists vulnerabilities."""
    mock_src = DummyMockSource("Sync Success Source", should_succeed=True)
    registry = SourceRegistry()
    registry.register(mock_src)

    app.dependency_overrides[get_source_registry] = lambda: registry

    try:
        source_repo = SourceRepository(db_session)
        source, _ = await source_repo.get_or_create(
            name="Sync Success Source",
            source_type="mock_type",
        )

        response = await api_client.post(f"/api/v1/sources/{source.id}/sync")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["records"] == 1
        assert data["source"] == "Sync Success Source"

        # Verify DB status updated
        updated = await source_repo.get_by_id(source.id)
        assert updated.status == "active"
        assert updated.record_count == 1
    finally:
        app.dependency_overrides.pop(get_source_registry, None)


async def test_sync_source_failure(api_client: AsyncClient, db_session: AsyncSession):
    """POST /api/v1/sources/{id}/sync records error when sync fails."""
    mock_src = DummyMockSource("Sync Failing Source", should_succeed=False)
    registry = SourceRegistry()
    registry.register(mock_src)

    app.dependency_overrides[get_source_registry] = lambda: registry

    try:
        source_repo = SourceRepository(db_session)
        source, _ = await source_repo.get_or_create(
            name="Sync Failing Source",
            source_type="mock_type",
        )

        response = await api_client.post(f"/api/v1/sources/{source.id}/sync")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert data["error"] == "Connection timeout"

        # Verify DB status updated to error
        updated = await source_repo.get_by_id(source.id)
        assert updated.status == "error"
        assert updated.last_error == "Connection timeout"
    finally:
        app.dependency_overrides.pop(get_source_registry, None)


async def test_sync_source_not_found(api_client: AsyncClient):
    """POST /api/v1/sources/{missing}/sync returns 404."""
    response = await api_client.post("/api/v1/sources/missing-id/sync")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SOURCE_NOT_FOUND"
