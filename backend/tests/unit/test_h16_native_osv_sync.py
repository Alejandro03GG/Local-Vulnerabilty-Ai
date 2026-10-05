"""H16: native OSV sync path (SourceService) must be idempotent without harness purge/dedupe.

These tests exercise the product path:
  OSVSource-like adapter → SourceService.sync_source → upsert_vulnerabilities
and prove robustness independent of any external seed_from_*/purge harness helpers.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.api.services.source_service import SourceService
from vuln_ai.core.models import (
    SyncResult,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.models import VulnerabilityDB, VulnerabilityIdentifierDB
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository
from vuln_ai.sources.base import VulnerabilitySource
from vuln_ai.sources.registry import SourceRegistry


def _osv_record(
    canonical_id: str,
    *,
    cve_id: str | None = None,
    aliases: list[str] | None = None,
    product: str = "pkg",
) -> VulnerabilityRecord:
    ids = [canonical_id, *(aliases or [])]
    if cve_id and cve_id not in ids:
        ids.append(cve_id)
    return VulnerabilityRecord(
        canonical_id=canonical_id,
        cve_id=cve_id,
        source_name="OSV",
        product=product,
        vulnerability_name=canonical_id,
        identifiers=[
            VulnerabilityIdentifier(identifier_type="OTHER", identifier=i) for i in ids
        ],
        source_records=[
            VulnerabilitySourceRecord(
                source_name="OSV",
                source_identifier=canonical_id,
                raw_payload={"id": canonical_id},
            )
        ],
    )


class ControllableOSVSource(VulnerabilitySource):
    """In-process OSV adapter used to drive the native SourceService sync path."""

    def __init__(self) -> None:
        self._records: list[VulnerabilityRecord] = []
        self._fail = False
        self.sync_calls = 0

    @property
    def name(self) -> str:
        return "OSV"

    @property
    def source_type(self) -> str:
        return "osv"

    @property
    def url(self) -> str:
        return "https://api.osv.dev/v1"

    @property
    def records(self) -> list[VulnerabilityRecord]:
        return list(self._records)

    def set_batch(self, records: list[VulnerabilityRecord]) -> None:
        self._records = list(records)

    def fail_next(self) -> None:
        self._fail = True

    async def sync(self) -> SyncResult:
        self.sync_calls += 1
        if self._fail:
            self._fail = False
            return SyncResult(
                source_name=self.name,
                success=False,
                error="simulated OSV sync failure",
                duration_seconds=0.01,
            )
        return SyncResult(
            source_name=self.name,
            success=True,
            records_synced=len(self._records),
            records_total=len(self._records),
            duration_seconds=0.01,
        )


async def _count_vulns(session: AsyncSession) -> int:
    res = await session.execute(select(func.count()).select_from(VulnerabilityDB))
    return int(res.scalar_one() or 0)


async def _count_idents(session: AsyncSession) -> int:
    res = await session.execute(select(func.count()).select_from(VulnerabilityIdentifierDB))
    return int(res.scalar_one() or 0)


@pytest.fixture
async def osv_sync_env(db_session: AsyncSession) -> tuple[SourceService, ControllableOSVSource, Any]:
    osv = ControllableOSVSource()
    registry = SourceRegistry()
    registry.register(osv)
    sources = SourceRepository(db_session)
    vulns = VulnerabilityRepository(db_session)
    db_source, _ = await sources.get_or_create(name="OSV", source_type="osv", url=osv.url)
    service = SourceService(sources, vulns, registry)
    return service, osv, db_source


async def test_h16_native_sync_repeated_three_times_is_idempotent(
    db_session: AsyncSession, osv_sync_env
) -> None:
    service, osv, db_source = osv_sync_env
    osv.set_batch(
        [
            _osv_record("GHSA-aaaa-bbbb-cccc"),
            _osv_record("CVE-2024-1111", cve_id="CVE-2024-1111"),
            _osv_record("OSV-PYPI-KEEP-1", product="requests"),
        ]
    )

    results = []
    for _ in range(3):
        results.append(await service.sync_source(db_source.id))

    assert all(r.success for r in results)
    assert await _count_vulns(db_session) == 3
    # record_count reflects catalog size, not cumulative batch * N
    assert results[-1].records == 3
    refreshed = await SourceRepository(db_session).get_by_id(db_source.id)
    assert refreshed is not None
    assert refreshed.status == "active"
    assert refreshed.record_count == 3
    assert osv.sync_calls == 3


async def test_h16_native_sync_same_records_again_no_duplicate_aliases(
    db_session: AsyncSession, osv_sync_env
) -> None:
    service, osv, db_source = osv_sync_env
    batch = [
        _osv_record(
            "CVE-2025-4242",
            cve_id="CVE-2025-4242",
            aliases=["GHSA-zzzz-yyyy-xxxx"],
        )
    ]
    osv.set_batch(batch)
    await service.sync_source(db_source.id)
    idents_after_first = await _count_idents(db_session)
    await service.sync_source(db_source.id)
    await service.sync_source(db_source.id)

    assert await _count_vulns(db_session) == 1
    assert await _count_idents(db_session) == idents_after_first
    vulns = VulnerabilityRepository(db_session)
    assert await vulns.get_by_identifier("CVE-2025-4242") is not None
    assert await vulns.get_by_identifier("GHSA-zzzz-yyyy-xxxx") is not None


async def test_h16_native_sync_partial_batches_preserve_other_ecosystems(
    db_session: AsyncSession, osv_sync_env
) -> None:
    service, osv, db_source = osv_sync_env

    osv.set_batch([_osv_record("OSV-PYPI-1", product="django")])
    await service.sync_source(db_source.id)
    osv.set_batch([_osv_record("OSV-NPM-1", product="lodash")])
    await service.sync_source(db_source.id)
    osv.set_batch([_osv_record("OSV-CRATES-1", product="serde")])
    await service.sync_source(db_source.id)

    assert await _count_vulns(db_session) == 3
    vulns = VulnerabilityRepository(db_session)
    assert await vulns.get_by_identifier("OSV-PYPI-1") is not None
    assert await vulns.get_by_identifier("OSV-NPM-1") is not None
    assert await vulns.get_by_identifier("OSV-CRATES-1") is not None


async def test_h16_native_sync_osv_never_passes_prune_missing(
    db_session: AsyncSession, osv_sync_env
) -> None:
    service, osv, db_source = osv_sync_env
    osv.set_batch([_osv_record("OSV-PROBE-1")])

    with patch.object(
        VulnerabilityRepository,
        "upsert_vulnerabilities",
        new_callable=AsyncMock,
        return_value=1,
    ) as upsert:
        # Keep real count_by_source working via side path — stub only upsert.
        await service.sync_source(db_source.id)
        assert upsert.await_count == 1
        kwargs = upsert.await_args.kwargs
        assert kwargs.get("prune_missing") is False


async def test_h16_native_sync_failure_preserves_existing_catalog(
    db_session: AsyncSession, osv_sync_env
) -> None:
    service, osv, db_source = osv_sync_env
    osv.set_batch([_osv_record("OSV-KEEP-BEFORE-FAIL")])
    ok = await service.sync_source(db_source.id)
    assert ok.success is True
    assert await _count_vulns(db_session) == 1

    osv.fail_next()
    osv.set_batch([_osv_record("OSV-SHOULD-NOT-LAND")])
    failed = await service.sync_source(db_source.id)
    assert failed.success is False
    assert "simulated OSV sync failure" in (failed.error or "")

    assert await _count_vulns(db_session) == 1
    vulns = VulnerabilityRepository(db_session)
    assert await vulns.get_by_identifier("OSV-KEEP-BEFORE-FAIL") is not None
    assert await vulns.get_by_identifier("OSV-SHOULD-NOT-LAND") is None

    refreshed = await SourceRepository(db_session).get_by_id(db_source.id)
    assert refreshed is not None
    assert refreshed.status == "error"


async def test_h16_native_sync_alias_bridge_collapses_orphan_rows(
    db_session: AsyncSession, osv_sync_env
) -> None:
    service, osv, db_source = osv_sync_env

    osv.set_batch([_osv_record("GHSA-orphan-1111-2222")])
    await service.sync_source(db_source.id)
    osv.set_batch([_osv_record("CVE-2025-9999", cve_id="CVE-2025-9999")])
    await service.sync_source(db_source.id)
    assert await _count_vulns(db_session) == 2

    osv.set_batch(
        [
            _osv_record(
                "CVE-2025-9999",
                cve_id="CVE-2025-9999",
                aliases=["GHSA-orphan-1111-2222"],
            )
        ]
    )
    await service.sync_source(db_source.id)

    assert await _count_vulns(db_session) == 1
    vulns = VulnerabilityRepository(db_session)
    row = await vulns.get_by_identifier("GHSA-orphan-1111-2222")
    assert row is not None
    assert row.canonical_id.upper().startswith("CVE-")
