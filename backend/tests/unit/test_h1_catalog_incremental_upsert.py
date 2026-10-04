"""H1/H16/H2 regression: catalog upsert must be incremental and idempotent."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import (
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.models import VulnerabilityDB
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository


def _record(canonical_id: str, *, cve_id: str | None = None) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        canonical_id=canonical_id,
        cve_id=cve_id,
        source_name="OSV",
        product="pkg",
        vulnerability_name=canonical_id,
        identifiers=[
            VulnerabilityIdentifier(identifier_type="OTHER", identifier=canonical_id)
        ],
        source_records=[
            VulnerabilitySourceRecord(
                source_name="OSV",
                source_identifier=canonical_id,
                raw_payload={"id": canonical_id},
            )
        ],
    )


async def _count(session: AsyncSession) -> int:
    res = await session.execute(select(func.count()).select_from(VulnerabilityDB))
    return int(res.scalar_one() or 0)


async def test_h1_partial_seed_preserves_prior_ecosystems(db_session: AsyncSession) -> None:
    """Seed PyPI then npm then crates: all three remain (no destructive replace)."""
    sources = SourceRepository(db_session)
    vulns = VulnerabilityRepository(db_session)
    osv, _ = await sources.get_or_create(name="OSV", source_type="osv")

    await vulns.upsert_vulnerabilities(osv.id, [_record("OSV-PYPI-1")])
    await vulns.upsert_vulnerabilities(osv.id, [_record("OSV-NPM-1")])
    await vulns.upsert_vulnerabilities(osv.id, [_record("OSV-CRATES-1")])

    assert await _count(db_session) == 3
    assert await vulns.get_by_identifier("OSV-PYPI-1") is not None
    assert await vulns.get_by_identifier("OSV-NPM-1") is not None
    assert await vulns.get_by_identifier("OSV-CRATES-1") is not None


async def test_h16_identical_seed_is_idempotent(db_session: AsyncSession) -> None:
    """Repeating the exact same seed must not inflate catalog size."""
    sources = SourceRepository(db_session)
    vulns = VulnerabilityRepository(db_session)
    osv, _ = await sources.get_or_create(name="OSV", source_type="osv")
    batch = [_record("GHSA-aaaa-bbbb-cccc"), _record("CVE-2024-1111", cve_id="CVE-2024-1111")]

    await vulns.upsert_vulnerabilities(osv.id, batch)
    count_after_first = await _count(db_session)
    await vulns.upsert_vulnerabilities(osv.id, batch)
    await vulns.upsert_vulnerabilities(osv.id, batch)
    assert await _count(db_session) == count_after_first == 2


async def test_h1_empty_batch_does_not_wipe_catalog(db_session: AsyncSession) -> None:
    """Empty upsert must never delete prior catalog rows (H2 wipe path)."""
    sources = SourceRepository(db_session)
    vulns = VulnerabilityRepository(db_session)
    osv, _ = await sources.get_or_create(name="OSV", source_type="osv")
    await vulns.upsert_vulnerabilities(osv.id, [_record("OSV-KEEP-1")])
    await vulns.upsert_vulnerabilities(osv.id, [])
    assert await _count(db_session) == 1
    assert await vulns.get_by_identifier("OSV-KEEP-1") is not None


async def test_h2_kev_enrichment_not_destroyed_by_osv_partial(
    db_session: AsyncSession,
) -> None:
    """OSV partial upsert must not delete a vuln also enriched by KEV."""
    sources = SourceRepository(db_session)
    vulns = VulnerabilityRepository(db_session)
    osv, _ = await sources.get_or_create(name="OSV", source_type="osv")
    kev, _ = await sources.get_or_create(name="CISA KEV", source_type="cisa_kev")

    await vulns.upsert_vulnerabilities(
        osv.id,
        [
            VulnerabilityRecord(
                canonical_id="CVE-2024-KEV1",
                cve_id="CVE-2024-KEV1",
                source_name="OSV",
                product="django",
                identifiers=[
                    VulnerabilityIdentifier(identifier_type="CVE", identifier="CVE-2024-KEV1")
                ],
                source_records=[
                    VulnerabilitySourceRecord(
                        source_name="OSV",
                        source_identifier="CVE-2024-KEV1",
                        raw_payload={},
                    )
                ],
            )
        ],
    )
    await vulns.upsert_vulnerabilities(
        kev.id,
        [
            VulnerabilityRecord(
                canonical_id="CVE-2024-KEV1",
                cve_id="CVE-2024-KEV1",
                source_name="CISA KEV",
                product="django",
                known_ransomware_use="Known",
                identifiers=[
                    VulnerabilityIdentifier(identifier_type="CVE", identifier="CVE-2024-KEV1")
                ],
                source_records=[
                    VulnerabilitySourceRecord(
                        source_name="CISA KEV",
                        source_identifier="CVE-2024-KEV1",
                        has_kev_evidence=True,
                        raw_payload={},
                    )
                ],
            )
        ],
        prune_missing=True,
    )
    # Later OSV probe for a different package must not erase CVE-2024-KEV1
    await vulns.upsert_vulnerabilities(osv.id, [_record("OSV-OTHER-PKG")])

    kept = await vulns.get_by_identifier("CVE-2024-KEV1")
    assert kept is not None
    assert kept.known_ransomware_use == "Known"
    assert await vulns.get_by_identifier("OSV-OTHER-PKG") is not None


async def test_alias_ghsa_and_cve_merge_to_one_row(db_session: AsyncSession) -> None:
    """GHSA then CVE alias must enrich one canonical vulnerability, not duplicate."""
    sources = SourceRepository(db_session)
    vulns = VulnerabilityRepository(db_session)
    osv, _ = await sources.get_or_create(name="OSV", source_type="osv")

    await vulns.upsert_vulnerabilities(
        osv.id,
        [
            VulnerabilityRecord(
                canonical_id="GHSA-1111-2222-3333",
                cve_id=None,
                source_name="OSV",
                product="lib",
                identifiers=[
                    VulnerabilityIdentifier(
                        identifier_type="GHSA", identifier="GHSA-1111-2222-3333"
                    )
                ],
                source_records=[
                    VulnerabilitySourceRecord(
                        source_name="OSV",
                        source_identifier="GHSA-1111-2222-3333",
                        raw_payload={},
                    )
                ],
            )
        ],
    )
    await vulns.upsert_vulnerabilities(
        osv.id,
        [
            VulnerabilityRecord(
                canonical_id="CVE-2025-4242",
                cve_id="CVE-2025-4242",
                source_name="OSV",
                product="lib",
                identifiers=[
                    VulnerabilityIdentifier(identifier_type="CVE", identifier="CVE-2025-4242"),
                    VulnerabilityIdentifier(
                        identifier_type="GHSA", identifier="GHSA-1111-2222-3333"
                    ),
                ],
                source_records=[
                    VulnerabilitySourceRecord(
                        source_name="OSV",
                        source_identifier="GHSA-1111-2222-3333",
                        raw_payload={},
                    )
                ],
            )
        ],
    )
    assert await _count(db_session) == 1
    row = await vulns.get_by_identifier("GHSA-1111-2222-3333")
    assert row is not None
    assert row.canonical_id == "CVE-2025-4242"
    assert row.cve_id == "CVE-2025-4242"
