"""Tests for OSV complex range representations and multi-source deduplication audit."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import (
    AffectedVersionRange,
    IdentifierType,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository
from vuln_ai.sources.osv import OSVSource


@pytest.fixture
def osv_source() -> OSVSource:
    return OSVSource()


class TestOSVComplexRanges:
    """Audit tests for representation of complex OSV affected version ranges."""

    def test_caso_a_introduced_fixed(self, osv_source: OSVSource):
        """Caso A: introduced -> fixed interval."""
        raw = {
            "id": "OSV-CASO-A",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.0.0"}, {"fixed": "2.31.0"}],
                        }
                    ],
                }
            ],
        }
        rec = osv_source.normalize(raw)
        assert len(rec.affected_ranges) == 1
        ar = rec.affected_ranges[0]
        # Structured fields
        assert ar.package_name == "requests"
        assert ar.ecosystem == "pypi"
        assert ar.range_type == "ecosystem"
        assert ar.introduced == "2.0.0"
        assert ar.fixed == "2.31.0"
        assert ar.last_affected is None
        # Audit field
        assert ar.raw_range == ">= 2.0.0, < 2.31.0"

    def test_caso_b_introduced_last_affected(self, osv_source: OSVSource):
        """Caso B: introduced -> last_affected (inclusive upper bound)."""
        raw = {
            "id": "OSV-CASO-B",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "4.0.0"}, {"last_affected": "4.17.20"}],
                        }
                    ],
                }
            ],
        }
        rec = osv_source.normalize(raw)
        assert len(rec.affected_ranges) == 1
        ar = rec.affected_ranges[0]
        # Structured fields
        assert ar.package_name == "lodash"
        assert ar.ecosystem == "npm"
        assert ar.range_type == "semver"
        assert ar.introduced == "4.0.0"
        assert ar.fixed is None
        assert ar.last_affected == "4.17.20"
        # Audit field
        assert ar.raw_range == ">= 4.0.0, <= 4.17.20"

    def test_caso_c_introduced_limit(self, osv_source: OSVSource):
        """Caso C: introduced -> limit (exclusive boundary where analysis ended, NOT a fix)."""
        raw = {
            "id": "OSV-CASO-C",
            "affected": [
                {
                    "package": {"ecosystem": "Go", "name": "golang.org/x/crypto"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0.1.0"}, {"limit": "0.5.0"}],
                        }
                    ],
                }
            ],
        }
        rec = osv_source.normalize(raw)
        assert len(rec.affected_ranges) == 1
        ar = rec.affected_ranges[0]
        # Structured fields must not hallucinate a fix
        assert ar.package_name == "golang.org/x/crypto"
        assert ar.ecosystem == "go"
        assert ar.range_type == "semver"
        assert ar.introduced == "0.1.0"
        assert ar.fixed is None
        assert ar.last_affected is None
        # Audit field preserves the limit expression
        assert ar.raw_range == ">= 0.1.0, < 0.5.0"

    def test_caso_d_multiple_intervals(self, osv_source: OSVSource):
        """Caso D: introduced -> fixed -> introduced -> fixed."""
        raw = {
            "id": "OSV-CASO-D",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "urllib3"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.26.18"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.0.7"},
                            ],
                        }
                    ],
                }
            ],
        }
        rec = osv_source.normalize(raw)
        assert len(rec.affected_ranges) == 2
        r1, r2 = rec.affected_ranges

        # Interval 1
        assert r1.introduced == "0"
        assert r1.fixed == "1.26.18"
        assert r1.last_affected is None
        assert r1.raw_range == "< 1.26.18"

        # Interval 2
        assert r2.introduced == "2.0.0"
        assert r2.fixed == "2.0.7"
        assert r2.last_affected is None
        assert r2.raw_range == ">= 2.0.0, < 2.0.7"

    def test_caso_e_open_ended_introduced(self, osv_source: OSVSource):
        """Caso E: open-ended introduced range (vulnerability has no known fix yet)."""
        raw = {
            "id": "OSV-CASO-E",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "vulnerable-lib"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0.0"}],
                        }
                    ],
                }
            ],
        }
        rec = osv_source.normalize(raw)
        assert len(rec.affected_ranges) == 1
        ar = rec.affected_ranges[0]
        assert ar.introduced == "1.0.0"
        assert ar.fixed is None
        assert ar.last_affected is None
        assert ar.raw_range == ">= 1.0.0"

    def test_caso_f_multiple_packages(self, osv_source: OSVSource):
        """Caso F: single vulnerability affecting multiple packages."""
        raw = {
            "id": "OSV-CASO-F",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pkg-one"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"fixed": "1.2"}],
                        }
                    ],
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "pkg-two"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.0"}, {"fixed": "2.5"}],
                        }
                    ],
                },
            ],
        }
        rec = osv_source.normalize(raw)
        assert len(rec.affected_ranges) == 2
        pkgs = {ar.package_name: ar for ar in rec.affected_ranges}
        assert "pkg-one" in pkgs
        assert "pkg-two" in pkgs
        assert pkgs["pkg-one"].fixed == "1.2"
        assert pkgs["pkg-two"].fixed == "2.5"

    def test_caso_g_multiple_ecosystems(self, osv_source: OSVSource):
        """Caso G: single advisory across different ecosystems."""
        raw = {
            "id": "OSV-CASO-G",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "shared-tool"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}],
                        }
                    ],
                },
                {
                    "package": {"ecosystem": "npm", "name": "shared-tool"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}],
                        }
                    ],
                },
            ],
        }
        rec = osv_source.normalize(raw)
        assert len(rec.affected_ranges) == 2
        ecos = {ar.ecosystem: ar.range_type for ar in rec.affected_ranges}
        assert ecos["pypi"] == "ecosystem"
        assert ecos["npm"] == "semver"


class TestMultiSourceDeduplication:
    """Audit tests for multi-source deduplication, UUID preservation, and canonical_id determinism."""

    @pytest.mark.asyncio
    async def test_scenario_1_osv_first_then_cve(self, db_session: AsyncSession):
        """Escenario 1: First OSV arrives, then CVE arrives from another source.

        Must recognize they are the same vulnerability via aliases, preserve the UUID,
        and attach both sources' evidence.
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        osv_src, _ = await source_repo.get_or_create(name="OSV", source_type="osv")
        kev_src, _ = await source_repo.get_or_create(name="CISA KEV", source_type="kev")

        # 1. OSV record arrives first
        osv_record = VulnerabilityRecord(
            canonical_id="CVE-2024-7777",
            cve_id="CVE-2024-7777",
            source_name="OSV",
            vendor_project="Apache",
            product="httpd",
            short_description="OSV description for Apache flaw",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="OSV-2024-ALPHA",
                    identifier_type=IdentifierType.OSV,
                    source="OSV",
                ),
                VulnerabilityIdentifier(
                    identifier="CVE-2024-7777",
                    identifier_type=IdentifierType.CVE,
                    source="OSV",
                ),
            ],
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="OSV",
                    source_identifier="OSV-2024-ALPHA",
                    has_kev_evidence=False,
                    has_affected_range=True,
                    raw_payload={"osv_raw": True},
                )
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="httpd",
                    range_type="ecosystem",
                    introduced="2.4.0",
                    fixed="2.4.58",
                    source_name="OSV",
                )
            ],
        )

        await vuln_repo.upsert_vulnerabilities(osv_src.id, [osv_record])
        await db_session.commit()

        v1 = await vuln_repo.get_by_canonical_id("CVE-2024-7777")
        assert v1 is not None
        initial_uuid = v1.id

        # 2. CISA KEV arrives later with the same CVE
        kev_record = VulnerabilityRecord(
            canonical_id="CVE-2024-7777",
            cve_id="CVE-2024-7777",
            source_name="CISA KEV",
            vendor_project="Apache",
            product="httpd",
            vulnerability_name="Apache HTTP Server Improper Input Validation",
            required_action="Apply vendor updates",
            known_ransomware_use="Known",
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="CISA KEV",
                    source_identifier="CVE-2024-7777",
                    has_kev_evidence=True,
                    has_affected_range=False,
                    raw_payload={"kev_raw": True},
                )
            ],
        )

        await vuln_repo.upsert_vulnerabilities(kev_src.id, [kev_record])
        await db_session.commit()

        # 3. Verification: Must be the SAME vulnerability UUID
        v2 = await vuln_repo.get_by_canonical_id("CVE-2024-7777")
        assert v2 is not None
        assert v2.id == initial_uuid  # UUID identity preserved!
        assert v2.canonical_id == "CVE-2024-7777"
        assert v2.known_ransomware_use == "Known"  # Enriched from KEV

        # Identifiers: OSV and CVE are preserved
        idents = await vuln_repo.get_identifiers(v2.id)
        ident_set = {i.identifier for i in idents}
        assert "OSV-2024-ALPHA" in ident_set
        assert "CVE-2024-7777" in ident_set

        # Source records: both sources are recorded
        srs = await vuln_repo.get_source_records(v2.id)
        assert len(srs) == 2
        sr_names = {sr.source_name for sr in srs}
        assert "OSV" in sr_names
        assert "CISA KEV" in sr_names

        # Total vulnerabilities in table must remain 1
        all_vulns = await vuln_repo.get_all()
        assert len(all_vulns) == 1

    @pytest.mark.asyncio
    async def test_scenario_2_cve_first_then_ghsa(self, db_session: AsyncSession):
        """Escenario 2: First CVE arrives, then GHSA arrives with an alias link.

        Reuses the existing canonical vulnerability and does NOT downgrade canonical_id to GHSA.
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        kev_src, _ = await source_repo.get_or_create(name="CISA KEV", source_type="kev")
        osv_src, _ = await source_repo.get_or_create(name="OSV", source_type="osv")

        # 1. KEV arrives first with CVE
        kev_record = VulnerabilityRecord(
            canonical_id="CVE-2024-8888",
            cve_id="CVE-2024-8888",
            source_name="CISA KEV",
            vendor_project="Django",
            product="Django",
            short_description="SQL injection in Django",
        )
        await vuln_repo.upsert_vulnerabilities(kev_src.id, [kev_record])
        await db_session.commit()

        v1 = await vuln_repo.get_by_canonical_id("CVE-2024-8888")
        assert v1 is not None
        initial_uuid = v1.id

        # 2. GHSA arrives from OSV with alias to CVE-2024-8888
        ghsa_record = VulnerabilityRecord(
            canonical_id="GHSA-8888-bbbb-cccc",
            cve_id=None,
            source_name="OSV",
            vendor_project="Django",
            product="Django",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="GHSA-8888-bbbb-cccc",
                    identifier_type=IdentifierType.GHSA,
                    source="OSV",
                ),
                VulnerabilityIdentifier(
                    identifier="CVE-2024-8888",
                    identifier_type=IdentifierType.CVE,
                    source="OSV",
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="django",
                    range_type="pep440",
                    introduced="4.2.0",
                    fixed="4.2.8",
                    source_name="OSV",
                )
            ],
        )

        await vuln_repo.upsert_vulnerabilities(osv_src.id, [ghsa_record])
        await db_session.commit()

        # 3. Verification:
        # Reuses exact UUID
        v2 = await vuln_repo.get_by_id(initial_uuid)
        assert v2 is not None
        # Canonical ID remains CVE (CVE priority > GHSA)
        assert v2.canonical_id == "CVE-2024-8888"
        assert v2.cve_id == "CVE-2024-8888"

        # GHSA is added to identifiers
        idents = await vuln_repo.get_identifiers(v2.id)
        assert any(i.identifier == "GHSA-8888-bbbb-cccc" for i in idents)
        assert any(i.identifier == "CVE-2024-8888" for i in idents)

        # Affected ranges from OSV are attached to the canonical vulnerability
        ranges = await vuln_repo.get_affected_ranges(v2.id)
        assert len(ranges) == 1
        assert ranges[0].package_name == "django"
        assert ranges[0].fixed == "4.2.8"

        # Lookup by GHSA identifier returns the same canonical vulnerability
        by_ghsa = await vuln_repo.get_by_identifier("GHSA-8888-bbbb-cccc")
        assert by_ghsa is not None
        assert by_ghsa.id == initial_uuid

    @pytest.mark.asyncio
    async def test_scenario_3_osv_exact_resync_idempotency(
        self,
        db_session: AsyncSession,
        osv_source: OSVSource,
    ):
        """Escenario 3: OSV synchronizes the exact same record multiple times.

        Must not create duplicate vulnerabilities, identifiers, source records, or ranges.
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        osv_src, _ = await source_repo.get_or_create(name="OSV", source_type="osv")

        raw_payload = {
            "id": "GHSA-sync-repeat",
            "aliases": ["CVE-2024-3333"],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "flask"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"fixed": "2.0.1"}],
                        }
                    ],
                }
            ],
        }

        record = osv_source.normalize(raw_payload)

        # Sync 1
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [record])
        await db_session.commit()
        v1 = await vuln_repo.get_by_canonical_id("CVE-2024-3333")
        assert v1 is not None
        uuid_1 = v1.id

        # Sync 2 (identical)
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [record])
        await db_session.commit()

        # Sync 3 (identical)
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [record])
        await db_session.commit()

        # Verify no duplicates anywhere
        all_vulns = await vuln_repo.get_all()
        assert len(all_vulns) == 1
        assert all_vulns[0].id == uuid_1

        idents = await vuln_repo.get_identifiers(uuid_1)
        assert len(idents) == 2  # GHSA + CVE

        srs = await vuln_repo.get_source_records(uuid_1)
        assert len(srs) == 1

        ranges = await vuln_repo.get_affected_ranges(uuid_1)
        assert len(ranges) == 1

    @pytest.mark.asyncio
    async def test_canonical_id_promotion_stability(self, db_session: AsyncSession):
        """Confirm CVE + GHSA + OSV always produces canonical_id = CVE stably."""
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)
        source, _ = await source_repo.get_or_create(name="OSV", source_type="osv")

        # 1. Starts as pure OSV native ID
        rec1 = VulnerabilityRecord(
            canonical_id="PYSEC-2024-001",
            cve_id=None,
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="PYSEC-2024-001",
                    identifier_type=IdentifierType.PYSEC,
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(source.id, [rec1])
        await db_session.commit()
        v = await vuln_repo.get_by_canonical_id("PYSEC-2024-001")
        assert v is not None
        v_uuid = v.id
        assert v.canonical_id == "PYSEC-2024-001"

        # 2. Later update links GHSA
        rec2 = VulnerabilityRecord(
            canonical_id="GHSA-test-1111",
            cve_id=None,
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="PYSEC-2024-001",
                    identifier_type=IdentifierType.PYSEC,
                ),
                VulnerabilityIdentifier(
                    identifier="GHSA-test-1111",
                    identifier_type=IdentifierType.GHSA,
                ),
            ],
        )
        await vuln_repo.upsert_vulnerabilities(source.id, [rec2])
        await db_session.commit()
        v = await vuln_repo.get_by_id(v_uuid)
        assert v is not None
        assert v.canonical_id == "GHSA-test-1111"  # Promoted from PYSEC to GHSA

        # 3. Later update links CVE
        rec3 = VulnerabilityRecord(
            canonical_id="CVE-2024-9999",
            cve_id="CVE-2024-9999",
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="PYSEC-2024-001",
                    identifier_type=IdentifierType.PYSEC,
                ),
                VulnerabilityIdentifier(
                    identifier="GHSA-test-1111",
                    identifier_type=IdentifierType.GHSA,
                ),
                VulnerabilityIdentifier(
                    identifier="CVE-2024-9999",
                    identifier_type=IdentifierType.CVE,
                ),
            ],
        )
        await vuln_repo.upsert_vulnerabilities(source.id, [rec3])
        await db_session.commit()
        v = await vuln_repo.get_by_id(v_uuid)
        assert v is not None
        assert v.canonical_id == "CVE-2024-9999"  # Promoted to top-tier CVE
        assert v.cve_id == "CVE-2024-9999"

        # 4. Subsequent sync mentioning only GHSA does NOT downgrade CVE
        rec4 = VulnerabilityRecord(
            canonical_id="GHSA-test-1111",
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="GHSA-test-1111",
                    identifier_type=IdentifierType.GHSA,
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(source.id, [rec4])
        await db_session.commit()
        v = await vuln_repo.get_by_id(v_uuid)
        assert v is not None
        assert v.canonical_id == "CVE-2024-9999"  # Stably remains CVE!
