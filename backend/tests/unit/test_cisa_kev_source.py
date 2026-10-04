"""Unit tests for the CISA KEV source adapter, normalization, and multi-source deduplication."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.exceptions import SourceParseError, SourceSyncError
from vuln_ai.core.models import (
    AffectedVersionRange,
    IdentifierType,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
)
from vuln_ai.db.models import (
    VulnerabilityDB,
    VulnerabilityIdentifierDB,
    VulnerabilitySourceRecordDB,
)
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository
from vuln_ai.sources.cisa_kev import CISAKEVSource

# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------


@pytest.fixture
def kev_source() -> CISAKEVSource:
    return CISAKEVSource()


@pytest.fixture
def sample_kev_entry_basic() -> dict[str, Any]:
    return {
        "cveID": "CVE-2024-1000",
        "vendorProject": "Django",
        "product": "Django",
        "vulnerabilityName": "Django SQL Injection Vulnerability",
        "dateAdded": "2024-01-15",
        "shortDescription": "Django contains a SQL injection vulnerability in the admin interface.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-02-15",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.djangoproject.com/security/",
        "cwes": ["CWE-89"],
    }


# ---------------------------------------------------------------------------
# 1. NORMALIZATION TESTS
# ---------------------------------------------------------------------------


class TestCISAKEVNormalization:
    """Tests for CISA KEV entry parsing and normalization into canonical domain models."""

    def test_normalize_valid_payload(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        """Standard valid KEV payload normalizes all fields accurately."""
        record = kev_source.normalize(sample_kev_entry_basic)

        assert record.canonical_id == "CVE-2024-1000"
        assert record.cve_id == "CVE-2024-1000"
        assert record.source_name == "CISA KEV"
        assert record.vendor_project == "Django"
        assert record.product == "Django"
        assert record.vulnerability_name == "Django SQL Injection Vulnerability"
        assert "SQL injection" in record.short_description
        assert "Apply updates" in record.required_action
        assert record.date_added == datetime(2024, 1, 15, tzinfo=UTC)
        assert record.due_date == datetime(2024, 2, 15, tzinfo=UTC)
        assert record.known_ransomware_use == "Known"
        assert record.notes == "https://www.djangoproject.com/security/"
        assert record.cwes == ["CWE-89"]

    def test_normalize_identifiers_structure(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        """Ensure canonical_id and identifiers are properly structured without synthetic IDs."""
        record = kev_source.normalize(sample_kev_entry_basic)

        assert len(record.identifiers) == 1
        ident = record.identifiers[0]
        assert ident.identifier == "CVE-2024-1000"
        assert ident.identifier_type == IdentifierType.CVE
        assert ident.source == "CISA KEV"

        # Explicitly verify NO artificial IDs like CISA-1234 or KEV-1234
        for i in record.identifiers:
            assert not i.identifier.startswith("CISA-")
            assert not i.identifier.startswith("KEV-")

    def test_normalize_source_records_evidence(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        """Ensure source record has KEV exploitation evidence and preserves raw payload."""
        record = kev_source.normalize(sample_kev_entry_basic)

        assert len(record.source_records) == 1
        sr = record.source_records[0]
        assert sr.source_name == "CISA KEV"
        assert sr.source_identifier == "CVE-2024-1000"
        assert sr.has_kev_evidence is True
        assert sr.has_affected_range is False
        assert sr.raw_payload == sample_kev_entry_basic
        assert sr.synced_at is not None

    def test_normalize_no_synthetic_affected_ranges(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        """CRITICAL: CISA KEV does NOT provide package ranges; never invent them."""
        record = kev_source.normalize(sample_kev_entry_basic)
        assert record.affected_ranges == []

    def test_normalize_optional_and_empty_fields(self, kev_source: CISAKEVSource) -> None:
        """Optional fields like notes, description, action handle empty values safely."""
        minimal = {
            "cveID": "CVE-2024-3333",
            "vendorProject": "Apache",
            "product": "HTTP Server",
        }
        record = kev_source.normalize(minimal)
        assert record.canonical_id == "CVE-2024-3333"
        assert record.vulnerability_name == ""
        assert record.short_description == ""
        assert record.required_action == ""
        assert record.notes == ""
        assert record.date_added is None
        assert record.due_date is None
        assert record.cwes == []
        assert record.known_ransomware_use == "Unknown"

    def test_normalize_ransomware_variations(self, kev_source: CISAKEVSource) -> None:
        """knownRansomwareCampaignUse handles strings, booleans, and casing properly."""
        # Boolean True -> "Known"
        r1 = kev_source.normalize(
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "V",
                "product": "P",
                "knownRansomwareCampaignUse": True,
            }
        )
        assert r1.known_ransomware_use == "Known"

        # Boolean False -> "Unknown"
        r2 = kev_source.normalize(
            {
                "cveID": "CVE-2024-0002",
                "vendorProject": "V",
                "product": "P",
                "knownRansomwareCampaignUse": False,
            }
        )
        assert r2.known_ransomware_use == "Unknown"

        # String "known" / "yes"
        r3 = kev_source.normalize(
            {
                "cveID": "CVE-2024-0003",
                "vendorProject": "V",
                "product": "P",
                "knownRansomwareCampaignUse": "yes",
            }
        )
        assert r3.known_ransomware_use == "Known"

        # String "no" / "unknown"
        r4 = kev_source.normalize(
            {
                "cveID": "CVE-2024-0004",
                "vendorProject": "V",
                "product": "P",
                "knownRansomwareCampaignUse": "no",
            }
        )
        assert r4.known_ransomware_use == "Unknown"

        # Custom campaign name preserved
        r5 = kev_source.normalize(
            {
                "cveID": "CVE-2024-0005",
                "vendorProject": "V",
                "product": "P",
                "knownRansomwareCampaignUse": "LockBit 3.0",
            }
        )
        assert r5.known_ransomware_use == "LockBit 3.0"

    def test_normalize_date_formats(self, kev_source: CISAKEVSource) -> None:
        """Date parsing handles ISO-8601 timestamps and YYYY-MM-DD formats."""
        entry = {
            "cveID": "CVE-2024-0010",
            "vendorProject": "V",
            "product": "P",
            "dateAdded": "2024-05-20T14:30:00Z",
            "dueDate": "2024-06-10",
        }
        record = kev_source.normalize(entry)
        assert record.date_added == datetime(2024, 5, 20, 14, 30, tzinfo=UTC)
        assert record.due_date == datetime(2024, 6, 10, tzinfo=UTC)

    def test_normalize_cwes_variations(self, kev_source: CISAKEVSource) -> None:
        """CWE parsing handles lists, comma-delimited strings, and whitespace."""
        # Comma delimited string
        r1 = kev_source.normalize(
            {
                "cveID": "CVE-2024-0020",
                "vendorProject": "V",
                "product": "P",
                "cwes": "CWE-79, CWE-89 ",
            }
        )
        assert r1.cwes == ["CWE-79", "CWE-89"]

        # List with whitespace
        r2 = kev_source.normalize(
            {
                "cveID": "CVE-2024-0021",
                "vendorProject": "V",
                "product": "P",
                "cwes": [" CWE-22 ", "CWE-352"],
            }
        )
        assert r2.cwes == ["CWE-22", "CWE-352"]


# ---------------------------------------------------------------------------
# 2. ERROR HANDLING TESTS
# ---------------------------------------------------------------------------


class TestCISAKEVErrorHandling:
    """Tests for malformed inputs, network errors, timeouts, and HTTP errors."""

    def test_normalize_non_dict_error(self, kev_source: CISAKEVSource) -> None:
        with pytest.raises(SourceParseError, match="must be a dictionary"):
            kev_source.normalize("not a dict")  # type: ignore

    def test_normalize_missing_cve_error(self, kev_source: CISAKEVSource) -> None:
        with pytest.raises(SourceParseError, match="Missing cveID"):
            kev_source.normalize({"vendorProject": "V", "product": "P"})

    def test_normalize_invalid_cve_format_error(self, kev_source: CISAKEVSource) -> None:
        with pytest.raises(SourceParseError, match="Invalid cveID"):
            kev_source.normalize({"cveID": "GHSA-xxxx-yyyy", "vendorProject": "V", "product": "P"})

    def test_normalize_missing_vendor_product_error(self, kev_source: CISAKEVSource) -> None:
        with pytest.raises(SourceParseError, match="Missing vendorProject or product"):
            kev_source.normalize({"cveID": "CVE-2024-1234", "vendorProject": ""})

    @pytest.mark.asyncio
    async def test_download_http_4xx(self, kev_source: CISAKEVSource) -> None:
        request = httpx.Request("GET", "https://example.com/kev.json")
        response = httpx.Response(404, request=request)
        with (
            patch(
                "httpx.AsyncClient.get",
                side_effect=httpx.HTTPStatusError("Not Found", request=request, response=response),
            ),
            pytest.raises(SourceSyncError, match="HTTP 404"),
        ):
            await kev_source._download("https://example.com/kev.json")

    @pytest.mark.asyncio
    async def test_download_http_5xx(self, kev_source: CISAKEVSource) -> None:
        request = httpx.Request("GET", "https://example.com/kev.json")
        response = httpx.Response(503, request=request)
        with (
            patch(
                "httpx.AsyncClient.get",
                side_effect=httpx.HTTPStatusError(
                    "Service Unavailable", request=request, response=response
                ),
            ),
            pytest.raises(SourceSyncError, match="HTTP 503"),
        ):
            await kev_source._download("https://example.com/kev.json")

    @pytest.mark.asyncio
    async def test_download_timeout(self, kev_source: CISAKEVSource) -> None:
        with (
            patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timeout")),
            pytest.raises(SourceSyncError, match="Timeout downloading"),
        ):
            await kev_source._download("https://example.com/kev.json")

    @pytest.mark.asyncio
    async def test_download_invalid_json(self, kev_source: CISAKEVSource) -> None:
        request = httpx.Request("GET", "https://example.com/kev.json")
        response = httpx.Response(200, request=request, text="<html>Invalid JSON</html>")
        with (
            patch("httpx.AsyncClient.get", return_value=response),
            pytest.raises(SourceParseError, match="Invalid JSON"),
        ):
            await kev_source._download("https://example.com/kev.json")

    def test_parse_missing_vulnerabilities_key(self, kev_source: CISAKEVSource) -> None:
        with pytest.raises(SourceParseError, match="missing 'vulnerabilities' key"):
            kev_source._parse({"catalogVersion": "1.0"})

    def test_parse_vulnerabilities_not_a_list(self, kev_source: CISAKEVSource) -> None:
        with pytest.raises(SourceParseError, match="is not an array"):
            kev_source._parse({"vulnerabilities": "not a list"})


# ---------------------------------------------------------------------------
# 3. SYNC, SEARCH, AND RETRIEVAL TESTS
# ---------------------------------------------------------------------------


class TestCISAKEVSyncAndSearch:
    """Tests for sync workflow, mirror fallback, and in-memory search."""

    @pytest.mark.asyncio
    async def test_sync_success_primary(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        feed_data = {"vulnerabilities": [sample_kev_entry_basic]}
        with patch.object(kev_source, "_download", new_callable=AsyncMock) as mock_dl:
            mock_dl.return_value = feed_data
            result = await kev_source.sync()

            assert result.success is True
            assert result.records_synced == 1
            assert len(kev_source.records) == 1
            assert kev_source.records[0].canonical_id == "CVE-2024-1000"

    @pytest.mark.asyncio
    async def test_sync_fallback_to_mirror(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        feed_data = {"vulnerabilities": [sample_kev_entry_basic]}
        with patch.object(kev_source, "_download", new_callable=AsyncMock) as mock_dl:
            # Primary fails, mirror succeeds
            mock_dl.side_effect = [
                SourceSyncError("Primary down"),
                feed_data,
            ]
            result = await kev_source.sync()

            assert result.success is True
            assert result.records_synced == 1
            assert mock_dl.call_count == 2

    @pytest.mark.asyncio
    async def test_sync_all_exhausted(self, kev_source: CISAKEVSource) -> None:
        with patch.object(kev_source, "_download", new_callable=AsyncMock) as mock_dl:
            mock_dl.side_effect = [
                SourceSyncError("Primary 503"),
                SourceSyncError("Mirror 404"),
            ]
            result = await kev_source.sync()

            assert result.success is False
            assert "Mirror 404" in result.error
            assert result.records_synced == 0

    def test_get_cve_lookup(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        rec = kev_source.normalize(sample_kev_entry_basic)
        kev_source._records = [rec]

        found = kev_source.get_cve("cve-2024-1000")
        assert found is not None
        assert found.canonical_id == "CVE-2024-1000"

        missing = kev_source.get_cve("CVE-2099-0000")
        assert missing is None

    @pytest.mark.asyncio
    async def test_search_by_component(
        self, kev_source: CISAKEVSource, sample_kev_entry_basic: dict[str, Any]
    ) -> None:
        rec = kev_source.normalize(sample_kev_entry_basic)
        kev_source._records = [rec]

        matches = await kev_source.search("django")
        assert len(matches) == 1
        assert matches[0].canonical_id == "CVE-2024-1000"

        no_matches = await kev_source.search("flask")
        assert len(no_matches) == 0


# ---------------------------------------------------------------------------
# 4. PERSISTENCE, IDEMPOTENCE, AND MULTI-SOURCE DEDUPLICATION TESTS
# ---------------------------------------------------------------------------


class TestCISAKEVMultiSourceDeduplication:
    """Database-backed tests verifying CISA KEV deduplication with OSV and NVD."""

    @pytest.mark.asyncio
    async def test_cisa_first_time_persistence(
        self,
        db_session: AsyncSession,
        kev_source: CISAKEVSource,
        sample_kev_entry_basic: dict[str, Any],
    ) -> None:
        """Case: CISA KEV persists into empty database."""
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        cisa_src, _ = await source_repo.get_or_create(
            name=kev_source.name,
            source_type=kev_source.source_type,
            url=kev_source.url,
        )

        record = kev_source.normalize(sample_kev_entry_basic)
        count = await vuln_repo.upsert_vulnerabilities(cisa_src.id, [record])
        await db_session.commit()

        assert count == 1
        db_vuln = await vuln_repo.get_by_canonical_id("CVE-2024-1000")
        assert db_vuln is not None
        assert db_vuln.canonical_id == "CVE-2024-1000"
        assert db_vuln.cve_id == "CVE-2024-1000"
        assert db_vuln.required_action == "Apply updates per vendor instructions."

        # Identifiers
        idents = await vuln_repo.get_identifiers(db_vuln.id)
        assert len(idents) == 1
        assert idents[0].identifier == "CVE-2024-1000"
        assert idents[0].identifier_type == "cve"

        # Source Records
        srs = await vuln_repo.get_source_records(db_vuln.id)
        assert len(srs) == 1
        assert srs[0].source_name == "CISA KEV"
        assert srs[0].has_kev_evidence is True
        assert srs[0].has_affected_range is False

        # Affected ranges must be empty
        ranges = await vuln_repo.get_affected_ranges(db_vuln.id)
        assert len(ranges) == 0

    @pytest.mark.asyncio
    async def test_cisa_idempotency_repeated_sync(
        self,
        db_session: AsyncSession,
        kev_source: CISAKEVSource,
        sample_kev_entry_basic: dict[str, Any],
    ) -> None:
        """Case A: CISA syncs the same CVE multiple times without duplicates."""
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        cisa_src, _ = await source_repo.get_or_create(
            name=kev_source.name,
            source_type=kev_source.source_type,
            url=kev_source.url,
        )

        record = kev_source.normalize(sample_kev_entry_basic)

        # Sync 1
        await vuln_repo.upsert_vulnerabilities(cisa_src.id, [record])
        await db_session.commit()
        v1 = await vuln_repo.get_by_canonical_id("CVE-2024-1000")
        assert v1 is not None
        uuid_1 = v1.id

        # Sync 2
        await vuln_repo.upsert_vulnerabilities(cisa_src.id, [record])
        await db_session.commit()

        # Sync 3
        await vuln_repo.upsert_vulnerabilities(cisa_src.id, [record])
        await db_session.commit()

        # Exactly 1 vulnerability with identical UUID
        all_vulns = (await db_session.execute(select(VulnerabilityDB))).scalars().all()
        assert len(all_vulns) == 1
        assert all_vulns[0].id == uuid_1

        # Exactly 1 identifier
        all_idents = (await db_session.execute(select(VulnerabilityIdentifierDB))).scalars().all()
        assert len(all_idents) == 1

        # Exactly 1 source record
        all_srs = (await db_session.execute(select(VulnerabilitySourceRecordDB))).scalars().all()
        assert len(all_srs) == 1

    @pytest.mark.asyncio
    async def test_deduplication_nvd_then_cisa(
        self,
        db_session: AsyncSession,
        kev_source: CISAKEVSource,
        sample_kev_entry_basic: dict[str, Any],
    ) -> None:
        """Case B: NVD arrives first, then CISA arrives for same CVE.

        Result:
        - 1 shared vulnerability UUID
        - NVD CVSS & CWE are preserved
        - CISA KEV evidence is added to source records
        - CISA requiredAction, dueDate, ransomware info enriches record
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        nvd_src, _ = await source_repo.get_or_create("NVD", "nvd", "https://nvd.example.com")
        cisa_src, _ = await source_repo.get_or_create(
            kev_source.name, kev_source.source_type, kev_source.url
        )

        # 1. NVD arrives first
        nvd_rec = VulnerabilityRecord(
            canonical_id="CVE-2024-1000",
            cve_id="CVE-2024-1000",
            source_name="NVD",
            short_description="NVD flaw description.",
            severity="HIGH",
            cvss_score=8.8,
            cwes=["CWE-89"],
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2024-1000",
                    identifier_type=IdentifierType.CVE,
                    source="NVD",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(nvd_src.id, [nvd_rec])
        await db_session.commit()

        v1 = await vuln_repo.get_by_canonical_id("CVE-2024-1000")
        assert v1 is not None
        shared_uuid = v1.id
        assert v1.cvss_score == 8.8

        # 2. CISA arrives second
        cisa_rec = kev_source.normalize(sample_kev_entry_basic)
        await vuln_repo.upsert_vulnerabilities(cisa_src.id, [cisa_rec])
        await db_session.commit()

        # Check identical UUID
        v2 = await vuln_repo.get_by_id(shared_uuid)
        assert v2 is not None
        assert v2.id == shared_uuid
        assert v2.canonical_id == "CVE-2024-1000"

        # Check NVD evidence preserved
        assert v2.cvss_score == 8.8
        assert v2.severity == "HIGH"

        # Check CISA evidence enriched
        assert v2.required_action == "Apply updates per vendor instructions."
        assert v2.due_date is not None
        assert v2.known_ransomware_use == "Known"

        # Check source records (NVD and CISA KEV)
        srs = await vuln_repo.get_source_records(shared_uuid)
        assert len(srs) == 2
        sr_sources = {sr.source_name: sr for sr in srs}
        assert "NVD" in sr_sources
        assert "CISA KEV" in sr_sources
        assert sr_sources["CISA KEV"].has_kev_evidence is True

    @pytest.mark.asyncio
    async def test_deduplication_osv_then_cisa(
        self,
        db_session: AsyncSession,
        kev_source: CISAKEVSource,
        sample_kev_entry_basic: dict[str, Any],
    ) -> None:
        """Case: OSV arrives first with affected ranges, then CISA arrives.

        Result:
        - Reuses same UUID
        - Identifiers contain CVE and GHSA
        - Source records contain OSV and CISA KEV
        - OSV affected version ranges remain completely intact
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        osv_src, _ = await source_repo.get_or_create("OSV", "osv", "https://osv.example.com")
        cisa_src, _ = await source_repo.get_or_create(
            kev_source.name, kev_source.source_type, kev_source.url
        )

        # 1. OSV arrives first
        osv_rec = VulnerabilityRecord(
            canonical_id="CVE-2024-1000",
            cve_id="CVE-2024-1000",
            source_name="OSV",
            short_description="OSV advisory description.",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2024-1000",
                    identifier_type=IdentifierType.CVE,
                    source="OSV",
                ),
                VulnerabilityIdentifier(
                    identifier="GHSA-django-sql-inj",
                    identifier_type=IdentifierType.GHSA,
                    source="OSV",
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="django",
                    range_type="ecosystem",
                    introduced="4.2.0",
                    fixed="4.2.11",
                    source_name="OSV",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [osv_rec])
        await db_session.commit()

        v1 = await vuln_repo.get_by_canonical_id("CVE-2024-1000")
        assert v1 is not None
        shared_uuid = v1.id

        # 2. CISA arrives second
        cisa_rec = kev_source.normalize(sample_kev_entry_basic)
        await vuln_repo.upsert_vulnerabilities(cisa_src.id, [cisa_rec])
        await db_session.commit()

        # Verify same UUID
        v2 = await vuln_repo.get_by_id(shared_uuid)
        assert v2 is not None
        assert v2.id == shared_uuid

        # Verify identifiers (both CVE and GHSA)
        idents = await vuln_repo.get_identifiers(shared_uuid)
        ident_set = {i.identifier for i in idents}
        assert "CVE-2024-1000" in ident_set
        assert "GHSA-django-sql-inj" in ident_set

        # Verify OSV affected ranges remain intact
        ranges = await vuln_repo.get_affected_ranges(shared_uuid)
        assert len(ranges) == 1
        assert ranges[0].package_name == "django"
        assert ranges[0].introduced == "4.2.0"
        assert ranges[0].fixed == "4.2.11"
        assert ranges[0].source_name == "OSV"

        # Verify source records
        srs = await vuln_repo.get_source_records(shared_uuid)
        assert len(srs) == 2
        sr_map = {sr.source_name: sr for sr in srs}
        assert sr_map["CISA KEV"].has_kev_evidence is True
        assert sr_map["OSV"].has_affected_range is True

    @pytest.mark.asyncio
    async def test_deduplication_cisa_then_nvd_then_osv(
        self,
        db_session: AsyncSession,
        kev_source: CISAKEVSource,
        sample_kev_entry_basic: dict[str, Any],
    ) -> None:
        """Case: CISA arrives first, followed by NVD and OSV.

        Result:
        - 1 single UUID across all 3 source syncs
        - All identifiers unified
        - All 3 source records present
        - CVSS from NVD, affected ranges from OSV, KEV evidence from CISA
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        cisa_src, _ = await source_repo.get_or_create(
            kev_source.name, kev_source.source_type, kev_source.url
        )
        nvd_src, _ = await source_repo.get_or_create("NVD", "nvd", "https://nvd.example.com")
        osv_src, _ = await source_repo.get_or_create("OSV", "osv", "https://osv.example.com")

        # 1. CISA arrives first
        cisa_rec = kev_source.normalize(sample_kev_entry_basic)
        await vuln_repo.upsert_vulnerabilities(cisa_src.id, [cisa_rec])
        await db_session.commit()
        v_cisa = await vuln_repo.get_by_canonical_id("CVE-2024-1000")
        assert v_cisa is not None
        shared_uuid = v_cisa.id

        # 2. NVD arrives second
        nvd_rec = VulnerabilityRecord(
            canonical_id="CVE-2024-1000",
            cve_id="CVE-2024-1000",
            source_name="NVD",
            severity="CRITICAL",
            cvss_score=9.8,
            cwes=["CWE-89"],
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2024-1000",
                    identifier_type=IdentifierType.CVE,
                    source="NVD",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(nvd_src.id, [nvd_rec])
        await db_session.commit()

        # 3. OSV arrives third
        osv_rec = VulnerabilityRecord(
            canonical_id="CVE-2024-1000",
            cve_id="CVE-2024-1000",
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2024-1000",
                    identifier_type=IdentifierType.CVE,
                    source="OSV",
                ),
                VulnerabilityIdentifier(
                    identifier="GHSA-9999-xxxx",
                    identifier_type=IdentifierType.GHSA,
                    source="OSV",
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="django",
                    range_type="ecosystem",
                    introduced="4.2.0",
                    fixed="4.2.11",
                    source_name="OSV",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [osv_rec])
        await db_session.commit()

        # Single canonical vulnerability UUID retained
        v_final = await vuln_repo.get_by_id(shared_uuid)
        assert v_final is not None
        assert v_final.canonical_id == "CVE-2024-1000"

        # Evidence preservation:
        # - CVSS from NVD
        assert v_final.cvss_score == 9.8
        assert v_final.severity == "CRITICAL"
        # - KEV action from CISA
        assert v_final.required_action == "Apply updates per vendor instructions."
        assert v_final.known_ransomware_use == "Known"

        # Identifiers contain CVE and GHSA
        idents = await vuln_repo.get_identifiers(shared_uuid)
        ident_vals = {i.identifier for i in idents}
        assert "CVE-2024-1000" in ident_vals
        assert "GHSA-9999-xxxx" in ident_vals

        # Source records contain all 3 sources
        srs = await vuln_repo.get_source_records(shared_uuid)
        assert len(srs) == 3
        sr_map = {sr.source_name: sr for sr in srs}
        assert "CISA KEV" in sr_map
        assert "NVD" in sr_map
        assert "OSV" in sr_map
        assert sr_map["CISA KEV"].has_kev_evidence is True

        # Affected ranges from OSV intact
        ranges = await vuln_repo.get_affected_ranges(shared_uuid)
        assert len(ranges) == 1
        assert ranges[0].package_name == "django"
        assert ranges[0].fixed == "4.2.11"

    @pytest.mark.asyncio
    async def test_deduplication_osv_then_nvd_then_cisa(
        self,
        db_session: AsyncSession,
        kev_source: CISAKEVSource,
        sample_kev_entry_basic: dict[str, Any],
    ) -> None:
        """Case C: OSV -> NVD -> CISA standard sequence.

        Verifies 1 canonical vulnerability UUID, full multi-source correlation,
        and zero loss of evidence across the 3 intelligence sources.
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        osv_src, _ = await source_repo.get_or_create("OSV", "osv", "https://osv.example.com")
        nvd_src, _ = await source_repo.get_or_create("NVD", "nvd", "https://nvd.example.com")
        cisa_src, _ = await source_repo.get_or_create(
            kev_source.name, kev_source.source_type, kev_source.url
        )

        # 1. OSV
        osv_rec = VulnerabilityRecord(
            canonical_id="CVE-2024-1000",
            cve_id="CVE-2024-1000",
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2024-1000",
                    identifier_type=IdentifierType.CVE,
                    source="OSV",
                ),
                VulnerabilityIdentifier(
                    identifier="GHSA-osv-first",
                    identifier_type=IdentifierType.GHSA,
                    source="OSV",
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="django",
                    range_type="ecosystem",
                    introduced="4.2.0",
                    fixed="4.2.11",
                    source_name="OSV",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [osv_rec])
        await db_session.commit()
        v_initial = await vuln_repo.get_by_canonical_id("CVE-2024-1000")
        assert v_initial is not None
        target_uuid = v_initial.id

        # 2. NVD
        nvd_rec = VulnerabilityRecord(
            canonical_id="CVE-2024-1000",
            cve_id="CVE-2024-1000",
            source_name="NVD",
            severity="HIGH",
            cvss_score=8.5,
            cwes=["CWE-89"],
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2024-1000",
                    identifier_type=IdentifierType.CVE,
                    source="NVD",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(nvd_src.id, [nvd_rec])
        await db_session.commit()

        # 3. CISA KEV
        cisa_rec = kev_source.normalize(sample_kev_entry_basic)
        await vuln_repo.upsert_vulnerabilities(cisa_src.id, [cisa_rec])
        await db_session.commit()

        # Validation
        v_final = await vuln_repo.get_by_id(target_uuid)
        assert v_final is not None
        assert v_final.id == target_uuid
        assert v_final.canonical_id == "CVE-2024-1000"
        assert v_final.cvss_score == 8.5
        assert v_final.severity == "HIGH"
        assert v_final.required_action == "Apply updates per vendor instructions."

        # Identifiers
        idents = await vuln_repo.get_identifiers(target_uuid)
        ident_set = {i.identifier for i in idents}
        assert "CVE-2024-1000" in ident_set
        assert "GHSA-osv-first" in ident_set

        # Source Records
        srs = await vuln_repo.get_source_records(target_uuid)
        assert len(srs) == 3
        sr_names = {sr.source_name for sr in srs}
        assert sr_names == {"OSV", "NVD", "CISA KEV"}

        # Affected Ranges
        ranges = await vuln_repo.get_affected_ranges(target_uuid)
        assert len(ranges) == 1
        assert ranges[0].package_name == "django"
        assert ranges[0].fixed == "4.2.11"


# ---------------------------------------------------------------------------
# 5. EDGE CASES AND PARSE LIMITS
# ---------------------------------------------------------------------------


class TestCISAKEVEdgeCoverage:
    """Additional edge cases to guarantee complete branch coverage."""

    @pytest.mark.asyncio
    async def test_custom_http_client(self) -> None:
        async with httpx.AsyncClient() as custom_client:
            source = CISAKEVSource(http_client=custom_client)
            client, should_close = await source._get_client()
            assert client is custom_client
            assert should_close is False

    @pytest.mark.asyncio
    async def test_download_json_not_a_dict(self, kev_source: CISAKEVSource) -> None:
        request = httpx.Request("GET", "https://example.com/kev.json")
        response = httpx.Response(200, request=request, json=["not", "a", "dict"])
        with (
            patch("httpx.AsyncClient.get", return_value=response),
            pytest.raises(SourceParseError, match="is not a JSON object"),
        ):
            await kev_source._download("https://example.com/kev.json")

    def test_parse_too_many_errors_aborts(self, kev_source: CISAKEVSource) -> None:
        bad_entries = [{"cveID": ""} for _ in range(105)]
        with pytest.raises(SourceParseError, match="Too many parse errors"):
            kev_source._parse({"vulnerabilities": bad_entries})

    def test_parse_no_valid_records_from_nonempty_vulnerabilities(
        self, kev_source: CISAKEVSource
    ) -> None:
        bad_entries = [{"cveID": "INVALID-1"}, {"cveID": "INVALID-2"}]
        with pytest.raises(SourceParseError, match="No records parsed"):
            kev_source._parse({"vulnerabilities": bad_entries})

    def test_parse_date_edge_cases(self, kev_source: CISAKEVSource) -> None:
        # Empty string
        assert kev_source._parse_date("") is None
        assert kev_source._parse_date("   ") is None
        # Non-string non-datetime
        assert kev_source._parse_date(12345) is None
        # Existing datetime with and without tzinfo
        dt_naive = datetime(2024, 3, 1, 10, 0)
        parsed = kev_source._parse_date(dt_naive)
        assert parsed is not None and parsed.tzinfo == UTC
        dt_aware = datetime(2024, 3, 1, 10, 0, tzinfo=UTC)
        assert kev_source._parse_date(dt_aware) == dt_aware
        # Malformed date strings
        assert kev_source._parse_date("not-a-date") is None
        assert kev_source._parse_date("2024-invalid") is None

    @pytest.mark.asyncio
    async def test_search_vendor_matching(self, kev_source: CISAKEVSource) -> None:
        entry = {
            "cveID": "CVE-2024-9999",
            "vendorProject": "Fortinet",
            "product": "FortiMail",
        }
        rec = kev_source.normalize(entry)
        kev_source._records = [rec]

        # Match by vendor
        matches = await kev_source.search("fortinet")
        assert len(matches) == 1
        assert matches[0].canonical_id == "CVE-2024-9999"

        # Explicit vendor filter mismatch
        matches_filtered = await kev_source.search("fortinet", vendor="Different Vendor")
        assert len(matches_filtered) == 0

        # Explicit product filter mismatch
        matches_prod_filtered = await kev_source.search("fortinet", product="Different Product")
        assert len(matches_prod_filtered) == 0
