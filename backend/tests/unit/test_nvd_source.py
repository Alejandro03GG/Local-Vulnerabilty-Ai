"""Unit tests for the NVD source adapter, CPE parsing, and multi-source deduplication."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.config import NVDSourceSettings
from vuln_ai.core.exceptions import SourceParseError, SourceSyncError
from vuln_ai.core.models import (
    AffectedVersionRange,
    IdentifierType,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
)
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository
from vuln_ai.sources.nvd import (
    NVDSource,
    map_cpe_to_package_ecosystem,
    parse_cpe_23,
)

# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------


@pytest.fixture
def nvd_source() -> NVDSource:
    return NVDSource()


@pytest.fixture
def sample_nvd_cve_basic() -> dict:
    return {
        "cve": {
            "id": "CVE-2024-1001",
            "sourceIdentifier": "security@nist.gov",
            "published": "2024-02-01T10:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "Basic vulnerability flaw description."}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                    }
                ]
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-89"}],
                }
            ],
        }
    }


@pytest.fixture
def sample_nvd_with_aliases() -> dict:
    return {
        "cve": {
            "id": "CVE-2024-2002",
            "aliases": ["GHSA-xxxx-1111-2222", "OSV-2024-99"],
            "descriptions": [{"lang": "en", "value": "CVE with aliases."}],
        }
    }


@pytest.fixture
def sample_nvd_cvss_v4() -> dict:
    return {
        "cve": {
            "id": "CVE-2024-4004",
            "descriptions": [{"lang": "en", "value": "CVSS v4 test."}],
            "metrics": {
                "cvssMetricV40": [
                    {
                        "source": "cve@mitre.org",
                        "cvssData": {
                            "version": "4.0",
                            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                            "baseScore": 9.3,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            },
        }
    }


@pytest.fixture
def sample_nvd_multi_cwe() -> dict:
    return {
        "cve": {
            "id": "CVE-2024-5005",
            "descriptions": [{"lang": "en", "value": "Multiple CWE vulnerability."}],
            "weaknesses": [
                {"description": [{"value": "CWE-79"}]},
                {"description": [{"value": "CWE-20"}]},
                {"description": [{"value": "NVD-CWE-noinfo"}]},  # Should be filtered out
            ],
        }
    }


@pytest.fixture
def sample_nvd_generic_app_cpe() -> dict:
    """A generic application CPE (e.g. Apache HTTP Server) that must NOT be converted to a package."""
    return {
        "cve": {
            "id": "CVE-2024-6006",
            "descriptions": [{"lang": "en", "value": "Apache HTTP Server buffer overflow."}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "abc-123",
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    }


@pytest.fixture
def sample_nvd_safe_package_cpe() -> dict:
    """A CPE explicitly mapped to a package ecosystem via target_sw."""
    return {
        "cve": {
            "id": "CVE-2024-7007",
            "descriptions": [{"lang": "en", "value": "Flaw in Python package requests."}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:psf:requests:*:*:*:*:*:python:*:*",
                                    "versionStartIncluding": "2.0.0",
                                    "versionEndExcluding": "2.31.0",
                                    "matchCriteriaId": "req-123",
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    }


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------


class TestNVDAdapterNormalization:
    """Unit tests for NVD parsing, CVSS, CWE, and CPE configuration handling."""

    def test_01_basic_cve(self, nvd_source: NVDSource, sample_nvd_cve_basic: dict):
        """Test 1: Basic NVD CVE normalization."""
        record = nvd_source.normalize(sample_nvd_cve_basic)

        assert record.canonical_id == "CVE-2024-1001"
        assert record.cve_id == "CVE-2024-1001"
        assert record.source_name == "NVD"
        assert record.short_description == "Basic vulnerability flaw description."
        assert record.severity == "HIGH"
        assert record.cvss_score == 7.5
        assert record.cwes == ["CWE-89"]

        # Identifiers
        assert len(record.identifiers) == 1
        assert record.identifiers[0].identifier == "CVE-2024-1001"
        assert record.identifiers[0].identifier_type == IdentifierType.CVE

        # Source record
        assert len(record.source_records) == 1
        sr = record.source_records[0]
        assert sr.source_name == "NVD"
        assert sr.source_identifier == "CVE-2024-1001"
        assert sr.has_kev_evidence is False
        assert sr.raw_payload == sample_nvd_cve_basic

    def test_02_cve_with_multiple_aliases(
        self, nvd_source: NVDSource, sample_nvd_with_aliases: dict
    ):
        """Test 2: CVE with multiple aliases."""
        record = nvd_source.normalize(sample_nvd_with_aliases)

        assert record.canonical_id == "CVE-2024-2002"
        ident_map = {i.identifier: i.identifier_type for i in record.identifiers}
        assert ident_map["CVE-2024-2002"] == IdentifierType.CVE
        assert ident_map["GHSA-xxxx-1111-2222"] == IdentifierType.GHSA
        assert ident_map["OSV-2024-99"] == IdentifierType.OSV

    def test_03_cvss_v3(self, nvd_source: NVDSource, sample_nvd_cve_basic: dict):
        """Test 3: CVSS v3.x extraction."""
        record = nvd_source.normalize(sample_nvd_cve_basic)
        assert record.cvss_score == 7.5
        assert record.severity == "HIGH"

    def test_04_cvss_v4(self, nvd_source: NVDSource, sample_nvd_cvss_v4: dict):
        """Test 4: CVSS v4.0 extraction."""
        record = nvd_source.normalize(sample_nvd_cvss_v4)
        assert record.cvss_score == 9.3
        assert record.severity == "CRITICAL"

    def test_05_multiple_cwes(self, nvd_source: NVDSource, sample_nvd_multi_cwe: dict):
        """Test 5: Multiple CWE normalization without invalid non-CWEs."""
        record = nvd_source.normalize(sample_nvd_multi_cwe)
        assert record.cwes == ["CWE-79", "CWE-20"]
        assert "NVD-CWE-noinfo" not in record.cwes

    def test_06_cpe_parser_simple(self):
        """Test 6: CPE 2.3 parsing helper."""
        cpe = "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"
        parsed = parse_cpe_23(cpe)
        assert parsed is not None
        assert parsed["part"] == "a"
        assert parsed["vendor"] == "apache"
        assert parsed["product"] == "http_server"
        assert parsed["version"] == "2.4.50"
        assert parsed["target_sw"] == "*"

    def test_07_cpe_parser_complex_escapes(self):
        """Test 7: CPE 2.3 parsing with backslashes and special characters."""
        cpe = r"cpe:2.3:a:paloalto:pan-os:10.1.6-h6:*:*:*:*:*:*:*"
        parsed = parse_cpe_23(cpe)
        assert parsed is not None
        assert parsed["vendor"] == "paloalto"
        assert parsed["product"] == "pan-os"
        assert parsed["version"] == "10.1.6-h6"

    def test_08_cpe_not_mapped_to_package_ecosystem(
        self, nvd_source: NVDSource, sample_nvd_generic_app_cpe: dict
    ):
        """Test 8: Generic application CPE must NOT be converted to a package ecosystem."""
        record = nvd_source.normalize(sample_nvd_generic_app_cpe)

        # Must not generate false package ranges
        assert len(record.affected_ranges) == 0
        # But provenance and raw payload are preserved
        assert len(record.source_records) == 1
        assert record.source_records[0].has_affected_range is False
        assert "http_server" in record.vendor_project or "apache" in record.vendor_project

    def test_09_safe_range_mapped_to_package(
        self, nvd_source: NVDSource, sample_nvd_safe_package_cpe: dict
    ):
        """Test 9: Safe CPE with explicit ecosystem target_sw maps cleanly to AffectedVersionRange."""
        record = nvd_source.normalize(sample_nvd_safe_package_cpe)

        assert len(record.affected_ranges) == 1
        ar = record.affected_ranges[0]
        assert ar.ecosystem == "pypi"
        assert ar.package_name == "requests"
        assert ar.range_type == "pep440"
        assert ar.introduced == "2.0.0"
        assert ar.fixed == "2.31.0"
        assert ar.source_name == "NVD"
        assert ar.raw_range == ">= 2.0.0, < 2.31.0"

    @pytest.mark.asyncio
    async def test_10_pagination_and_query_cves(
        self, nvd_source: NVDSource, sample_nvd_cve_basic: dict
    ):
        """Test 10: Pagination handling via query_cves."""
        mock_response = {
            "totalResults": 2,
            "startIndex": 0,
            "resultsPerPage": 2,
            "vulnerabilities": [sample_nvd_cve_basic, sample_nvd_cve_basic],
        }

        with patch.object(nvd_source, "_fetch_json", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_response
            records, total = await nvd_source.query_cves(start_index=0, results_per_page=2)

            assert len(records) == 2
            assert total == 2
            mock_fetch.assert_called_once()
            params = mock_fetch.call_args[1]["params"]
            assert params["startIndex"] == 0
            assert params["resultsPerPage"] == 2

    @pytest.mark.asyncio
    async def test_11_http_4xx_error(self, nvd_source: NVDSource):
        """Test 11: HTTP 4xx error raises SourceSyncError."""
        req = httpx.Request("GET", nvd_source.url)
        resp_404 = httpx.Response(404, request=req)

        with (
            patch(
                "httpx.AsyncClient.get",
                side_effect=httpx.HTTPStatusError("Not found", request=req, response=resp_404),
            ),
            pytest.raises(SourceSyncError, match="HTTP error 404"),
        ):
            await nvd_source.get_cve("CVE-2024-404")

    @pytest.mark.asyncio
    async def test_12_http_5xx_error(self, nvd_source: NVDSource):
        """Test 12: HTTP 5xx error raises SourceSyncError."""
        req = httpx.Request("GET", nvd_source.url)
        resp_503 = httpx.Response(503, request=req)

        with (
            patch(
                "httpx.AsyncClient.get",
                side_effect=httpx.HTTPStatusError(
                    "Service Unavailable", request=req, response=resp_503
                ),
            ),
            pytest.raises(SourceSyncError, match="HTTP error 503"),
        ):
            await nvd_source.get_cve("CVE-2024-503")

    @pytest.mark.asyncio
    async def test_13_timeout_error(self, nvd_source: NVDSource):
        """Test 13: HTTP timeout raises SourceSyncError."""
        with (
            patch(
                "httpx.AsyncClient.get",
                side_effect=httpx.TimeoutException("Read timeout"),
            ),
            pytest.raises(SourceSyncError, match="Timeout querying NVD API"),
        ):
            await nvd_source.get_cve("CVE-2024-9999")

    def test_14_invalid_payload(self, nvd_source: NVDSource):
        """Test 14: Invalid payload raises SourceParseError."""
        with pytest.raises(SourceParseError, match="must be a dictionary"):
            nvd_source.normalize("not a dict")  # type: ignore

        with pytest.raises(SourceParseError, match="Invalid NVD CVE identifier"):
            nvd_source.normalize({"cve": {"id": "INVALID-ID"}})


class TestNVDMultiSourceDeduplication:
    """Tests for NVD idempotency and multi-source deduplication with OSV and CISA KEV."""

    @pytest.mark.asyncio
    async def test_15_nvd_idempotence(
        self,
        db_session: AsyncSession,
        nvd_source: NVDSource,
        sample_nvd_cve_basic: dict,
    ):
        """Test 15: NVD synchronizes the same CVE twice. Must not duplicate rows."""
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        nvd_src, _ = await source_repo.get_or_create(name="NVD", source_type="nvd")
        record = nvd_source.normalize(sample_nvd_cve_basic)

        # Sync 1
        await vuln_repo.upsert_vulnerabilities(nvd_src.id, [record])
        await db_session.commit()
        v1 = await vuln_repo.get_by_canonical_id("CVE-2024-1001")
        assert v1 is not None
        uuid_1 = v1.id

        # Sync 2
        await vuln_repo.upsert_vulnerabilities(nvd_src.id, [record])
        await db_session.commit()

        # Check single vulnerability preserved
        all_vulns = await vuln_repo.get_all()
        assert len(all_vulns) == 1
        assert all_vulns[0].id == uuid_1

        idents = await vuln_repo.get_identifiers(uuid_1)
        assert len(idents) == 1

        srs = await vuln_repo.get_source_records(uuid_1)
        assert len(srs) == 1

    @pytest.mark.asyncio
    async def test_16_deduplication_osv_then_nvd(self, db_session: AsyncSession):
        """Test 16: OSV already has CVE-2025-0001, then NVD arrives. Must reuse exact UUID."""
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        osv_src, _ = await source_repo.get_or_create(name="OSV", source_type="osv")
        nvd_src, _ = await source_repo.get_or_create(name="NVD", source_type="nvd")

        # 1. OSV arrives first
        osv_rec = VulnerabilityRecord(
            canonical_id="CVE-2025-0001",
            cve_id="CVE-2025-0001",
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2025-0001",
                    identifier_type=IdentifierType.CVE,
                    source="OSV",
                ),
                VulnerabilityIdentifier(
                    identifier="GHSA-osv-0001",
                    identifier_type=IdentifierType.GHSA,
                    source="OSV",
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="flask",
                    range_type="pep440",
                    introduced="2.0.0",
                    fixed="2.0.3",
                    source_name="OSV",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [osv_rec])
        await db_session.commit()

        v1 = await vuln_repo.get_by_canonical_id("CVE-2025-0001")
        assert v1 is not None
        shared_uuid = v1.id

        # 2. NVD arrives with CVE-2025-0001, CVSS score, and CWE
        nvd_rec = VulnerabilityRecord(
            canonical_id="CVE-2025-0001",
            cve_id="CVE-2025-0001",
            source_name="NVD",
            severity="HIGH",
            cvss_score=8.5,
            cwes=["CWE-79"],
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2025-0001",
                    identifier_type=IdentifierType.CVE,
                    source="NVD",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(nvd_src.id, [nvd_rec])
        await db_session.commit()

        # 3. Verification: SAME UUID
        v2 = await vuln_repo.get_by_id(shared_uuid)
        assert v2 is not None
        assert v2.id == shared_uuid
        assert v2.canonical_id == "CVE-2025-0001"
        assert v2.severity == "HIGH"
        assert v2.cvss_score == 8.5

        # Source records from both OSV and NVD are preserved
        srs = await vuln_repo.get_source_records(shared_uuid)
        assert len(srs) == 2
        sources = {sr.source_name for sr in srs}
        assert "OSV" in sources
        assert "NVD" in sources

        # Ranges from OSV remain attached
        ranges = await vuln_repo.get_affected_ranges(shared_uuid)
        assert len(ranges) == 1
        assert ranges[0].package_name == "flask"

    @pytest.mark.asyncio
    async def test_17_deduplication_nvd_then_osv(self, db_session: AsyncSession):
        """Test 17: NVD arrives first, then OSV arrives with the same CVE."""
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        nvd_src, _ = await source_repo.get_or_create(name="NVD", source_type="nvd")
        osv_src, _ = await source_repo.get_or_create(name="OSV", source_type="osv")

        # 1. NVD arrives first
        nvd_rec = VulnerabilityRecord(
            canonical_id="CVE-2025-9999",
            cve_id="CVE-2025-9999",
            source_name="NVD",
            short_description="NVD initial description",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2025-9999",
                    identifier_type=IdentifierType.CVE,
                    source="NVD",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(nvd_src.id, [nvd_rec])
        await db_session.commit()

        v1 = await vuln_repo.get_by_canonical_id("CVE-2025-9999")
        assert v1 is not None
        shared_uuid = v1.id

        # 2. OSV arrives second with GHSA alias and affected range
        osv_rec = VulnerabilityRecord(
            canonical_id="CVE-2025-9999",
            cve_id="CVE-2025-9999",
            source_name="OSV",
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="CVE-2025-9999",
                    identifier_type=IdentifierType.CVE,
                    source="OSV",
                ),
                VulnerabilityIdentifier(
                    identifier="GHSA-nvd-first",
                    identifier_type=IdentifierType.GHSA,
                    source="OSV",
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="npm",
                    package_name="express",
                    range_type="semver",
                    introduced="4.0.0",
                    fixed="4.18.0",
                    source_name="OSV",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(osv_src.id, [osv_rec])
        await db_session.commit()

        # Reused same UUID
        v2 = await vuln_repo.get_by_id(shared_uuid)
        assert v2 is not None
        assert v2.id == shared_uuid
        assert v2.canonical_id == "CVE-2025-9999"

        # Identifiers contain both CVE and GHSA
        idents = await vuln_repo.get_identifiers(shared_uuid)
        ident_set = {i.identifier for i in idents}
        assert "CVE-2025-9999" in ident_set
        assert "GHSA-nvd-first" in ident_set

        # Source records contain both NVD and OSV
        srs = await vuln_repo.get_source_records(shared_uuid)
        assert len(srs) == 2

    @pytest.mark.asyncio
    async def test_18_sync_and_search_methods(
        self,
        nvd_source: NVDSource,
        sample_nvd_cve_basic: dict,
        sample_nvd_safe_package_cpe: dict,
    ):
        """Test NVD sync health check and in-memory search."""
        # 1. sync success
        with patch.object(nvd_source, "query_cves", new_callable=AsyncMock) as mock_q:
            mock_q.return_value = ([nvd_source.normalize(sample_nvd_cve_basic)], 1)
            res = await nvd_source.sync(limit=1)
            assert res.success is True
            assert res.records_synced == 1
            assert res.source_name == "NVD"

        # 2. sync failure
        with patch.object(nvd_source, "query_cves", new_callable=AsyncMock) as mock_fail:
            mock_fail.side_effect = SourceSyncError("NVD service offline")
            res_fail = await nvd_source.sync(limit=1)
            assert res_fail.success is False
            assert "NVD service offline" in res_fail.error

        # 3. search
        nvd_source._cached_records.append(nvd_source.normalize(sample_nvd_cve_basic))
        matches = await nvd_source.search("CVE-2024-1001")
        assert len(matches) == 1
        assert matches[0].canonical_id == "CVE-2024-1001"

        nvd_source._cached_records.append(nvd_source.normalize(sample_nvd_safe_package_cpe))
        pkg_matches = await nvd_source.search("requests")
        assert len(pkg_matches) >= 1

    @pytest.mark.asyncio
    async def test_19_edge_cases_and_error_branches(self, nvd_source: NVDSource):
        """Test parsing and network branches for NVD."""
        # 1. Invalid CPE strings
        assert parse_cpe_23("not-a-cpe") is None
        assert parse_cpe_23("cpe:2.3:a:b") is None
        assert map_cpe_to_package_ecosystem({"part": "o"}) is None

        # 2. Vendor mapping fallback in map_cpe_to_package_ecosystem
        cpe_vendor = {
            "part": "a",
            "target_sw": "*",
            "vendor": "python",
            "product": "certifi",
        }
        mapped = map_cpe_to_package_ecosystem(cpe_vendor)
        assert mapped is not None
        assert mapped[0] == "pypi"
        assert mapped[1] == "certifi"

        # 3. Client initialization with API key and custom settings / existing client
        mock_cli = httpx.AsyncClient()
        src_with_cli = NVDSource(http_client=mock_cli)
        assert await src_with_cli._get_client() is mock_cli
        await mock_cli.aclose()

        custom = NVDSource(settings=NVDSourceSettings(api_key="secret-key", timeout_seconds=15.0))
        client = await custom._get_client()
        assert client.headers.get("apiKey") == "secret-key"
        await client.aclose()

        # 4. get_cve success & empty list
        with patch.object(
            nvd_source,
            "_fetch_json",
            return_value={"vulnerabilities": [{"cve": {"id": "CVE-2024-7777"}}]},
        ):
            cve_rec = await nvd_source.get_cve("CVE-2024-7777")
            assert cve_rec is not None
            assert cve_rec.canonical_id == "CVE-2024-7777"

        with patch.object(nvd_source, "_fetch_json", return_value={"vulnerabilities": []}):
            assert await nvd_source.get_cve("CVE-2024-0000") is None

        # 5. query_cves with parameters and non-list error
        with patch.object(
            nvd_source,
            "_fetch_json",
            return_value={"totalResults": 0, "vulnerabilities": []},
        ) as mock_f:
            await nvd_source.query_cves(
                cpe_name="cpe:2.3:a:psf:requests:*:*:*:*:*:python:*:*", keyword="overflow"
            )
            mock_f.assert_called_once()
            call_params = mock_f.call_args[1]["params"]
            assert call_params["cpeName"] == "cpe:2.3:a:psf:requests:*:*:*:*:*:python:*:*"
            assert call_params["keywordSearch"] == "overflow"

        with (
            patch.object(nvd_source, "_fetch_json", return_value={"vulnerabilities": "bad"}),
            pytest.raises(SourceParseError, match="Expected 'vulnerabilities' list"),
        ):
            await nvd_source.query_cves()

        # 6. Fallback non-en description and published date
        raw_non_en = {
            "cve": {
                "id": "CVE-2024-9000",
                "published": "2024-05-10T12:00:00Z",
                "descriptions": [{"lang": "es", "value": "Descripcion en espanol"}],
            }
        }
        rec = nvd_source.normalize(raw_non_en)
        assert rec.short_description == "Descripcion en espanol"
        assert rec.date_added is not None

        # 7. CVSS v2 fallback
        raw_v2 = {
            "cve": {
                "id": "CVE-2024-9001",
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {"baseScore": 6.8},
                            "baseSeverity": "MEDIUM",
                        }
                    ]
                },
            }
        }
        rec_v2 = nvd_source.normalize(raw_v2)
        assert rec_v2.cvss_score == 6.8
        assert rec_v2.severity == "MEDIUM"

        # 8. Malformed weaknesses and configurations
        raw_malformed_config = {
            "cve": {
                "id": "CVE-2024-9002",
                "weaknesses": ["not-a-dict", {"description": "not-a-list"}],
                "configurations": [
                    "not-a-dict",
                    {
                        "nodes": [
                            "not-a-dict",
                            {
                                "cpeMatch": [
                                    "not-a-dict",
                                    {"vulnerable": False},
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:psf:requests:*:*:*:*:*:python:*:*",
                                        "versionStartExcluding": "1.0",
                                        "versionEndIncluding": "2.0",
                                    },
                                ]
                            },
                        ]
                    },
                ],
            }
        }
        rec_mal = nvd_source.normalize(raw_malformed_config)
        assert len(rec_mal.affected_ranges) == 1
        assert rec_mal.affected_ranges[0].introduced == "1.0"
        assert rec_mal.affected_ranges[0].last_affected == "2.0"

        # 9. _fetch_json connection and parse error
        req = httpx.Request("GET", "https://example.com")
        with (
            patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("Failed", request=req)),
            pytest.raises(SourceSyncError, match="Connection failed querying NVD"),
        ):
            await nvd_source._fetch_json("https://example.com")

        bad_resp = httpx.Response(200, request=req, content=b"{bad")
        with (
            patch("httpx.AsyncClient.get", return_value=bad_resp),
            pytest.raises(SourceParseError, match="Failed to parse NVD API JSON"),
        ):
            await nvd_source._fetch_json("https://example.com")
