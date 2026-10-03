"""Unit tests for the OSV source adapter and normalization engine."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.config import OSVSourceSettings
from vuln_ai.core.exceptions import SourceParseError, SourceSyncError
from vuln_ai.core.models import Ecosystem, IdentifierType
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository
from vuln_ai.sources.osv import (
    OSVSource,
    determine_canonical_id,
    determine_identifier_type,
    map_osv_ecosystem,
    map_to_osv_ecosystem,
)

# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------


@pytest.fixture
def osv_source() -> OSVSource:
    return OSVSource()


@pytest.fixture
def sample_osv_simple() -> dict:
    return {
        "schema_version": "1.6.0",
        "id": "GHSA-j8r2-6x86-q33q",
        "summary": "Urllib3 vulnerable to header injection",
        "details": "Urllib3 prior to 1.26.18 is vulnerable to CRLF injection in HTTP headers.",
        "aliases": ["CVE-2023-45803"],
        "published": "2023-10-18T19:30:00Z",
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "urllib3",
                    "purl": "pkg:pypi/urllib3",
                },
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
        "database_specific": {"severity": "MODERATE"},
        "severity": [{"type": "CVSS_V3", "score": "5.3"}],
    }


@pytest.fixture
def sample_osv_multi_id() -> dict:
    return {
        "id": "PYSEC-2024-123",
        "aliases": ["CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"],
        "summary": "Multiple identifier test vulnerability",
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


@pytest.fixture
def sample_osv_no_cve() -> dict:
    return {
        "id": "GHSA-9999-8888-7777",
        "aliases": ["OSV-2024-001"],
        "summary": "Advisory without CVE identifier",
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


@pytest.fixture
def sample_osv_osv_only() -> dict:
    return {
        "id": "OSV-2024-999",
        "summary": "Pure OSV identifier vulnerability",
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


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------


class TestOSVAdapterNormalization:
    """Tests covering normalization of OSV records into Canonical VulnerabilityRecords."""

    def test_01_simple_osv_vulnerability(self, osv_source: OSVSource, sample_osv_simple: dict):
        """Test 1: Simple OSV vulnerability normalization.

        Verifies canonical_id, identifiers, source record, package, and ecosystem.
        """
        record = osv_source.normalize(sample_osv_simple)

        # Canonical ID selection: CVE exists in aliases, so CVE is chosen
        assert record.canonical_id == "CVE-2023-45803"
        assert record.cve_id == "CVE-2023-45803"
        assert record.product == "urllib3"
        assert record.source_name == "OSV"

        # Identifiers must contain both GHSA and CVE
        ident_dict = {i.identifier: i.identifier_type for i in record.identifiers}
        assert "GHSA-j8r2-6x86-q33q" in ident_dict
        assert ident_dict["GHSA-j8r2-6x86-q33q"] == IdentifierType.GHSA
        assert "CVE-2023-45803" in ident_dict
        assert ident_dict["CVE-2023-45803"] == IdentifierType.CVE

        # Source record provenance
        assert len(record.source_records) == 1
        sr = record.source_records[0]
        assert sr.source_name == "OSV"
        assert sr.source_identifier == "GHSA-j8r2-6x86-q33q"
        assert sr.has_kev_evidence is False
        assert sr.has_affected_range is True
        assert sr.raw_payload == sample_osv_simple

        # Ecosystem and package ranges
        assert len(record.affected_ranges) == 2
        r1, r2 = record.affected_ranges
        assert r1.package_name == "urllib3"
        assert r1.ecosystem == "pypi"
        assert r1.introduced == "0"
        assert r1.fixed == "1.26.18"
        assert r2.package_name == "urllib3"
        assert r2.introduced == "2.0.0"
        assert r2.fixed == "2.0.7"

    def test_02_osv_cve_ghsa_osv_id_priority(
        self, osv_source: OSVSource, sample_osv_multi_id: dict
    ):
        """Test 2: OSV with CVE + GHSA + OSV ID.

        Verifies CVE becomes canonical_id and all 3 identifiers are preserved without loss.
        """
        # Direct function test
        canon, cve = determine_canonical_id(
            "PYSEC-2024-123", ["GHSA-xxxx-yyyy-zzzz", "CVE-2024-1234"]
        )
        assert canon == "CVE-2024-1234"
        assert cve == "CVE-2024-1234"

        record = osv_source.normalize(sample_osv_multi_id)

        assert record.canonical_id == "CVE-2024-1234"
        assert record.cve_id == "CVE-2024-1234"

        ident_map = {i.identifier: i.identifier_type for i in record.identifiers}
        assert len(ident_map) == 3
        assert ident_map["CVE-2024-1234"] == IdentifierType.CVE
        assert ident_map["GHSA-xxxx-yyyy-zzzz"] == IdentifierType.GHSA
        assert ident_map["PYSEC-2024-123"] == IdentifierType.PYSEC

    def test_03_osv_without_cve(
        self,
        osv_source: OSVSource,
        sample_osv_no_cve: dict,
        sample_osv_osv_only: dict,
    ):
        """Test 3: OSV without CVE.

        - If GHSA exists, it becomes canonical_id (cve_id is None).
        - If neither CVE nor GHSA exists, native OSV ID becomes canonical_id.
        """
        # Case A: GHSA without CVE
        rec_ghsa = osv_source.normalize(sample_osv_no_cve)
        assert rec_ghsa.canonical_id == "GHSA-9999-8888-7777"
        assert rec_ghsa.cve_id is None
        assert any(i.identifier == "GHSA-9999-8888-7777" for i in rec_ghsa.identifiers)
        assert any(i.identifier == "OSV-2024-001" for i in rec_ghsa.identifiers)

        # Case B: Native OSV ID only
        rec_osv = osv_source.normalize(sample_osv_osv_only)
        assert rec_osv.canonical_id == "OSV-2024-999"
        assert rec_osv.cve_id is None
        assert rec_osv.identifiers[0].identifier == "OSV-2024-999"
        assert rec_osv.identifiers[0].identifier_type == IdentifierType.OSV

    def test_04_affected_ranges_details(self, osv_source: OSVSource):
        """Test 4: Affected ranges extraction and precision.

        Tests introduced, fixed, last_affected, limit, raw_range, and range_type.
        """
        raw = {
            "id": "OSV-RANGE-TEST",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "express"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "4.0.0"},
                                {"fixed": "4.18.2"},
                                {"introduced": "5.0.0-alpha.1"},
                                {"last_affected": "5.0.0-alpha.7"},
                                {"introduced": "6.0.0"},
                                {"limit": "7.0.0"},
                                {"introduced": "8.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        record = osv_source.normalize(raw)
        ranges = record.affected_ranges
        assert len(ranges) == 4

        # 1. introduced + fixed
        assert ranges[0].introduced == "4.0.0"
        assert ranges[0].fixed == "4.18.2"
        assert ranges[0].last_affected is None
        assert ranges[0].range_type == "semver"
        assert ranges[0].raw_range == ">= 4.0.0, < 4.18.2"

        # 2. introduced + last_affected
        assert ranges[1].introduced == "5.0.0-alpha.1"
        assert ranges[1].fixed is None
        assert ranges[1].last_affected == "5.0.0-alpha.7"
        assert ranges[1].raw_range == ">= 5.0.0-alpha.1, <= 5.0.0-alpha.7"

        # 3. introduced + limit
        assert ranges[2].introduced == "6.0.0"
        assert ranges[2].limit == "7.0.0"
        assert ranges[2].fixed is None
        assert ranges[2].last_affected is None
        assert ranges[2].raw_range == ">= 6.0.0, < 7.0.0"

        # 4. trailing open-ended introduced
        assert ranges[3].introduced == "8.0.0"
        assert ranges[3].fixed is None
        assert ranges[3].raw_range == ">= 8.0.0"

    def test_05_multiple_ranges_and_multiple_packages(self, osv_source: OSVSource):
        """Test 5: Vulnerability affecting multiple packages and ranges.

        Ensures no package or range is lost during normalization.
        """
        raw = {
            "id": "CVE-2024-8888",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pkg-a"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"fixed": "1.5"}],
                        }
                    ],
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "pkg-b"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.0"}, {"fixed": "2.8"}],
                        }
                    ],
                },
            ],
        }

        record = osv_source.normalize(raw)
        assert len(record.affected_ranges) == 2
        pkgs = {ar.package_name: ar.fixed for ar in record.affected_ranges}
        assert pkgs["pkg-a"] == "1.5"
        assert pkgs["pkg-b"] == "2.8"

    def test_06_severity_and_cvss_mapping(self, osv_source: OSVSource):
        """Test 6: Normalization of severity ratings and CVSS scores without hallucination."""
        # Case A: Explicit database_specific severity and float CVSS
        raw_with_both = {
            "id": "OSV-SEV-1",
            "database_specific": {"severity": "CRITICAL"},
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        }
        rec_both = osv_source.normalize(raw_with_both)
        assert rec_both.severity == "CRITICAL"
        assert rec_both.cvss_score == 9.8

        # Case B: CVSS vector string without float base score
        raw_vector = {
            "id": "OSV-SEV-2",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
        }
        rec_vector = osv_source.normalize(raw_vector)
        assert rec_vector.cvss_score is None  # Must not invent float score
        assert rec_vector.severity == "CVSS_RATED"

        # Case C: Completely absent severity metadata
        raw_none = {"id": "OSV-SEV-3"}
        rec_none = osv_source.normalize(raw_none)
        assert rec_none.severity is None
        assert rec_none.cvss_score is None

    @pytest.mark.asyncio
    async def test_07_idempotence(
        self,
        db_session: AsyncSession,
        osv_source: OSVSource,
        sample_osv_simple: dict,
    ):
        """Test 7: Idempotency.

        Repeated synchronizations/upserts of the same records must not create duplicate
        vulnerabilities, identifiers, source records, or affected ranges.
        """
        source_repo = SourceRepository(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        source, _ = await source_repo.get_or_create(
            name="OSV",
            source_type="osv",
            url=osv_source.url,
        )

        record = osv_source.normalize(sample_osv_simple)

        # 1st upsert
        count1 = await vuln_repo.upsert_vulnerabilities(source.id, [record])
        await db_session.commit()
        assert count1 == 1

        v1 = await vuln_repo.get_by_canonical_id("CVE-2023-45803")
        assert v1 is not None
        idents1 = await vuln_repo.get_identifiers(v1.id)
        ranges1 = await vuln_repo.get_affected_ranges(v1.id)
        sources1 = await vuln_repo.get_source_records(v1.id)

        assert len(idents1) == 2  # GHSA and CVE
        assert len(ranges1) == 2  # 2 ranges
        assert len(sources1) == 1  # 1 source record

        # 2nd upsert with identical record
        count2 = await vuln_repo.upsert_vulnerabilities(source.id, [record])
        await db_session.commit()
        assert count2 == 1

        v2 = await vuln_repo.get_by_canonical_id("CVE-2023-45803")
        assert v2 is not None
        idents2 = await vuln_repo.get_identifiers(v2.id)
        ranges2 = await vuln_repo.get_affected_ranges(v2.id)
        sources2 = await vuln_repo.get_source_records(v2.id)

        # Counts must remain identical without duplicate rows
        assert len(idents2) == len(idents1)
        assert len(ranges2) == len(ranges1)
        assert len(sources2) == len(sources1)

        # Check find_by_package works with newly saved ranges
        found = await vuln_repo.find_by_package("pypi", "urllib3")
        assert len(found) == 1
        assert found[0].canonical_id == "CVE-2023-45803"

    @pytest.mark.asyncio
    async def test_08_http_errors_4xx_5xx(self, osv_source: OSVSource):
        """Test 8: HTTP error handling.

        Raises SourceSyncError on 4xx and 5xx HTTP responses.
        """
        req = httpx.Request("POST", f"{osv_source.url}/query")

        # 404 response on query
        resp_404 = httpx.Response(404, request=req)
        with (
            patch(
                "httpx.AsyncClient.post",
                side_effect=httpx.HTTPStatusError("Not found", request=req, response=resp_404),
            ),
            pytest.raises(SourceSyncError, match="HTTP error 404"),
        ):
            await osv_source.query_package("nonexistent-pkg", Ecosystem.PYPI)

        # 500 server error
        resp_500 = httpx.Response(500, request=req)
        with (
            patch(
                "httpx.AsyncClient.post",
                side_effect=httpx.HTTPStatusError("Server error", request=req, response=resp_500),
            ),
            pytest.raises(SourceSyncError, match="HTTP error 500"),
        ):
            await osv_source.query_package("requests", Ecosystem.PYPI)

    @pytest.mark.asyncio
    async def test_09_timeout_error(self, osv_source: OSVSource):
        """Test 9: Timeout handling.

        Raises SourceSyncError when OSV API queries timeout.
        """
        with (
            patch(
                "httpx.AsyncClient.post",
                side_effect=httpx.TimeoutException("Connection timed out"),
            ),
            pytest.raises(SourceSyncError, match="Timeout querying OSV API"),
        ):
            await osv_source.query_package("requests", Ecosystem.PYPI)

    def test_10_invalid_payload(self, osv_source: OSVSource):
        """Test 10: Invalid payload handling.

        Raises SourceParseError on malformed JSON or missing required fields.
        """
        with pytest.raises(SourceParseError, match="must be a dict"):
            osv_source.normalize("not a dict")  # type: ignore

        with pytest.raises(SourceParseError, match="containing an 'id' field"):
            osv_source.normalize({"summary": "no id present"})

    def test_11_ecosystem_mappings(self, osv_source: OSVSource):
        """Test 11: Ecosystem mapping support for PyPI, npm, Go, and Cargo/crates.io."""
        ecosystems = [
            ("pypi", "PyPI", Ecosystem.PYPI),
            ("npm", "npm", Ecosystem.NPM),
            ("go", "Go", Ecosystem.GO),
            ("cargo", "crates.io", Ecosystem.CARGO),
        ]

        for internal, official_osv, enum_val in ecosystems:
            # Map OSV -> internal
            assert map_osv_ecosystem(official_osv) == internal
            # Map internal -> OSV
            assert map_to_osv_ecosystem(internal) == official_osv
            assert map_to_osv_ecosystem(enum_val) == official_osv

            # Verify normalized record preserves mapped ecosystem
            raw = {
                "id": f"OSV-ECO-{internal.upper()}",
                "affected": [
                    {
                        "package": {"ecosystem": official_osv, "name": f"test-{internal}"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}],
                            }
                        ],
                    }
                ],
            }
            rec = osv_source.normalize(raw)
            assert rec.affected_ranges[0].ecosystem == internal

    @pytest.mark.asyncio
    async def test_12_query_batch_and_search(self, osv_source: OSVSource):
        """Test querybatch operation and in-memory search method."""
        batch_response = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-1111-2222-3333",
                            "aliases": ["CVE-2024-1111"],
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "django"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "5.0.1"}],
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                },
                {"vulns": []},
            ]
        }

        with patch.object(osv_source, "_post_json", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = batch_response
            results = await osv_source.query_batch(
                [("django", Ecosystem.PYPI), ("fastapi", Ecosystem.PYPI)]
            )

            assert len(results) == 1
            assert results[0].canonical_id == "CVE-2024-1111"

            # Search in-memory
            found = await osv_source.search("django")
            assert len(found) == 1
            assert found[0].canonical_id == "CVE-2024-1111"

            # Search non-matching
            not_found = await osv_source.search("flask")
            assert len(not_found) == 0

    @pytest.mark.asyncio
    async def test_13_get_by_id_and_sync(self, osv_source: OSVSource, sample_osv_simple: dict):
        """Test get_by_id retrieval and sync health probe."""
        # 1. get_by_id 200
        req = httpx.Request("GET", f"{osv_source.url}/vulns/GHSA-j8r2-6x86-q33q")
        resp_ok = httpx.Response(200, request=req, content=json.dumps(sample_osv_simple).encode())

        with patch("httpx.AsyncClient.get", return_value=resp_ok):
            rec = await osv_source.get_by_id("GHSA-j8r2-6x86-q33q")
            assert rec is not None
            assert rec.canonical_id == "CVE-2023-45803"

        # 2. get_by_id 404
        resp_404 = httpx.Response(404, request=req)
        with patch("httpx.AsyncClient.get", return_value=resp_404):
            rec_404 = await osv_source.get_by_id("NONEXISTENT")
            assert rec_404 is None

        # 3. sync probe success
        with patch.object(osv_source, "query_package", new_callable=AsyncMock) as mock_query:
            mock_query.return_value = [osv_source.normalize(sample_osv_simple)]
            sync_res = await osv_source.sync()
            assert sync_res.success is True
            assert sync_res.records_synced == 1
            assert sync_res.source_name == "OSV"

        # 4. sync probe failure
        with patch.object(osv_source, "query_package", new_callable=AsyncMock) as mock_fail:
            mock_fail.side_effect = SourceSyncError("OSV API unavailable")
            sync_fail = await osv_source.sync()
            assert sync_fail.success is False
            assert "OSV API unavailable" in sync_fail.error

    @pytest.mark.asyncio
    async def test_14_edge_cases_and_error_branches(self, osv_source: OSVSource):
        """Test additional error and parsing edge cases."""
        # A. Unrecognized identifier prefix falls back to ALIAS
        assert determine_identifier_type("CUSTOM-1234") == IdentifierType.ALIAS

        # B. query_batch with empty queries returns []
        assert await osv_source.query_batch([]) == []

        # C. query_package with non-list 'vulns'
        with (
            patch.object(osv_source, "_post_json", return_value={"vulns": "not-a-list"}),
            pytest.raises(SourceParseError, match="Expected 'vulns' list"),
        ):
            await osv_source.query_package("pkg", Ecosystem.PYPI)

        # D. query_batch with non-list 'results'
        with (
            patch.object(osv_source, "_post_json", return_value={"results": "not-a-list"}),
            pytest.raises(SourceParseError, match="Expected 'results' list"),
        ):
            await osv_source.query_batch([("pkg", Ecosystem.PYPI)])

        # E. get_by_id exceptions
        req = httpx.Request("GET", "https://api.osv.dev/v1/vulns/TEST")
        with (
            patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Timeout")),
            pytest.raises(SourceSyncError, match="Timeout fetching OSV"),
        ):
            await osv_source.get_by_id("TEST")

        resp_500 = httpx.Response(500, request=req)
        with (
            patch(
                "httpx.AsyncClient.get",
                side_effect=httpx.HTTPStatusError("Err", request=req, response=resp_500),
            ),
            pytest.raises(SourceSyncError, match="HTTP error 500"),
        ):
            await osv_source.get_by_id("TEST")

        with (
            patch(
                "httpx.AsyncClient.get", side_effect=httpx.ConnectError("Conn err", request=req)
            ),
            pytest.raises(SourceSyncError, match="Connection error"),
        ):
            await osv_source.get_by_id("TEST")

        resp_bad_json = httpx.Response(200, request=req, content=b"invalid json")
        with (
            patch("httpx.AsyncClient.get", return_value=resp_bad_json),
            pytest.raises(SourceParseError, match="Failed to parse OSV"),
        ):
            await osv_source.get_by_id("TEST")

        # F. _post_json connection error and parse error
        with (
            patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Failed", request=req)),
            pytest.raises(SourceSyncError, match="Connection failed"),
        ):
            await osv_source._post_json("https://example.com", {})

        resp_bad_post = httpx.Response(200, request=req, content=b"{bad")
        with (
            patch("httpx.AsyncClient.post", return_value=resp_bad_post),
            pytest.raises(SourceParseError, match="Failed to parse OSV API JSON"),
        ):
            await osv_source._post_json("https://example.com", {})

        # G. Normalizing with non-dict affected / ranges / events items is resilient
        malformed_affected = {
            "id": "OSV-MALFORMED",
            "affected": [
                "not-a-dict",
                {
                    "package": {"ecosystem": "PyPI", "name": "test"},
                    "ranges": [
                        "not-a-dict",
                        {"type": "ECOSYSTEM", "events": "not-a-list"},
                        {"type": "ECOSYSTEM", "events": ["not-a-dict", {"introduced": "1.0"}]},
                    ],
                },
            ],
        }
        res = osv_source.normalize(malformed_affected)
        assert len(res.affected_ranges) == 1
        assert res.affected_ranges[0].introduced == "1.0"

        # H. Real client initialization when no mock passed
        custom_src = OSVSource(settings=OSVSourceSettings(timeout_seconds=25.0))
        client = await custom_src._get_client()
        assert client.timeout.read == 25.0
        await client.aclose()
