"""Tests for the CISA KEV source parser."""

from __future__ import annotations

import pytest

from vuln_ai.core.exceptions import SourceParseError
from vuln_ai.sources.cisa_kev import CISAKEVSource


@pytest.fixture
def kev_source() -> CISAKEVSource:
    return CISAKEVSource()


class TestKEVParser:
    """Tests for KEV JSON parsing."""

    def test_parse_valid_data(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        records = kev_source._parse(sample_kev_data)
        assert len(records) == 5

    def test_parse_cve_ids(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        records = kev_source._parse(sample_kev_data)
        cve_ids = {r.cve_id for r in records}
        assert "CVE-2024-1000" in cve_ids
        assert "CVE-2024-2000" in cve_ids
        assert "CVE-2024-5000" in cve_ids

    def test_parse_vendor_product(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        records = kev_source._parse(sample_kev_data)
        django = next(r for r in records if r.cve_id == "CVE-2024-1000")
        assert django.vendor_project == "Django"
        assert django.product == "Django"

    def test_parse_cwes(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        records = kev_source._parse(sample_kev_data)
        fortinet = next(r for r in records if r.cve_id == "CVE-2024-2000")
        assert fortinet.cwes == ["CWE-22", "CWE-158"]

    def test_parse_dates(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        records = kev_source._parse(sample_kev_data)
        django = next(r for r in records if r.cve_id == "CVE-2024-1000")
        assert django.date_added is not None
        assert django.date_added.year == 2024
        assert django.date_added.month == 1
        assert django.date_added.day == 15

    def test_parse_ransomware(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        records = kev_source._parse(sample_kev_data)
        fortinet = next(r for r in records if r.cve_id == "CVE-2024-2000")
        assert fortinet.known_ransomware_use == "Known"

    def test_parse_source_name(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        records = kev_source._parse(sample_kev_data)
        assert all(r.source_name == "CISA KEV" for r in records)

    def test_parse_empty_vulnerabilities(self, kev_source: CISAKEVSource):
        data = {"vulnerabilities": []}
        records = kev_source._parse(data)
        assert len(records) == 0

    def test_parse_not_a_dict(self, kev_source: CISAKEVSource):
        with pytest.raises(SourceParseError, match="not a JSON object"):
            kev_source._parse("not a dict")

    def test_parse_missing_vulnerabilities_key(self, kev_source: CISAKEVSource):
        with pytest.raises(SourceParseError, match="missing 'vulnerabilities'"):
            kev_source._parse({"title": "test"})

    def test_parse_vulnerabilities_not_array(self, kev_source: CISAKEVSource):
        with pytest.raises(SourceParseError, match="not an array"):
            kev_source._parse({"vulnerabilities": "not an array"})

    def test_parse_entry_missing_cve(self, kev_source: CISAKEVSource):
        """Entries without cveID should be skipped."""
        data = {
            "vulnerabilities": [
                {"vendorProject": "Test", "product": "Test"},
                {
                    "cveID": "CVE-2024-1000",
                    "vendorProject": "Test",
                    "product": "Test",
                },
            ]
        }
        records = kev_source._parse(data)
        assert len(records) == 1

    def test_parse_entry_missing_vendor(self, kev_source: CISAKEVSource):
        """Entries without vendor/product should be skipped."""
        data = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-1000"},
                {
                    "cveID": "CVE-2024-2000",
                    "vendorProject": "Test",
                    "product": "Test",
                },
            ]
        }
        records = kev_source._parse(data)
        assert len(records) == 1


class TestKEVSearch:
    """Tests for KEV record searching."""

    @pytest.fixture(autouse=True)
    def _setup(self, kev_source: CISAKEVSource, sample_kev_data: dict):
        """Parse sample data into the source before each test."""
        self.source = kev_source
        self.source._records = kev_source._parse(sample_kev_data)

    async def test_search_by_product_name(self):
        results = await self.source.search("django")
        assert len(results) >= 1
        assert any(r.cve_id == "CVE-2024-1000" for r in results)

    async def test_search_by_product_case_insensitive(self):
        results = await self.source.search("Django")
        assert len(results) >= 1

    async def test_search_no_match(self):
        results = await self.source.search("nonexistent-package")
        assert len(results) == 0

    async def test_search_by_vendor_filter(self):
        results = await self.source.search("fortimail", vendor="Fortinet")
        assert len(results) >= 1
        assert any(r.cve_id == "CVE-2024-2000" for r in results)

    async def test_search_by_product_filter(self):
        results = await self.source.search("flask", product="Flask")
        assert len(results) >= 1


class TestKEVProperties:
    """Tests for KEV source properties."""

    def test_name(self, kev_source: CISAKEVSource):
        assert kev_source.name == "CISA KEV"

    def test_source_type(self, kev_source: CISAKEVSource):
        assert kev_source.source_type == "kev"

    def test_url(self, kev_source: CISAKEVSource):
        assert "cisa.gov" in kev_source.url
