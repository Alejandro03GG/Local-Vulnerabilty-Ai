"""Tests for Pydantic domain models and normalization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vuln_ai.core.models import (
    Applicability,
    ComponentType,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    ScanResultSummary,
    ScanStatus,
    VersionType,
    VulnerabilityRecord,
    normalize_component_name,
)


class TestNormalization:
    """Tests for component name normalization."""

    def test_lowercase(self):
        assert normalize_component_name("Django") == "django"

    def test_hyphens_to_underscores(self):
        assert normalize_component_name("my-package") == "my_package"

    def test_dots_to_underscores(self):
        assert normalize_component_name("my.package") == "my_package"

    def test_strip_whitespace(self):
        assert normalize_component_name("  django  ") == "django"

    def test_collapse_underscores(self):
        assert normalize_component_name("my__package") == "my_package"

    def test_mixed_separators(self):
        assert normalize_component_name("My-Cool.Package") == "my_cool_package"

    def test_already_normalized(self):
        assert normalize_component_name("requests") == "requests"

    def test_empty_string(self):
        assert normalize_component_name("") == ""

    def test_strip_leading_trailing_underscores(self):
        assert normalize_component_name("_private_") == "private"

    def test_kev_vendor_normalization(self):
        """KEV vendor names like 'Fortinet' should normalize."""
        assert normalize_component_name("Fortinet") == "fortinet"
        assert normalize_component_name("FortiMail") == "fortimail"
        assert normalize_component_name("Apache") == "apache"
        assert normalize_component_name("HTTP Server") == "http server"


class TestDetectedComponent:
    """Tests for the DetectedComponent model."""

    def test_valid_component(self):
        comp = DetectedComponent(
            name="django",
            version="4.2.11",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
        assert comp.name == "django"
        assert comp.version == "4.2.11"
        assert comp.ecosystem == Ecosystem.PYPI
        assert comp.version_type == VersionType.UNKNOWN
        assert comp.component_type == ComponentType.LIBRARY

    def test_component_without_version(self):
        comp = DetectedComponent(
            name="numpy",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
        assert comp.version is None
        assert comp.version_type == VersionType.UNKNOWN

    def test_normalized_name(self):
        comp = DetectedComponent(
            name="My-Package",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
        assert comp.normalized_name() == "my_package"

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            DetectedComponent(
                name="django",
                # Missing ecosystem and source_file
            )


class TestVulnerabilityRecord:
    """Tests for the VulnerabilityRecord model."""

    def test_valid_record(self):
        record = VulnerabilityRecord(
            cve_id="CVE-2024-1234",
            source_name="CISA KEV",
            vendor_project="Django",
            product="Django",
        )
        assert record.cve_id == "CVE-2024-1234"
        assert record.cwes == []
        assert record.known_ransomware_use == "Unknown"

    def test_normalized_vendor(self):
        record = VulnerabilityRecord(
            cve_id="CVE-2024-1234",
            source_name="CISA KEV",
            vendor_project="Fortinet",
            product="FortiMail",
        )
        assert record.normalized_vendor() == "fortinet"
        assert record.normalized_product() == "fortimail"

    def test_record_with_cwes(self):
        record = VulnerabilityRecord(
            cve_id="CVE-2024-1234",
            source_name="CISA KEV",
            vendor_project="Test",
            product="Test",
            cwes=["CWE-89", "CWE-79"],
        )
        assert len(record.cwes) == 2


class TestMatchResult:
    """Tests for the MatchResult model."""

    def test_valid_match(self, sample_components, sample_vulnerabilities):
        match = MatchResult(
            component=sample_components[0],
            vulnerability=sample_vulnerabilities[0],
            match_type=MatchType.EXACT_NAME,
            match_confidence=0.7,
            applicability=Applicability.DETECTED,
            evidence=["Component matches product name"],
        )
        assert match.match_confidence == 0.7
        assert match.applicability == Applicability.DETECTED

    def test_confidence_bounds(self, sample_components, sample_vulnerabilities):
        """Confidence must be between 0.0 and 1.0."""
        with pytest.raises(ValidationError):
            MatchResult(
                component=sample_components[0],
                vulnerability=sample_vulnerabilities[0],
                match_type=MatchType.EXACT_NAME,
                match_confidence=1.5,
            )

    def test_confidence_negative(self, sample_components, sample_vulnerabilities):
        with pytest.raises(ValidationError):
            MatchResult(
                component=sample_components[0],
                vulnerability=sample_vulnerabilities[0],
                match_type=MatchType.EXACT_NAME,
                match_confidence=-0.1,
            )


class TestScanResultSummary:
    """Tests for the ScanResultSummary model."""

    def test_empty_scan(self):
        result = ScanResultSummary(
            project_name="test",
            project_path="/tmp/test",
            scan_status=ScanStatus.COMPLETED,
        )
        assert result.components_found == 0
        assert result.matches == []

    def test_failed_scan(self):
        result = ScanResultSummary(
            project_name="test",
            project_path="/tmp/test",
            scan_status=ScanStatus.FAILED,
            error="Project not found",
        )
        assert result.scan_status == ScanStatus.FAILED
        assert result.error is not None
