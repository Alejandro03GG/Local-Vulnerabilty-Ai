"""Tests for the deterministic vulnerability matcher."""

from __future__ import annotations

import pytest

from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    Ecosystem,
    MatchType,
    VersionType,
    VulnerabilityRecord,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher


@pytest.fixture
def matcher() -> VulnerabilityMatcher:
    return VulnerabilityMatcher()


class TestExactNameMatching:
    """Tests for exact product name matching."""

    def test_exact_match_django(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Django component should match Django vulnerability."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        django_matches = [m for m in matches if m.component.name == "django"]
        assert len(django_matches) >= 1
        assert django_matches[0].match_type == MatchType.EXACT_NAME

    def test_exact_match_flask(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Flask component should match Flask vulnerability."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        flask_matches = [m for m in matches if m.component.name == "flask"]
        assert len(flask_matches) >= 1

    def test_exact_match_requests(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Requests component should match Requests vulnerability."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        requests_matches = [m for m in matches if m.component.name == "requests"]
        assert len(requests_matches) >= 1


class TestNoMatch:
    """Tests for components that should NOT match."""

    def test_no_match_numpy(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """numpy should not match any vulnerability in our fixture."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        numpy_matches = [m for m in matches if m.component.name == "numpy"]
        assert len(numpy_matches) == 0

    def test_no_match_pydantic(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """pydantic should not match any vulnerability in our fixture."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        pydantic_matches = [m for m in matches if m.component.name == "pydantic"]
        assert len(pydantic_matches) == 0

    def test_empty_components(self, matcher: VulnerabilityMatcher, sample_vulnerabilities):
        matches = matcher.match([], sample_vulnerabilities)
        assert len(matches) == 0

    def test_empty_vulnerabilities(self, matcher: VulnerabilityMatcher, sample_components):
        matches = matcher.match(sample_components, [])
        assert len(matches) == 0

    def test_both_empty(self, matcher: VulnerabilityMatcher):
        matches = matcher.match([], [])
        assert len(matches) == 0


class TestMatchConfidence:
    """Tests for match confidence levels."""

    def test_exact_name_higher_confidence(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Exact name matches should have higher confidence than vendor matches."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        for m in matches:
            if m.match_type == MatchType.EXACT_NAME:
                assert m.match_confidence >= 0.5
            elif m.match_type == MatchType.VENDOR_PRODUCT:
                assert m.match_confidence < 0.7

    def test_confidence_within_bounds(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """All confidence scores should be between 0.0 and 1.0."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        for m in matches:
            assert 0.0 <= m.match_confidence <= 1.0


class TestApplicability:
    """Tests for applicability assessment."""

    def test_exact_match_is_detected(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Exact name matches should be marked as DETECTED."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        exact_matches = [m for m in matches if m.match_type == MatchType.EXACT_NAME]
        for m in exact_matches:
            assert m.applicability == Applicability.DETECTED

    def test_never_likely_affected_without_version_evidence(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Matcher should never claim LIKELY_AFFECTED with KEV alone."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        for m in matches:
            assert m.applicability != Applicability.LIKELY_AFFECTED


class TestEvidence:
    """Tests for evidence generation."""

    def test_evidence_not_empty(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Every match should have evidence."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        for m in matches:
            assert len(m.evidence) > 0

    def test_evidence_mentions_kev_limitation(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Evidence should mention KEV version range limitation."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        for m in matches:
            kev_note = [e for e in m.evidence if "version range" in e.lower()]
            assert len(kev_note) > 0, f"Match {m.vulnerability.cve_id} missing KEV limitation note"

    def test_evidence_includes_source_file(
        self, matcher: VulnerabilityMatcher, sample_components, sample_vulnerabilities
    ):
        """Evidence should mention where the component was found."""
        matches = matcher.match(sample_components, sample_vulnerabilities)
        for m in matches:
            source_evidence = [e for e in m.evidence if "Found in" in e]
            assert len(source_evidence) > 0


class TestNormalization:
    """Tests for matching with normalization."""

    def test_case_insensitive_matching(self, matcher: VulnerabilityMatcher):
        """Matching should be case-insensitive."""
        components = [
            DetectedComponent(
                name="Django",
                version="4.2",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulnerabilities = [
            VulnerabilityRecord(
                cve_id="CVE-2024-1000",
                source_name="CISA KEV",
                vendor_project="django",
                product="django",
            )
        ]
        matches = matcher.match(components, vulnerabilities)
        assert len(matches) >= 1

    def test_hyphen_underscore_normalization(self, matcher: VulnerabilityMatcher):
        """Hyphens and underscores should be treated as equivalent."""
        components = [
            DetectedComponent(
                name="my-package",
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulnerabilities = [
            VulnerabilityRecord(
                cve_id="CVE-2024-9999",
                source_name="CISA KEV",
                vendor_project="Test",
                product="my_package",
            )
        ]
        matches = matcher.match(components, vulnerabilities)
        assert len(matches) >= 1

    def test_no_duplicate_matches(self, matcher: VulnerabilityMatcher):
        """Same CVE should not match a component more than once."""
        components = [
            DetectedComponent(
                name="django",
                version="4.2",
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        # Vulnerability where vendor AND product are "Django"
        vulnerabilities = [
            VulnerabilityRecord(
                cve_id="CVE-2024-1000",
                source_name="CISA KEV",
                vendor_project="Django",
                product="Django",
            )
        ]
        matches = matcher.match(components, vulnerabilities)
        cve_ids = [m.vulnerability.cve_id for m in matches]
        assert cve_ids.count("CVE-2024-1000") == 1
