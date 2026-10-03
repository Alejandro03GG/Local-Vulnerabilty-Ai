"""Comprehensive tests for the version-aware matcher (Stage 7).

Tests cover:
- Version parsing per ecosystem (PEP 440, SemVer, Maven)
- Range evaluation (introduced+fixed, introduced+last_affected, open ranges)
- Edge cases (unparseable versions, None versions, "0" introduced)
- Multi-ecosystem support
- Integration with the VulnerabilityMatcher
- Structured evidence generation
- Boundary conditions (exactly at fixed, exactly at introduced)
"""

from __future__ import annotations

import pytest

from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    DetectedComponent,
    Ecosystem,
    EvidenceType,
    MatchType,
    VersionType,
    VulnerabilityRecord,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.matching.version import (
    MavenStrategy,
    PEP440Strategy,
    RangeVerdict,
    SemVerStrategy,
    evaluate_component_ranges,
    get_strategy,
)

# ===========================================================================
# Section 1: Version Parsing Tests
# ===========================================================================


class TestPEP440Parsing:
    """PEP 440 version parsing via packaging.version."""

    def test_standard_version(self):
        s = PEP440Strategy()
        v = s.parse("2.31.0")
        assert v is not None

    def test_pre_release(self):
        s = PEP440Strategy()
        assert s.parse("4.0.0a1") is not None
        assert s.parse("4.0.0b2") is not None
        assert s.parse("4.0.0rc1") is not None

    def test_post_release(self):
        s = PEP440Strategy()
        assert s.parse("1.0.post1") is not None

    def test_dev_release(self):
        s = PEP440Strategy()
        assert s.parse("1.0.dev5") is not None

    def test_epoch(self):
        s = PEP440Strategy()
        assert s.parse("1!2.0") is not None

    def test_invalid_version(self):
        s = PEP440Strategy()
        assert s.parse("not-a-version") is None

    def test_empty_string(self):
        s = PEP440Strategy()
        assert s.parse("") is None


class TestSemVerParsing:
    """SemVer parsing via semver library."""

    def test_standard_version(self):
        s = SemVerStrategy()
        v = s.parse("1.2.3")
        assert v is not None

    def test_with_prerelease(self):
        s = SemVerStrategy()
        v = s.parse("1.0.0-alpha.1")
        assert v is not None

    def test_with_build_metadata(self):
        s = SemVerStrategy()
        v = s.parse("1.0.0+build.123")
        assert v is not None

    def test_v_prefix_stripped(self):
        s = SemVerStrategy()
        v = s.parse("v1.2.3")
        assert v is not None

    def test_two_part_coercion(self):
        s = SemVerStrategy()
        v = s.parse("1.0")
        assert v is not None

    def test_one_part_coercion(self):
        s = SemVerStrategy()
        v = s.parse("5")
        assert v is not None

    def test_invalid(self):
        s = SemVerStrategy()
        assert s.parse("not-semver-at-all!!!") is None


class TestMavenParsing:
    """Maven version comparison."""

    def test_standard_version(self):
        s = MavenStrategy()
        v = s.parse("3.12.0")
        assert v is not None

    def test_snapshot(self):
        s = MavenStrategy()
        v = s.parse("1.0-SNAPSHOT")
        assert v is not None

    def test_alpha(self):
        s = MavenStrategy()
        v = s.parse("1.0-alpha-1")
        assert v is not None

    def test_empty_string(self):
        s = MavenStrategy()
        assert s.parse("") is None


# ===========================================================================
# Section 2: Version Comparison Tests
# ===========================================================================


class TestPEP440Comparison:
    """Verify PEP 440 ordering."""

    def test_basic_ordering(self):
        s = PEP440Strategy()
        a = s.parse("1.0.0")
        b = s.parse("2.0.0")
        assert s.compare(a, b) == -1
        assert s.compare(b, a) == 1
        assert s.compare(a, a) == 0

    def test_pre_vs_release(self):
        s = PEP440Strategy()
        pre = s.parse("1.0.0rc1")
        rel = s.parse("1.0.0")
        assert s.compare(pre, rel) == -1

    def test_post_after_release(self):
        s = PEP440Strategy()
        rel = s.parse("1.0.0")
        post = s.parse("1.0.0.post1")
        assert s.compare(rel, post) == -1


class TestSemVerComparison:
    """Verify SemVer ordering."""

    def test_basic_ordering(self):
        s = SemVerStrategy()
        a = s.parse("1.0.0")
        b = s.parse("2.0.0")
        assert s.compare(a, b) == -1
        assert s.compare(b, a) == 1

    def test_prerelease_before_release(self):
        s = SemVerStrategy()
        pre = s.parse("1.0.0-alpha.1")
        rel = s.parse("1.0.0")
        assert s.compare(pre, rel) == -1

    def test_patch_ordering(self):
        s = SemVerStrategy()
        a = s.parse("1.0.0")
        b = s.parse("1.0.1")
        assert s.compare(a, b) == -1


class TestMavenComparison:
    """Verify Maven version ordering."""

    def test_basic_ordering(self):
        s = MavenStrategy()
        a = s.parse("1.0")
        b = s.parse("2.0")
        assert s.compare(a, b) == -1

    def test_snapshot_before_release(self):
        s = MavenStrategy()
        snap = s.parse("1.0-snapshot")
        rel = s.parse("1.0")
        assert s.compare(snap, rel) == -1

    def test_alpha_before_beta(self):
        s = MavenStrategy()
        alpha = s.parse("1.0-alpha")
        beta = s.parse("1.0-beta")
        assert s.compare(alpha, beta) == -1


# ===========================================================================
# Section 3: Range Evaluation Tests
# ===========================================================================


class TestRangeEvaluationPEP440:
    """Range evaluation with PEP 440 (PyPI)."""

    def _make_range(self, **kwargs) -> AffectedVersionRange:
        defaults = {
            "ecosystem": "pypi",
            "package_name": "requests",
            "range_type": "ecosystem",
            "source_name": "OSV",
        }
        defaults.update(kwargs)
        return AffectedVersionRange(**defaults)

    def test_within_introduced_fixed(self):
        """Version 2.25.0 is within [2.0, 3.0)."""
        s = PEP440Strategy()
        r = self._make_range(introduced="2.0", fixed="3.0")
        ev = s.evaluate_range("2.25.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_outside_above_fixed(self):
        """Version 3.0.0 is at the fixed boundary → OUTSIDE."""
        s = PEP440Strategy()
        r = self._make_range(introduced="2.0", fixed="3.0")
        ev = s.evaluate_range("3.0.0", r)
        assert ev.verdict == RangeVerdict.OUTSIDE

    def test_exactly_at_introduced(self):
        """Version exactly at introduced → WITHIN."""
        s = PEP440Strategy()
        r = self._make_range(introduced="2.0", fixed="3.0")
        ev = s.evaluate_range("2.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_below_introduced(self):
        """Version 1.9.0 is below introduced 2.0 → OUTSIDE."""
        s = PEP440Strategy()
        r = self._make_range(introduced="2.0", fixed="3.0")
        ev = s.evaluate_range("1.9.0", r)
        assert ev.verdict == RangeVerdict.OUTSIDE

    def test_within_last_affected(self):
        """Version 2.5 is within [2.0, 2.31] (inclusive)."""
        s = PEP440Strategy()
        r = self._make_range(introduced="2.0", last_affected="2.31.0")
        ev = s.evaluate_range("2.5.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_exactly_at_last_affected(self):
        """Version at last_affected boundary → WITHIN (inclusive)."""
        s = PEP440Strategy()
        r = self._make_range(introduced="2.0", last_affected="2.31.0")
        ev = s.evaluate_range("2.31.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_above_last_affected(self):
        """Version above last_affected → OUTSIDE."""
        s = PEP440Strategy()
        r = self._make_range(introduced="2.0", last_affected="2.31.0")
        ev = s.evaluate_range("2.32.0", r)
        assert ev.verdict == RangeVerdict.OUTSIDE

    def test_open_range_within(self):
        """Open range [1.0, ∞) — version 5.0 is within."""
        s = PEP440Strategy()
        r = self._make_range(introduced="1.0")
        ev = s.evaluate_range("5.0.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_open_range_below(self):
        """Open range [1.0, ∞) — version 0.9 is OUTSIDE."""
        s = PEP440Strategy()
        r = self._make_range(introduced="1.0")
        ev = s.evaluate_range("0.9.0", r)
        assert ev.verdict == RangeVerdict.OUTSIDE

    def test_zero_introduced_means_all(self):
        """Introduced = "0" means 'from the beginning'."""
        s = PEP440Strategy()
        r = self._make_range(introduced="0", fixed="2.0")
        ev = s.evaluate_range("0.1.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_none_introduced_means_all(self):
        """Introduced = None means 'from the beginning'."""
        s = PEP440Strategy()
        r = self._make_range(introduced=None, fixed="2.0")
        ev = s.evaluate_range("1.5.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_unparseable_installed_version(self):
        """Unparseable installed version → UNKNOWN."""
        s = PEP440Strategy()
        r = self._make_range(introduced="1.0", fixed="2.0")
        ev = s.evaluate_range("not-a-version", r)
        assert ev.verdict == RangeVerdict.UNKNOWN

    def test_no_boundaries(self):
        """No structured boundaries → UNKNOWN."""
        s = PEP440Strategy()
        r = self._make_range()
        ev = s.evaluate_range("1.0.0", r)
        assert ev.verdict == RangeVerdict.UNKNOWN


class TestRangeEvaluationSemVer:
    """Range evaluation with SemVer (npm, Cargo, Go, NuGet)."""

    def _make_range(self, **kwargs) -> AffectedVersionRange:
        defaults = {
            "ecosystem": "npm",
            "package_name": "lodash",
            "range_type": "semver",
            "source_name": "OSV",
        }
        defaults.update(kwargs)
        return AffectedVersionRange(**defaults)

    def test_within_range(self):
        s = SemVerStrategy()
        r = self._make_range(introduced="4.0.0", fixed="4.17.21")
        ev = s.evaluate_range("4.17.20", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_at_fixed_boundary(self):
        s = SemVerStrategy()
        r = self._make_range(introduced="4.0.0", fixed="4.17.21")
        ev = s.evaluate_range("4.17.21", r)
        assert ev.verdict == RangeVerdict.OUTSIDE

    def test_above_fixed(self):
        s = SemVerStrategy()
        r = self._make_range(introduced="4.0.0", fixed="4.17.21")
        ev = s.evaluate_range("4.18.0", r)
        assert ev.verdict == RangeVerdict.OUTSIDE

    def test_v_prefix_in_installed(self):
        s = SemVerStrategy()
        r = self._make_range(introduced="1.0.0", fixed="2.0.0")
        ev = s.evaluate_range("v1.5.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_go_module_version(self):
        s = SemVerStrategy()
        r = AffectedVersionRange(
            ecosystem="go",
            package_name="github.com/gin-gonic/gin",
            range_type="semver",
            introduced="0",
            fixed="1.9.1",
            source_name="OSV",
        )
        ev = s.evaluate_range("1.9.0", r)
        assert ev.verdict == RangeVerdict.WITHIN

    def test_go_fixed_version(self):
        s = SemVerStrategy()
        r = AffectedVersionRange(
            ecosystem="go",
            package_name="github.com/gin-gonic/gin",
            range_type="semver",
            introduced="0",
            fixed="1.9.1",
            source_name="OSV",
        )
        ev = s.evaluate_range("1.9.1", r)
        assert ev.verdict == RangeVerdict.OUTSIDE


# ===========================================================================
# Section 4: Strategy Registry Tests
# ===========================================================================


class TestStrategyRegistry:
    """Test strategy lookup by ecosystem."""

    def test_pypi(self):
        assert isinstance(get_strategy(Ecosystem.PYPI), PEP440Strategy)

    def test_npm(self):
        assert isinstance(get_strategy(Ecosystem.NPM), SemVerStrategy)

    def test_cargo(self):
        assert isinstance(get_strategy(Ecosystem.CARGO), SemVerStrategy)

    def test_go(self):
        assert isinstance(get_strategy(Ecosystem.GO), SemVerStrategy)

    def test_maven(self):
        assert isinstance(get_strategy(Ecosystem.MAVEN), MavenStrategy)

    def test_nuget(self):
        assert isinstance(get_strategy(Ecosystem.NUGET), SemVerStrategy)

    def test_unknown_ecosystem(self):
        assert get_strategy("totally_unknown") is None

    def test_string_lookup(self):
        assert isinstance(get_strategy("pypi"), PEP440Strategy)


# ===========================================================================
# Section 5: evaluate_component_ranges Tests
# ===========================================================================


class TestEvaluateComponentRanges:
    """Integration test for evaluate_component_ranges."""

    def _make_component(self, name="requests", version="2.25.0", ecosystem=Ecosystem.PYPI):
        return DetectedComponent(
            name=name,
            version=version,
            version_type=VersionType.EXACT,
            ecosystem=ecosystem,
            source_file="requirements.txt",
        )

    def _make_range(self, **kwargs):
        defaults = {
            "ecosystem": "pypi",
            "package_name": "requests",
            "range_type": "ecosystem",
            "source_name": "OSV",
        }
        defaults.update(kwargs)
        return AffectedVersionRange(**defaults)

    def test_likely_affected(self):
        """Component version within range → LIKELY_AFFECTED."""
        component = self._make_component(version="2.25.0")
        ranges = [self._make_range(introduced="2.0", fixed="2.28.0")]
        applicability, evidences = evaluate_component_ranges(component, ranges, "CVE-2023-1234")
        assert applicability == Applicability.LIKELY_AFFECTED
        assert len(evidences) >= 1
        assert evidences[0].evidence_type == EvidenceType.RANGE_CONFIRMED

    def test_likely_not_affected(self):
        """Component version outside range → LIKELY_NOT_AFFECTED."""
        component = self._make_component(version="2.32.0")
        ranges = [self._make_range(introduced="2.0", fixed="2.28.0")]
        applicability, evidences = evaluate_component_ranges(component, ranges, "CVE-2023-1234")
        assert applicability == Applicability.LIKELY_NOT_AFFECTED
        assert evidences[0].evidence_type == EvidenceType.OUTSIDE_RANGE

    def test_no_version(self):
        """Component without version → UNKNOWN."""
        component = self._make_component(version=None)
        ranges = [self._make_range(introduced="2.0", fixed="2.28.0")]
        applicability, evidences = evaluate_component_ranges(component, ranges, "CVE-2023-1234")
        assert applicability == Applicability.UNKNOWN
        assert evidences[0].evidence_type == EvidenceType.VERSION_UNKNOWN

    def test_no_matching_ranges(self):
        """No ranges match component ecosystem+name → UNKNOWN with no evidence."""
        component = self._make_component(name="flask")
        ranges = [self._make_range(package_name="requests", introduced="2.0", fixed="3.0")]
        applicability, evidences = evaluate_component_ranges(component, ranges, "CVE-2023-1234")
        assert applicability == Applicability.UNKNOWN
        assert len(evidences) == 0

    def test_multiple_ranges_one_within(self):
        """Multiple ranges, one match → LIKELY_AFFECTED wins."""
        component = self._make_component(version="2.25.0")
        ranges = [
            self._make_range(introduced="1.0", fixed="2.0"),  # outside
            self._make_range(introduced="2.20", fixed="2.28.0"),  # within
        ]
        applicability, evidences = evaluate_component_ranges(component, ranges, "CVE-2023-1234")
        assert applicability == Applicability.LIKELY_AFFECTED
        assert len(evidences) == 2

    def test_unsupported_ecosystem(self):
        """Unsupported ecosystem → UNKNOWN."""
        component = DetectedComponent(
            name="mylib",
            version="1.0",
            version_type=VersionType.EXACT,
            ecosystem=Ecosystem.UNKNOWN,
            source_file="unknown.lock",
        )
        ranges = [
            AffectedVersionRange(
                ecosystem="unknown",
                package_name="mylib",
                range_type="ecosystem",
                introduced="0",
                fixed="2.0",
                source_name="OSV",
            )
        ]
        applicability, _evidences = evaluate_component_ranges(component, ranges, "CVE-2023-0000")
        assert applicability == Applicability.UNKNOWN

    def test_cross_ecosystem_ignored(self):
        """Ranges for different ecosystem are ignored."""
        component = self._make_component(name="lodash", ecosystem=Ecosystem.NPM)
        ranges = [self._make_range(ecosystem="pypi", package_name="lodash")]
        applicability, evidences = evaluate_component_ranges(component, ranges, "CVE-2023-9999")
        assert applicability == Applicability.UNKNOWN
        assert len(evidences) == 0


# ===========================================================================
# Section 6: VulnerabilityMatcher Integration Tests
# ===========================================================================


class TestMatcherVersionAwareIntegration:
    """Test VulnerabilityMatcher with version-aware logic."""

    @pytest.fixture
    def matcher(self):
        return VulnerabilityMatcher()

    def test_kev_only_no_version_evaluation(self, matcher):
        """CISA KEV has no affected_ranges → name-only match, DETECTED."""
        components = [
            DetectedComponent(
                name="django",
                version="4.2.11",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                cve_id="CVE-2024-1000",
                source_name="CISA KEV",
                vendor_project="Django",
                product="Django",
                affected_ranges=[],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) == 1
        assert matches[0].applicability == Applicability.DETECTED
        # Structured evidence should contain PRODUCT_NAME_ONLY
        assert any(
            ev.evidence_type == EvidenceType.PRODUCT_NAME_ONLY
            for ev in matches[0].structured_evidences
        )

    def test_osv_range_likely_affected(self, matcher):
        """OSV range confirms version is affected → LIKELY_AFFECTED."""
        components = [
            DetectedComponent(
                name="requests",
                version="2.25.0",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="CVE-2023-9999",
                cve_id="CVE-2023-9999",
                source_name="OSV",
                vendor_project="",
                product="requests",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="pypi",
                        package_name="requests",
                        range_type="ecosystem",
                        introduced="2.0",
                        fixed="2.28.0",
                        source_name="OSV",
                        raw_range=">= 2.0, < 2.28.0",
                    )
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) == 1
        assert matches[0].applicability == Applicability.LIKELY_AFFECTED
        assert any(
            ev.evidence_type == EvidenceType.RANGE_CONFIRMED
            for ev in matches[0].structured_evidences
        )

    def test_osv_range_likely_not_affected(self, matcher):
        """OSV range confirms version is NOT affected → LIKELY_NOT_AFFECTED."""
        components = [
            DetectedComponent(
                name="requests",
                version="2.32.0",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="CVE-2023-9999",
                cve_id="CVE-2023-9999",
                source_name="OSV",
                vendor_project="",
                product="requests",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="pypi",
                        package_name="requests",
                        range_type="ecosystem",
                        introduced="2.0",
                        fixed="2.28.0",
                        source_name="OSV",
                        raw_range=">= 2.0, < 2.28.0",
                    )
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) == 1
        assert matches[0].applicability == Applicability.LIKELY_NOT_AFFECTED

    def test_npm_package_via_range_index(self, matcher):
        """npm package matched via affected_range package_name index."""
        components = [
            DetectedComponent(
                name="lodash",
                version="4.17.20",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.NPM,
                source_file="package.json",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="GHSA-xxxx-yyyy-zzzz",
                source_name="OSV",
                vendor_project="",
                product="lodash-vuln-entry",  # product doesn't match
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="npm",
                        package_name="lodash",
                        range_type="semver",
                        introduced="0",
                        fixed="4.17.21",
                        source_name="OSV",
                        raw_range="< 4.17.21",
                    )
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) == 1
        assert matches[0].applicability == Applicability.LIKELY_AFFECTED
        assert matches[0].match_type == MatchType.NORMALIZED

    def test_no_version_component_stays_unknown(self, matcher):
        """Component without version stays UNKNOWN even with ranges."""
        components = [
            DetectedComponent(
                name="requests",
                version=None,
                version_type=VersionType.UNKNOWN,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="CVE-2023-9999",
                source_name="OSV",
                vendor_project="",
                product="requests",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="pypi",
                        package_name="requests",
                        range_type="ecosystem",
                        introduced="2.0",
                        fixed="2.28.0",
                        source_name="OSV",
                    )
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) == 1
        assert matches[0].applicability == Applicability.UNKNOWN

    def test_multi_source_deduplication(self, matcher):
        """Same canonical_id matched via product and range should not duplicate."""
        components = [
            DetectedComponent(
                name="django",
                version="4.2.0",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="CVE-2024-1000",
                cve_id="CVE-2024-1000",
                source_name="Multi",
                vendor_project="Django",
                product="Django",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="pypi",
                        package_name="django",
                        range_type="ecosystem",
                        introduced="4.0",
                        fixed="4.2.8",
                        source_name="OSV",
                    )
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        # Should get exactly 1 match (product match), not duplicated by range index
        assert len(matches) == 1
        assert matches[0].applicability == Applicability.LIKELY_AFFECTED


# ===========================================================================
# Section 7: Boundary & Edge Case Tests
# ===========================================================================


class TestBoundaryConditions:
    """Critical boundary conditions for version comparison."""

    def test_fixed_is_exclusive_pep440(self):
        """fixed boundary is exclusive: version == fixed → OUTSIDE."""
        s = PEP440Strategy()
        r = AffectedVersionRange(
            ecosystem="pypi",
            package_name="pkg",
            range_type="ecosystem",
            introduced="1.0",
            fixed="2.0",
            source_name="test",
        )
        assert s.evaluate_range("2.0", r).verdict == RangeVerdict.OUTSIDE

    def test_last_affected_is_inclusive_pep440(self):
        """last_affected boundary is inclusive: version == last_affected → WITHIN."""
        s = PEP440Strategy()
        r = AffectedVersionRange(
            ecosystem="pypi",
            package_name="pkg",
            range_type="ecosystem",
            introduced="1.0",
            last_affected="2.0",
            source_name="test",
        )
        assert s.evaluate_range("2.0", r).verdict == RangeVerdict.WITHIN

    def test_introduced_is_inclusive_pep440(self):
        """introduced boundary is inclusive: version == introduced → WITHIN."""
        s = PEP440Strategy()
        r = AffectedVersionRange(
            ecosystem="pypi",
            package_name="pkg",
            range_type="ecosystem",
            introduced="1.0",
            fixed="2.0",
            source_name="test",
        )
        assert s.evaluate_range("1.0", r).verdict == RangeVerdict.WITHIN

    def test_fixed_is_exclusive_semver(self):
        s = SemVerStrategy()
        r = AffectedVersionRange(
            ecosystem="npm",
            package_name="pkg",
            range_type="semver",
            introduced="1.0.0",
            fixed="2.0.0",
            source_name="test",
        )
        assert s.evaluate_range("2.0.0", r).verdict == RangeVerdict.OUTSIDE

    def test_one_version_below_fixed_semver(self):
        s = SemVerStrategy()
        r = AffectedVersionRange(
            ecosystem="npm",
            package_name="pkg",
            range_type="semver",
            introduced="1.0.0",
            fixed="2.0.0",
            source_name="test",
        )
        assert s.evaluate_range("1.99.99", r).verdict == RangeVerdict.WITHIN

    def test_pre_release_below_fixed(self):
        """Pre-release of the fixed version should be WITHIN."""
        s = PEP440Strategy()
        r = AffectedVersionRange(
            ecosystem="pypi",
            package_name="pkg",
            range_type="ecosystem",
            introduced="1.0",
            fixed="2.0",
            source_name="test",
        )
        assert s.evaluate_range("2.0rc1", r).verdict == RangeVerdict.WITHIN

    def test_zero_introduced_semver(self):
        """introduced="0" → from beginning, version 0.0.1 is within."""
        s = SemVerStrategy()
        r = AffectedVersionRange(
            ecosystem="npm",
            package_name="pkg",
            range_type="semver",
            introduced="0",
            fixed="1.0.0",
            source_name="test",
        )
        assert s.evaluate_range("0.0.1", r).verdict == RangeVerdict.WITHIN


# ===========================================================================
# Section 8: Real-World Scenario Tests
# ===========================================================================


class TestRealWorldScenarios:
    """Tests based on real vulnerability patterns."""

    @pytest.fixture
    def matcher(self):
        return VulnerabilityMatcher()

    def test_django_cve_with_osv_range(self, matcher):
        """Django 4.2.0 is affected by a CVE with OSV range [4.0, 4.2.8)."""
        components = [
            DetectedComponent(
                name="django",
                version="4.2.0",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="CVE-2024-12345",
                cve_id="CVE-2024-12345",
                source_name="Multi",
                vendor_project="Django",
                product="Django",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="pypi",
                        package_name="Django",
                        range_type="ecosystem",
                        introduced="4.0",
                        fixed="4.2.8",
                        source_name="OSV",
                        raw_range=">= 4.0, < 4.2.8",
                    ),
                    AffectedVersionRange(
                        ecosystem="pypi",
                        package_name="Django",
                        range_type="ecosystem",
                        introduced="5.0",
                        fixed="5.0.1",
                        source_name="OSV",
                        raw_range=">= 5.0, < 5.0.1",
                    ),
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) == 1
        m = matches[0]
        assert m.applicability == Applicability.LIKELY_AFFECTED
        # Should have evidence for both ranges (one within, one outside)
        assert len(m.structured_evidences) == 2

    def test_patched_django_not_affected(self, matcher):
        """Django 4.2.8 is at the fixed version → LIKELY_NOT_AFFECTED."""
        components = [
            DetectedComponent(
                name="django",
                version="4.2.8",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="CVE-2024-12345",
                cve_id="CVE-2024-12345",
                source_name="Multi",
                vendor_project="Django",
                product="Django",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="pypi",
                        package_name="Django",
                        range_type="ecosystem",
                        introduced="4.0",
                        fixed="4.2.8",
                        source_name="OSV",
                        raw_range=">= 4.0, < 4.2.8",
                    ),
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) == 1
        assert matches[0].applicability == Applicability.LIKELY_NOT_AFFECTED

    def test_cargo_package_within_range(self, matcher):
        """Cargo package serde 1.0.150 within affected range [1.0.0, 1.0.160)."""
        components = [
            DetectedComponent(
                name="serde",
                version="1.0.150",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.CARGO,
                source_file="Cargo.lock",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="RUSTSEC-2024-0001",
                source_name="OSV",
                vendor_project="",
                product="serde",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="cargo",
                        package_name="serde",
                        range_type="semver",
                        introduced="1.0.0",
                        fixed="1.0.160",
                        source_name="OSV",
                    )
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) >= 1
        assert any(m.applicability == Applicability.LIKELY_AFFECTED for m in matches)

    def test_maven_spring_boot(self, matcher):
        """Maven Spring Boot 2.7.0 within [2.0, 2.7.14)."""
        components = [
            DetectedComponent(
                name="spring-boot",
                version="2.7.0",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.MAVEN,
                source_file="pom.xml",
            )
        ]
        vulns = [
            VulnerabilityRecord(
                canonical_id="CVE-2023-5555",
                source_name="NVD",
                vendor_project="pivotal",
                product="spring_boot",
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem="maven",
                        package_name="spring-boot",
                        range_type="maven",
                        introduced="2.0",
                        fixed="2.7.14",
                        source_name="NVD",
                    )
                ],
            )
        ]
        matches = matcher.match(components, vulns)
        assert len(matches) >= 1
        assert any(m.applicability == Applicability.LIKELY_AFFECTED for m in matches)


class TestVersionBoundaryAudit:
    """Comprehensive boundary tests for Stage 7.1 audit.

    Verifies introduced, fixed, last_affected, and limit boundaries
    across all supported ecosystems (PyPI, npm, Go, Cargo, NuGet, Maven).
    """

    # --- Limit Boundary Tests ---

    def test_limit_boundary_npm(self):
        """npm SemVer [1.0.0, 2.0.0) where 2.0.0 is limit."""
        strategy = get_strategy("npm")
        assert strategy is not None
        ar = AffectedVersionRange(
            ecosystem="npm",
            package_name="test-pkg",
            introduced="1.0.0",
            limit="2.0.0",
        )
        # Below intro -> OUTSIDE
        assert strategy.evaluate_range("0.9.9", ar).verdict == RangeVerdict.OUTSIDE
        # Exactly intro -> WITHIN
        assert strategy.evaluate_range("1.0.0", ar).verdict == RangeVerdict.WITHIN
        # Inside -> WITHIN
        assert strategy.evaluate_range("1.5.0", ar).verdict == RangeVerdict.WITHIN
        # Exactly limit -> OUTSIDE (limit is exclusive)
        assert strategy.evaluate_range("2.0.0", ar).verdict == RangeVerdict.OUTSIDE
        # Above limit -> OUTSIDE
        assert strategy.evaluate_range("2.0.1", ar).verdict == RangeVerdict.OUTSIDE

    def test_limit_boundary_pypi_pep440(self):
        """PyPI PEP440 [1.0.0, 2.0.0) where 2.0.0 is limit."""
        strategy = get_strategy("pypi")
        assert strategy is not None
        ar = AffectedVersionRange(
            ecosystem="pypi",
            package_name="test-pkg",
            introduced="1.0.0",
            limit="2.0.0",
        )
        assert strategy.evaluate_range("0.9.9", ar).verdict == RangeVerdict.OUTSIDE
        assert strategy.evaluate_range("1.0.0", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("1.9.9", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("2.0.0", ar).verdict == RangeVerdict.OUTSIDE
        assert strategy.evaluate_range("2.0.1", ar).verdict == RangeVerdict.OUTSIDE

    def test_limit_with_introduced_zero(self):
        """Range [0, 3.0.0) with limit and introduced='0' (beginning of time)."""
        strategy = get_strategy("cargo")
        assert strategy is not None
        ar = AffectedVersionRange(
            ecosystem="cargo",
            package_name="test-crate",
            introduced="0",
            limit="3.0.0",
        )
        assert strategy.evaluate_range("0.0.1", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("2.9.9", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("3.0.0", ar).verdict == RangeVerdict.OUTSIDE

    # --- Fixed Boundary Tests ---

    def test_fixed_boundary_exclusive(self):
        """Range [1.0.0, 1.2.0) with fixed=1.2.0: 1.2.0 must be OUTSIDE."""
        strategy = get_strategy("npm")
        ar = AffectedVersionRange(
            ecosystem="npm",
            package_name="foo",
            introduced="1.0.0",
            fixed="1.2.0",
        )
        assert strategy.evaluate_range("1.0.0", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("1.1.9", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("1.2.0", ar).verdict == RangeVerdict.OUTSIDE
        assert strategy.evaluate_range("1.2.1", ar).verdict == RangeVerdict.OUTSIDE

    # --- Last Affected Boundary Tests ---

    def test_last_affected_boundary_inclusive(self):
        """Range [1.0.0, 1.2.0] with last_affected=1.2.0: 1.2.0 must be WITHIN."""
        strategy = get_strategy("go")
        ar = AffectedVersionRange(
            ecosystem="go",
            package_name="github.com/foo/bar",
            introduced="1.0.0",
            last_affected="1.2.0",
        )
        assert strategy.evaluate_range("0.9.0", ar).verdict == RangeVerdict.OUTSIDE
        assert strategy.evaluate_range("1.0.0", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("1.2.0", ar).verdict == RangeVerdict.WITHIN  # Inclusive!
        assert strategy.evaluate_range("1.2.1", ar).verdict == RangeVerdict.OUTSIDE

    # --- Open Range Tests ---

    def test_open_range_no_upper_bound(self):
        """Range [2.0.0, ∞): all versions >= 2.0.0 are WITHIN."""
        strategy = get_strategy("nuget")
        ar = AffectedVersionRange(
            ecosystem="nuget",
            package_name="Newtonsoft.Json",
            introduced="2.0.0",
        )
        assert strategy.evaluate_range("1.9.9", ar).verdict == RangeVerdict.OUTSIDE
        assert strategy.evaluate_range("2.0.0", ar).verdict == RangeVerdict.WITHIN
        assert strategy.evaluate_range("99.99.99", ar).verdict == RangeVerdict.WITHIN

    # --- Maven Qualifier Ordering Tests ---

    def test_maven_qualifier_order_boundaries(self):
        """Maven qualifier ordering: alpha < beta < rc < release < sp."""
        strategy = get_strategy("maven")
        assert isinstance(strategy, MavenStrategy)

        ar = AffectedVersionRange(
            ecosystem="maven",
            package_name="org.example:demo",
            introduced="1.0-alpha",
            fixed="1.0",
        )
        # 1.0-alpha is intro -> WITHIN
        assert strategy.evaluate_range("1.0-alpha", ar).verdict == RangeVerdict.WITHIN
        # 1.0-beta is between alpha and release -> WITHIN
        assert strategy.evaluate_range("1.0-beta", ar).verdict == RangeVerdict.WITHIN
        # 1.0-rc is between beta and release -> WITHIN
        assert strategy.evaluate_range("1.0-rc", ar).verdict == RangeVerdict.WITHIN
        # 1.0 (release) is fixed -> OUTSIDE
        assert strategy.evaluate_range("1.0", ar).verdict == RangeVerdict.OUTSIDE
        # 1.0-sp1 is post-release -> OUTSIDE
        assert strategy.evaluate_range("1.0-sp1", ar).verdict == RangeVerdict.OUTSIDE


def test_os_package_version_strategy_deb_apk_rpm():
    """deb/apk/rpm ecosystems use normalized upstream version comparison."""
    from vuln_ai.matching.version import get_strategy

    deb = get_strategy("deb")
    apk = get_strategy("apk")
    rpm = get_strategy("rpm")
    assert deb is not None and apk is not None and rpm is not None

    assert deb.parse("1:3.0.11-1~deb12u1") == deb.parse("3.0.11")
    assert apk.parse("1.2.4-r2") == apk.parse("1.2.4")
    assert rpm.parse("2.1.0-4.el9") == rpm.parse("2.1.0")

    assert deb.compare(deb.parse("7.88.1-10"), deb.parse("8.0.0")) == -1
    assert deb.compare(deb.parse("8.0.0"), deb.parse("7.88.1")) == 1
    assert deb.compare(deb.parse("8.0.0"), deb.parse("8.0.0-1")) == 0

    assert deb.parse("") is None
    assert deb.parse("not-a-version") is None
    assert deb.is_valid("3.0.2") is True

    # letter-suffixed OpenSSL-style versions fall back to numeric prefix
    assert str(deb.parse("1.1.1w")) == "1.1.1"


def test_os_package_range_evaluation_likely_affected():
    """Version-aware matching works for Debian OS packages with affected ranges."""
    from vuln_ai.core.models import (
        AffectedVersionRange,
        Applicability,
        DetectedComponent,
        Ecosystem,
    )
    from vuln_ai.matching.version import evaluate_component_ranges

    component = DetectedComponent(
        name="libssl3",
        version="3.0.2-1",
        ecosystem=Ecosystem.DEB,
        source_file="/var/lib/dpkg/status",
    )
    ranges = [
        AffectedVersionRange(
            ecosystem="deb",
            package_name="libssl3",
            introduced="0",
            fixed="3.0.8",
            source_name="OSV",
        )
    ]
    applicability, evidence = evaluate_component_ranges(component, ranges, "CVE-OS-1")
    assert applicability == Applicability.LIKELY_AFFECTED
    assert evidence
