"""Unit tests for multi-version matching and independent applicability determinations."""

from __future__ import annotations

from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    DetectedComponent,
    Ecosystem,
    VulnerabilityRecord,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher


def test_multi_version_independent_matching():
    """Verify that multiple versions of the same package receive independent applicability results."""
    matcher = VulnerabilityMatcher()

    # Package A: vulnerable version 4.17.20 (affected: < 4.17.21)
    comp_vulnerable = DetectedComponent(
        name="lodash",
        version="4.17.20",
        ecosystem=Ecosystem.NPM,
        source_file="package-lock.json",
        is_direct=False,
        parent_name="legacy-module",
        dependency_path=["app", "legacy-module", "lodash"],
    )

    # Package B: patched version 4.17.21
    comp_patched = DetectedComponent(
        name="lodash",
        version="4.17.21",
        ecosystem=Ecosystem.NPM,
        source_file="package-lock.json",
        is_direct=True,
        dependency_path=["lodash"],
    )

    # Vulnerability affecting lodash < 4.17.21
    vuln = VulnerabilityRecord(
        canonical_id="GHSA-35jh-r3h4-6jhm",
        cve_id="CVE-2021-23337",
        source_name="OSV",
        product="lodash",
        short_description="Command Injection in lodash",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="npm",
                package_name="lodash",
                introduced="0",
                fixed="4.17.21",
                source_name="OSV",
            )
        ],
    )

    matches = matcher.match([comp_vulnerable, comp_patched], [vuln])
    assert len(matches) == 2

    match_by_ver = {m.component.version: m for m in matches}

    # 4.17.20 is LIKELY_AFFECTED
    assert match_by_ver["4.17.20"].applicability == Applicability.LIKELY_AFFECTED
    assert match_by_ver["4.17.20"].component.is_direct is False

    # 4.17.21 is LIKELY_NOT_AFFECTED
    assert match_by_ver["4.17.21"].applicability == Applicability.LIKELY_NOT_AFFECTED
    assert match_by_ver["4.17.21"].component.is_direct is True


def test_transitive_only_vulnerability_matching():
    """Verify that a vulnerability present only in a transitive dependency is detected with full path."""
    matcher = VulnerabilityMatcher()

    comp_direct = DetectedComponent(
        name="requests",
        version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=True,
    )
    comp_transitive = DetectedComponent(
        name="urllib3",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=False,
        parent_name="requests",
        dependency_path=["requests", "urllib3"],
    )

    vuln_urllib3 = VulnerabilityRecord(
        canonical_id="CVE-2024-9999",
        cve_id="CVE-2024-9999",
        source_name="OSV",
        product="urllib3",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="pypi",
                package_name="urllib3",
                introduced="2.0.0",
                fixed="2.32.0",
                source_name="OSV",
            )
        ],
    )

    matches = matcher.match([comp_direct, comp_transitive], [vuln_urllib3])
    assert len(matches) == 1
    m = matches[0]

    assert m.component.name == "urllib3"
    assert m.component.is_direct is False
    assert m.component.parent_name == "requests"
    assert m.component.dependency_path == ["requests", "urllib3"]
    assert m.applicability == Applicability.LIKELY_AFFECTED
