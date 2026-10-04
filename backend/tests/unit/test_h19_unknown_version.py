"""H19: missing exact version must yield UNKNOWN — never invent versions."""

from __future__ import annotations

from vuln_ai.core.models import (
    Applicability,
    ComponentType,
    DetectedComponent,
    Ecosystem,
    VersionType,
)
from vuln_ai.matching.version import evaluate_component_ranges


def test_missing_version_is_unknown_not_affected():
    comp = DetectedComponent(
        name="left-pad",
        version=None,
        version_type=VersionType.UNKNOWN,
        source_file="package.json",
        ecosystem=Ecosystem.NPM,
        component_type=ComponentType.LIBRARY,
    )
    status, _evidences = evaluate_component_ranges(
        component=comp,
        ranges=[],
        vulnerability_id="GHSA-xxxx-yyyy-zzzz",
    )
    assert status == Applicability.UNKNOWN
    assert status != Applicability.LIKELY_AFFECTED
    assert status != Applicability.LIKELY_NOT_AFFECTED


def test_empty_version_string_is_unknown():
    comp = DetectedComponent(
        name="requests",
        version="",
        version_type=VersionType.UNKNOWN,
        source_file="requirements.txt",
        ecosystem=Ecosystem.PYPI,
        component_type=ComponentType.LIBRARY,
    )
    status, _ = evaluate_component_ranges(
        component=comp,
        ranges=[],
        vulnerability_id="CVE-2024-0001",
    )
    assert status == Applicability.UNKNOWN
