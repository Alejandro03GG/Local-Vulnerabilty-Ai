"""H10: likely_not_affected must not inflate LOW risk metrics."""

from __future__ import annotations

from vuln_ai.core.models import (
    Applicability,
    ComponentType,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    VersionType,
    VulnerabilityRecord,
)
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.risk.models import RiskLevel, RiskStatus


def _match(applicability: Applicability, *, severity: str | None = "HIGH") -> MatchResult:
    comp = DetectedComponent(
        name="pkg",
        version="1.0.0",
        version_type=VersionType.EXACT,
        source_file="requirements.txt",
        ecosystem=Ecosystem.PYPI,
        component_type=ComponentType.LIBRARY,
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2024-H10",
        cve_id="CVE-2024-H10",
        severity=severity,
        short_description="test",
    )
    return MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=0.9,
        applicability=applicability,
    )


def test_likely_not_affected_risk_not_low():
    engine = DeterministicRiskEngine()
    assessment = engine.assess(_match(Applicability.LIKELY_NOT_AFFECTED))
    assert assessment.status == RiskStatus.LIKELY_NOT_AFFECTED
    assert assessment.risk_level != RiskLevel.LOW
    assert assessment.risk_level == RiskLevel.UNKNOWN


def test_likely_affected_keeps_elevated_risk():
    engine = DeterministicRiskEngine()
    assessment = engine.assess(_match(Applicability.LIKELY_AFFECTED, severity="HIGH"))
    assert assessment.status == RiskStatus.LIKELY_AFFECTED
    assert assessment.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM)
