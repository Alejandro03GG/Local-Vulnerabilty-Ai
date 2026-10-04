"""H13/H14: fail_on must respect applicability; violation messages must be precise."""

from __future__ import annotations

from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    VulnerabilityRecord,
)
from vuln_ai.policy.engine import PolicyEngine
from vuln_ai.policy.models import Policy, PolicyAction, PolicyStatus, PolicyThresholds
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


def _match(
    *,
    applicability: Applicability,
    severity: str = "HIGH",
    risk_level: RiskLevel = RiskLevel.HIGH,
    review: bool = False,
) -> MatchResult:
    # Mirror risk-engine behaviour for LNA: risk drops to LOW.
    if applicability == Applicability.LIKELY_NOT_AFFECTED:
        risk_level = RiskLevel.LOW
        risk_status = RiskStatus.LIKELY_NOT_AFFECTED
    elif applicability == Applicability.REQUIRES_REVIEW:
        risk_status = RiskStatus.REQUIRES_REVIEW
        review = True
    elif applicability == Applicability.LIKELY_AFFECTED:
        risk_status = RiskStatus.LIKELY_AFFECTED
    elif applicability == Applicability.DETECTED:
        risk_status = RiskStatus.DETECTED
    else:
        risk_status = RiskStatus.UNKNOWN

    return MatchResult(
        component=DetectedComponent(
            name="demo",
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        ),
        vulnerability=VulnerabilityRecord(
            canonical_id="CVE-2024-H13",
            cve_id="CVE-2024-H13",
            severity=severity,
            cvss_score=8.0,
            source_name="OSV",
        ),
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=applicability,
        risk_assessment=RiskAssessment(
            status=risk_status,
            risk_level=risk_level,
            certainty=0.9,
            rationale="test",
            recommended_action="test",
            requires_human_review=review,
        ),
    )


def _eval(match: MatchResult):
    engine = PolicyEngine(
        policy=Policy(
            name="fail-on-high",
            default_action=PolicyAction.ALLOW,
            thresholds=PolicyThresholds(fail_on=["HIGH", "CRITICAL"], fail_on_review=False),
        )
    )
    return engine.evaluate([match])


def test_h13_high_likely_affected_is_violation() -> None:
    res = _eval(_match(applicability=Applicability.LIKELY_AFFECTED, risk_level=RiskLevel.HIGH))
    assert res.violations_count == 1
    assert res.evaluations[0].status == PolicyStatus.VIOLATION
    assert res.ci_exit_code == 1


def test_h13_high_detected_is_violation() -> None:
    res = _eval(
        _match(
            applicability=Applicability.DETECTED,
            risk_level=RiskLevel.HIGH,
        )
    )
    assert res.violations_count == 1


def test_h13_high_requires_review_severity_can_violate() -> None:
    res = _eval(
        _match(
            applicability=Applicability.REQUIRES_REVIEW,
            risk_level=RiskLevel.MEDIUM,
            review=True,
        )
    )
    # Severity HIGH still applies for reviewable/affected-uncertain findings.
    assert res.violations_count == 1
    assert "advisory_severity" in (res.evaluations[0].reason or "")


def test_h13_high_likely_not_affected_is_allowed() -> None:
    """Advisory HIGH + LIKELY_NOT_AFFECTED must NOT violate fail_on HIGH."""
    res = _eval(_match(applicability=Applicability.LIKELY_NOT_AFFECTED))
    assert res.violations_count == 0
    assert res.evaluations[0].status == PolicyStatus.ALLOWED
    assert res.ci_exit_code == 0


def test_h13_unknown_with_high_severity_still_evaluated() -> None:
    res = _eval(
        _match(
            applicability=Applicability.UNKNOWN,
            risk_level=RiskLevel.MEDIUM,
        )
    )
    assert res.violations_count == 1


def test_h14_violation_message_distinguishes_risk_and_severity() -> None:
    res = _eval(_match(applicability=Applicability.LIKELY_AFFECTED, risk_level=RiskLevel.HIGH))
    reason = res.evaluations[0].reason or ""
    assert "trigger=" in reason
    assert "advisory_severity=" in reason
    assert "applicability=" in reason
    assert "fail_on=" in reason
