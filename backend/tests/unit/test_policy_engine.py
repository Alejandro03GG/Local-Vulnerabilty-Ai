"""Unit tests for Policy Engine, Parser, Conditions, and Suppressions (Etapa 16)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    VulnerabilityRecord,
)
from vuln_ai.matching.conflict import SourceConflict
from vuln_ai.policy.clock import FixedClock
from vuln_ai.policy.engine import ConditionEvaluator, PolicyEngine
from vuln_ai.policy.errors import PolicyParseError, PolicyValidationError
from vuln_ai.policy.models import (
    CVSSComparator,
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyRule,
    PolicyStatus,
    PolicyThresholds,
    Suppression,
    SuppressionMatchCriteria,
    SuppressionStatus,
)
from vuln_ai.policy.parser import (
    load_policy_file,
    parse_policy_yaml,
)
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


def _make_match(
    name: str = "urllib3",
    version: str = "1.26.5",
    ecosystem: Ecosystem = Ecosystem.PYPI,
    canonical_id: str = "CVE-2021-33503",
    severity: str = "HIGH",
    cvss: float = 7.5,
    risk_level: RiskLevel = RiskLevel.HIGH,
    is_direct: bool = True,
    has_kev: bool = False,
    review: bool = False,
    conflicts: list[SourceConflict] | None = None,
) -> MatchResult:
    comp = DetectedComponent(
        name=name,
        version=version,
        ecosystem=ecosystem,
        source_file="requirements.txt",
        is_direct=is_direct,
    )
    vuln = VulnerabilityRecord(
        canonical_id=canonical_id,
        severity=severity,
        cvss_score=cvss,
        source_name="CISA KEV" if has_kev else "NVD",
    )
    risk = RiskAssessment(
        status=RiskStatus.REQUIRES_REVIEW if review else RiskStatus.LIKELY_AFFECTED,
        risk_level=risk_level,
        certainty=0.9,
        rationale="Evaluation rationale",
        recommended_action="Remediate component",
        requires_human_review=review,
    )
    return MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.REQUIRES_REVIEW if review else Applicability.LIKELY_AFFECTED,
        risk_assessment=risk,
        conflicts=conflicts or [],
    )


def test_policy_yaml_parser_valid_minimal():
    yaml_text = """
version: "1"
policy:
  name: corporate-policy
  thresholds:
    fail_on:
      - CRITICAL
      - HIGH
  rules:
    - id: block-kev
      description: Block known exploited vulnerabilities
      when:
        has_kev_evidence: true
      action: BLOCK
"""
    pol = parse_policy_yaml(yaml_text)
    assert pol.name == "corporate-policy"
    assert pol.thresholds.fail_on == ["CRITICAL", "HIGH"]
    assert len(pol.rules) == 1
    assert pol.rules[0].id == "block-kev"
    assert pol.rules[0].when.has_kev_evidence is True
    assert pol.rules[0].action == PolicyAction.BLOCK


def test_policy_yaml_parser_errors():
    # Empty
    with pytest.raises(PolicyParseError, match="Policy document is empty"):
        parse_policy_yaml("")

    # Malformed YAML
    with pytest.raises(PolicyParseError, match="Malformed YAML syntax"):
        parse_policy_yaml("name: [unclosed list")

    # Extra fields forbidden
    with pytest.raises(PolicyValidationError, match="Extra inputs are not permitted"):
        parse_policy_yaml("""
name: test
unknown_field: true
""")

    # Duplicate rule ID
    with pytest.raises(PolicyValidationError, match="Duplicate rule ID detected"):
        parse_policy_yaml("""
name: test
rules:
  - id: rule-1
    action: BLOCK
  - id: rule-1
    action: ALLOW
""")

    # Prohibited status 'VULNERABLE'
    with pytest.raises(PolicyValidationError, match="Status 'VULNERABLE' is prohibited"):
        parse_policy_yaml("""
name: test
rules:
  - id: rule-vuln
    when:
      applicability: VULNERABLE
    action: BLOCK
""")


def test_load_policy_file(tmp_path: Path):
    policy_file = tmp_path / ".vuln-ai.yaml"
    policy_file.write_text("name: local-file-policy\nversion: '1'", encoding="utf-8")
    pol = load_policy_file(policy_file)
    assert pol.name == "local-file-policy"

    # Nonexistent
    with pytest.raises(PolicyParseError, match="Policy file not found"):
        load_policy_file(tmp_path / "nonexistent.yaml")

    # Directory
    with pytest.raises(PolicyParseError, match="is not a file"):
        load_policy_file(tmp_path)


def test_condition_evaluator_all_attributes():
    match = _make_match(
        name="requests",
        version="2.25.0",
        ecosystem=Ecosystem.PYPI,
        canonical_id="CVE-2023-32681",
        severity="HIGH",
        cvss=7.5,
        risk_level=RiskLevel.HIGH,
        is_direct=True,
        has_kev=True,
        review=False,
    )

    # 1. Matching conditions
    c1 = PolicyCondition(
        severity="HIGH",
        risk_level=["HIGH", "CRITICAL"],
        applicability="LIKELY_AFFECTED",
        dependency_type="DIRECT",
        ecosystem="pypi",
        package_name="requests",
        package_version="2.25.0",
        vulnerability_id="CVE-2023-32681",
        has_kev_evidence=True,
        cvss_score=7.0,
        cvss_comparator=CVSSComparator.GTE,
        requires_human_review=False,
        conflict_detected=False,
    )
    assert ConditionEvaluator.evaluate(c1, match) is True

    # 2. CVSS comparator variations
    assert (
        ConditionEvaluator.evaluate(
            PolicyCondition(cvss_score=7.5, cvss_comparator=CVSSComparator.EQ), match
        )
        is True
    )
    assert (
        ConditionEvaluator.evaluate(
            PolicyCondition(cvss_score=7.4, cvss_comparator=CVSSComparator.GT), match
        )
        is True
    )
    assert (
        ConditionEvaluator.evaluate(
            PolicyCondition(cvss_score=7.5, cvss_comparator=CVSSComparator.LTE), match
        )
        is True
    )
    assert (
        ConditionEvaluator.evaluate(
            PolicyCondition(cvss_score=8.0, cvss_comparator=CVSSComparator.LT), match
        )
        is True
    )
    assert (
        ConditionEvaluator.evaluate(
            PolicyCondition(cvss_score=8.0, cvss_comparator=CVSSComparator.GTE), match
        )
        is False
    )

    # 3. Mismatches
    assert ConditionEvaluator.evaluate(PolicyCondition(severity="LOW"), match) is False
    assert ConditionEvaluator.evaluate(PolicyCondition(package_name="other-pkg"), match) is False
    assert (
        ConditionEvaluator.evaluate(PolicyCondition(dependency_type="TRANSITIVE"), match) is False
    )
    assert ConditionEvaluator.evaluate(PolicyCondition(has_kev_evidence=False), match) is False
    assert ConditionEvaluator.evaluate(PolicyCondition(conflict_detected=True), match) is False


def test_suppression_clock_expiration_lifecycle():
    now_ref = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)
    clock = FixedClock(now_ref)

    # 1. Active suppression (expires tomorrow)
    s_active = Suppression(
        reason="Vendor acknowledged false positive",
        owner="sec-team",
        reference="SEC-101",
        expires_at=now_ref + timedelta(days=1),
        match_criteria=SuppressionMatchCriteria(package_name="flask"),
    )
    assert s_active.status(clock) == SuppressionStatus.ACTIVE
    assert s_active.is_active(clock) is True

    # 2. Expired suppression (expired 1 hour ago)
    s_expired = Suppression(
        reason="Temporary exception",
        owner="dev-team",
        reference="DEV-202",
        expires_at=now_ref - timedelta(hours=1),
        match_criteria=SuppressionMatchCriteria(package_name="flask"),
    )
    assert s_expired.status(clock) == SuppressionStatus.EXPIRED
    assert s_expired.is_active(clock) is False

    # 3. Disabled suppression
    s_disabled = Suppression(
        reason="Revoked exception",
        owner="audit-team",
        reference="REV-303",
        enabled=False,
        match_criteria=SuppressionMatchCriteria(package_name="flask"),
    )
    assert s_disabled.status(clock) == SuppressionStatus.DISABLED
    assert s_disabled.is_active(clock) is False

    # 4. Advance clock past active expiry
    clock.set_time(now_ref + timedelta(days=2))
    assert s_active.status(clock) == SuppressionStatus.EXPIRED
    assert s_active.is_active(clock) is False


def test_policy_engine_precedence_active_vs_expired_suppression():
    clock = FixedClock("2026-10-03T12:00:00Z")
    match = _make_match(
        name="jinja2", canonical_id="CVE-2024-34064", severity="HIGH", risk_level=RiskLevel.HIGH
    )

    policy = Policy(
        name="strict-policy",
        thresholds=PolicyThresholds(fail_on=["HIGH"]),
        rules=[
            PolicyRule(
                id="block-all-high",
                when=PolicyCondition(risk_level="HIGH"),
                action=PolicyAction.BLOCK,
            )
        ],
    )

    # 1. With Active Suppression -> Exempted, SUPPRESSED, exit code 0
    active_sup = Suppression(
        reason="Jinja template sandbox mitigates finding",
        owner="security-analyst",
        reference="SEC-500",
        expires_at=datetime(2026, 11, 1, tzinfo=UTC),
        match_criteria=SuppressionMatchCriteria(package_name="jinja2"),
    )
    engine_active = PolicyEngine(policy=policy, suppressions=[active_sup], clock=clock)
    res_active = engine_active.evaluate([match])

    assert res_active.total_findings == 1
    assert res_active.suppressed_count == 1
    assert res_active.violations_count == 0
    assert res_active.ci_exit_code == 0
    assert res_active.evaluations[0].status == PolicyStatus.SUPPRESSED
    assert res_active.evaluations[0].matched_suppression_id == active_sup.id

    # 2. With Expired Suppression -> NOT exempted, triggers BLOCK, VIOLATION, exit code 1
    expired_sup = Suppression(
        reason="Old temporary exemption",
        owner="security-analyst",
        reference="SEC-500",
        expires_at=datetime(2026, 9, 1, tzinfo=UTC),  # Expired last month
        match_criteria=SuppressionMatchCriteria(package_name="jinja2"),
    )
    engine_expired = PolicyEngine(policy=policy, suppressions=[expired_sup], clock=clock)
    res_expired = engine_expired.evaluate([match])

    assert res_expired.total_findings == 1
    assert res_expired.suppressed_count == 0
    assert res_expired.violations_count == 1
    assert res_expired.ci_exit_code == 1
    assert res_expired.evaluations[0].status == PolicyStatus.VIOLATION
    assert "expired_suppression_warning" in res_expired.evaluations[0].audit_trace


def test_policy_engine_rule_action_precedence():
    """Verify BLOCK > REQUIRE_REVIEW > ACCEPT_RISK > ALLOW when multiple rules match."""
    match = _make_match(name="fastapi", risk_level=RiskLevel.HIGH)

    # Both a BLOCK and an ALLOW rule match
    policy = Policy(
        name="conflict-rules-policy",
        rules=[
            PolicyRule(
                id="rule-allow",
                when=PolicyCondition(package_name="fastapi"),
                action=PolicyAction.ALLOW,
                priority=10,
            ),
            PolicyRule(
                id="rule-block",
                when=PolicyCondition(package_name="fastapi"),
                action=PolicyAction.BLOCK,
                priority=20,
            ),
        ],
    )
    engine = PolicyEngine(policy=policy)
    res = engine.evaluate([match])

    # BLOCK wins over ALLOW
    assert res.evaluations[0].status == PolicyStatus.VIOLATION
    assert res.evaluations[0].action == PolicyAction.BLOCK


def test_policy_engine_threshold_and_default_fallback():
    match = _make_match(name="safe-lib", severity="LOW", risk_level=RiskLevel.LOW)

    # 1. Default ALLOW
    pol_allow = Policy(name="default-allow", default_action=PolicyAction.ALLOW)
    res_allow = PolicyEngine(policy=pol_allow).evaluate([match])
    assert res_allow.evaluations[0].status == PolicyStatus.ALLOWED
    assert res_allow.ci_exit_code == 0

    # 2. Default BLOCK
    pol_block = Policy(name="default-block", default_action=PolicyAction.BLOCK)
    res_block = PolicyEngine(policy=pol_block).evaluate([match])
    assert res_block.evaluations[0].status == PolicyStatus.VIOLATION
    assert res_block.ci_exit_code == 1
