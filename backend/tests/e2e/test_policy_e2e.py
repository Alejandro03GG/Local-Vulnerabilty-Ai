"""End-to-End Scenarios K through U for Advanced Policy & Suppression Engine (Etapa 16).

Verifies:
- Scenario K: BLOCK finding -> exit 1 / violation.
- Scenario L: ACTIVE SUPPRESSION -> exempt from violation -> exit 0.
- Scenario M: EXPIRED SUPPRESSION -> not exempted -> VIOLATION -> exit 1.
- Scenario N: REQUIRE_REVIEW rule triggered on conflict/uncertainty -> requires_human_review flag set.
- Scenario O: ACCEPTED_RISK -> organizational risk acceptance -> exit 0.
- Scenario P: Multiple matching rules -> deterministic precedence (BLOCK > REVIEW > ACCEPT_RISK > ALLOW).
- Scenario Q: Multi-source conflict condition -> auditable trace.
- Scenario R: Direct vs Transitive dependency conditions.
- Scenario S: CISA KEV evidence + active suppression -> finding visible, policy allows.
- Scenario T: Empty project (0 findings) -> clean evaluation, exit 0.
- Scenario U: Large dataset benchmark (1000+ findings, 100+ rules, 100+ suppressions).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from vuln_ai.core.models import (
    Applicability,
    DependencyScope,
    DependencyType,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    VulnerabilityRecord,
)
from vuln_ai.policy.clock import FixedClock
from vuln_ai.policy.engine import PolicyEngine
from vuln_ai.policy.models import (
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyRule,
    PolicyStatus,
    PolicyThresholds,
    Suppression,
    SuppressionMatchCriteria,
)
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


def _make_match(
    package_name: str,
    version: str,
    cve_id: str,
    severity: str = "HIGH",
    risk_level: str | RiskLevel = "HIGH",
    dep_type: DependencyType = DependencyType.DIRECT,
    scope: DependencyScope = DependencyScope.RUNTIME,
    ecosystem: Ecosystem = Ecosystem.PYPI,
    has_kev: bool = False,
    conflict_detected: bool = False,
    conflict_type: str | None = None,
    requires_review: bool = False,
    cvss_score: float | None = 7.5,
) -> MatchResult:
    comp = DetectedComponent(
        name=package_name,
        version=version,
        ecosystem=ecosystem,
        source_file="requirements.txt",
        is_direct=(dep_type == DependencyType.DIRECT),
        dependency_type=dep_type,
        scope=scope,
    )
    vuln = VulnerabilityRecord(
        cve_id=cve_id,
        source_name="CISA KEV" if has_kev else "NVD",
        vendor_project=package_name,
        product=package_name,
        severity=severity,
        cvss_score=cvss_score,
    )

    r_level = (
        risk_level if isinstance(risk_level, RiskLevel) else RiskLevel(str(risk_level).lower())
    )
    risk = RiskAssessment(
        status=RiskStatus.REQUIRES_REVIEW if requires_review else RiskStatus.LIKELY_AFFECTED,
        risk_level=r_level,
        certainty=0.9,
        rationale="Deterministic risk assessment",
        recommended_action="Upgrade component",
        final_score=8.0 if r_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else 5.0,
        risk_factors=["Direct dependency", "High CVSS"],
        requires_human_review=requires_review,
        human_review_reason="Discrepancy" if requires_review else None,
    )
    conflicts_list = []
    if conflict_detected:
        from vuln_ai.matching.conflict import SourceConflict

        conflicts_list.append(
            SourceConflict(
                conflict_type=conflict_type or "SEVERITY",
                severity="HIGH",
                field="severity",
                sources=["NVD", "OSV"],
                resolution="REQUIRES_REVIEW",
            )
        )

    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED
        if not requires_review
        else Applicability.REQUIRES_REVIEW,
        evidence=["Version matches advisory range"],
        risk_assessment=risk,
        conflicts=conflicts_list,
    )
    return match


# Scenario K: BLOCK
def test_scenario_k_block_rule():
    match = _make_match("requests", "2.25.0", "CVE-2024-0001", risk_level=RiskLevel.HIGH)
    policy = Policy(
        name="k-block-policy",
        rules=[
            PolicyRule(
                id="block-high",
                when=PolicyCondition(risk_level="HIGH"),
                action=PolicyAction.BLOCK,
                reason="High risk findings are prohibited",
            )
        ],
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([match])

    assert result.has_violations is True
    assert result.violations_count == 1
    assert result.ci_exit_code == 1
    assert result.evaluations[0].status == PolicyStatus.VIOLATION
    assert result.evaluations[0].action == PolicyAction.BLOCK
    assert "block-high" in result.evaluations[0].matched_rules


# Scenario L: ACTIVE SUPPRESSION
def test_scenario_l_active_suppression():
    match = _make_match("requests", "2.25.0", "CVE-2024-0002", risk_level=RiskLevel.HIGH)
    policy = Policy(
        name="l-suppression-policy",
        rules=[
            PolicyRule(
                id="block-high",
                when=PolicyCondition(risk_level="HIGH"),
                action=PolicyAction.BLOCK,
            )
        ],
    )
    now = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
    clock = FixedClock(now)

    suppression = Suppression(
        id="SUP-ACTIVE-1",
        reason="False positive acknowledged by security architect",
        owner="architect@company.com",
        reference="SEC-2026-001",
        match_criteria=SuppressionMatchCriteria(vulnerability_id="CVE-2024-0002"),
        expires_at=now + timedelta(days=30),
        enabled=True,
    )

    engine = PolicyEngine(policy=policy, suppressions=[suppression], clock=clock)
    result = engine.evaluate([match])

    assert result.has_violations is False
    assert result.violations_count == 0
    assert result.suppressed_count == 1
    assert result.ci_exit_code == 0
    assert result.evaluations[0].status == PolicyStatus.SUPPRESSED
    assert result.evaluations[0].action == PolicyAction.SUPPRESS
    assert result.evaluations[0].matched_suppression_id == "SUP-ACTIVE-1"
    # Ground truth check: finding still exists in evaluations!
    assert result.total_findings == 1


# Scenario M: EXPIRED SUPPRESSION
def test_scenario_m_expired_suppression():
    match = _make_match("requests", "2.25.0", "CVE-2024-0003", risk_level=RiskLevel.HIGH)
    policy = Policy(
        name="m-expired-policy",
        rules=[
            PolicyRule(
                id="block-high",
                when=PolicyCondition(risk_level="HIGH"),
                action=PolicyAction.BLOCK,
            )
        ],
    )
    now = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
    clock = FixedClock(now)

    expired_suppression = Suppression(
        id="SUP-EXPIRED-1",
        reason="Old temporary exemption",
        owner="lead@company.com",
        reference="SEC-2026-002",
        match_criteria=SuppressionMatchCriteria(vulnerability_id="CVE-2024-0003"),
        expires_at=now - timedelta(days=1),  # Expired yesterday
        enabled=True,
    )

    engine = PolicyEngine(policy=policy, suppressions=[expired_suppression], clock=clock)
    result = engine.evaluate([match])

    assert result.has_violations is True
    assert result.violations_count == 1
    assert result.ci_exit_code == 1
    assert result.evaluations[0].status == PolicyStatus.VIOLATION
    assert result.evaluations[0].matched_suppression_id is None
    assert (
        result.evaluations[0].audit_trace["suppression_warning"]
        == "Suppression SUP-EXPIRED-1 is EXPIRED"
    )


# Scenario N: REQUIRE REVIEW
def test_scenario_n_require_review():
    match = _make_match(
        "urllib3", "1.26.4", "CVE-2024-0004", conflict_detected=True, requires_review=True
    )
    policy = Policy(
        name="n-review-policy",
        thresholds=PolicyThresholds(fail_on_review=True),
        rules=[
            PolicyRule(
                id="review-conflicts",
                when=PolicyCondition(conflict_detected=True),
                action=PolicyAction.REQUIRE_REVIEW,
                reason="Discrepancies between advisory sources require human sign-off",
            )
        ],
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([match])

    assert result.requires_review_count == 1
    assert result.evaluations[0].status == PolicyStatus.REQUIRES_REVIEW
    assert result.evaluations[0].requires_human_review is True
    # Since fail_on_review is True, ci_exit_code is 1
    assert result.ci_exit_code == 1


# Scenario O: ACCEPTED RISK
def test_scenario_o_accepted_risk():
    match = _make_match("jinja2", "2.11.2", "CVE-2024-0005", risk_level=RiskLevel.MEDIUM)
    policy = Policy(
        name="o-accepted-risk-policy",
        rules=[
            PolicyRule(
                id="accept-jinja-risk",
                when=PolicyCondition(package_name="jinja2"),
                action=PolicyAction.ACCEPT_RISK,
                reason="Legacy internal tooling where template sandbox is not exposed to user input",
            )
        ],
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([match])

    assert result.has_violations is False
    assert result.violations_count == 0
    assert result.accepted_risk_count == 1
    assert result.ci_exit_code == 0
    assert result.evaluations[0].status == PolicyStatus.ACCEPTED_RISK
    assert result.evaluations[0].action == PolicyAction.ACCEPT_RISK


# Scenario P: Multiple Rules Precedence
def test_scenario_p_multiple_rules_precedence():
    match = _make_match(
        "flask", "1.1.2", "CVE-2024-0006", severity="HIGH", risk_level=RiskLevel.HIGH
    )
    # Define competing rules matching the same finding: ALLOW, REQUIRE_REVIEW, BLOCK
    policy = Policy(
        name="p-precedence-policy",
        rules=[
            PolicyRule(
                id="allow-flask",
                when=PolicyCondition(package_name="flask"),
                action=PolicyAction.ALLOW,
                priority=100,
            ),
            PolicyRule(
                id="review-flask",
                when=PolicyCondition(severity="HIGH"),
                action=PolicyAction.REQUIRE_REVIEW,
                priority=50,
            ),
            PolicyRule(
                id="block-flask",
                when=PolicyCondition(risk_level="HIGH"),
                action=PolicyAction.BLOCK,
                priority=10,
            ),
        ],
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([match])

    # Precedence: BLOCK beats REQUIRE_REVIEW beats ALLOW
    assert result.has_violations is True
    assert result.evaluations[0].action == PolicyAction.BLOCK
    assert result.evaluations[0].status == PolicyStatus.VIOLATION
    assert len(result.evaluations[0].matched_rules) == 3


# Scenario Q: Multi-source Conflict Condition & Trace
def test_scenario_q_multisource_conflict():
    match = _make_match(
        "aiohttp",
        "3.8.1",
        "CVE-2024-0007",
        conflict_detected=True,
        conflict_type="SEVERITY",
    )
    policy = Policy(
        name="q-conflict-policy",
        rules=[
            PolicyRule(
                id="flag-conflicts",
                when=PolicyCondition(conflict_detected=True, conflict_type="SEVERITY"),
                action=PolicyAction.REQUIRE_REVIEW,
                reason="NVD and OSV report conflicting severity metrics",
            )
        ],
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([match])

    assert result.requires_review_count == 1
    eval_f = result.evaluations[0]
    assert eval_f.status == PolicyStatus.REQUIRES_REVIEW
    assert eval_f.audit_trace["conflict_detected"] is True
    assert eval_f.audit_trace["conflict_type"] == "SEVERITY"


# Scenario R: Direct vs Transitive Condition
def test_scenario_r_direct_vs_transitive():
    direct_match = _make_match(
        "direct-pkg", "1.0", "CVE-2024-0008", dep_type=DependencyType.DIRECT
    )
    transitive_match = _make_match(
        "trans-pkg", "1.0", "CVE-2024-0009", dep_type=DependencyType.TRANSITIVE
    )

    policy = Policy(
        name="r-dep-type-policy",
        rules=[
            PolicyRule(
                id="block-direct",
                when=PolicyCondition(dependency_type="DIRECT"),
                action=PolicyAction.BLOCK,
                reason="Direct dependencies with findings must be blocked immediately",
            ),
            PolicyRule(
                id="allow-transitive",
                when=PolicyCondition(dependency_type="TRANSITIVE"),
                action=PolicyAction.ALLOW,
                reason="Transitive dependencies allowed with monitoring",
            ),
        ],
        default_action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([direct_match, transitive_match])

    eval_direct = next(e for e in result.evaluations if e.component_name == "direct-pkg")
    eval_trans = next(e for e in result.evaluations if e.component_name == "trans-pkg")

    assert eval_direct.status == PolicyStatus.VIOLATION
    assert eval_direct.action == PolicyAction.BLOCK
    assert eval_trans.status == PolicyStatus.ALLOWED
    assert eval_trans.action == PolicyAction.ALLOW


# Scenario S: CISA KEV + Active Suppression
def test_scenario_s_cisa_kev_with_suppression():
    match = _make_match(
        "openssl",
        "1.1.1",
        "CVE-2024-0010",
        has_kev=True,
        severity="CRITICAL",
        risk_level=RiskLevel.CRITICAL,
    )
    policy = Policy(
        name="s-kev-policy",
        rules=[
            PolicyRule(
                id="block-kev",
                when=PolicyCondition(has_kev_evidence=True),
                action=PolicyAction.BLOCK,
                reason="Block CISA KEV active exploits",
            )
        ],
    )
    clock = FixedClock(datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC))
    suppression = Suppression(
        id="SUP-KEV-01",
        reason="Vendor hotfix scheduled for tonight; compensated by WAF virtual patch",
        owner="security-ops@company.com",
        reference="HOTFIX-999",
        match_criteria=SuppressionMatchCriteria(vulnerability_id="CVE-2024-0010"),
        expires_at=clock.now() + timedelta(days=2),
        enabled=True,
    )

    engine = PolicyEngine(policy=policy, suppressions=[suppression], clock=clock)
    result = engine.evaluate([match])

    # CI pipeline allows because of documented active suppression
    assert result.has_violations is False
    assert result.ci_exit_code == 0
    assert result.evaluations[0].status == PolicyStatus.SUPPRESSED
    # Technical finding remains completely visible and auditable!
    assert result.total_findings == 1
    assert result.evaluations[0].audit_trace["has_kev_evidence"] is True


# Scenario T: Empty Project (0 findings)
def test_scenario_t_empty_project():
    policy = Policy(
        name="t-empty-policy",
        thresholds=PolicyThresholds(fail_on=["HIGH", "CRITICAL"]),
        rules=[
            PolicyRule(
                id="block-all-high",
                when=PolicyCondition(severity="HIGH"),
                action=PolicyAction.BLOCK,
            )
        ],
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([])

    assert result.total_findings == 0
    assert result.has_violations is False
    assert result.violations_count == 0
    assert result.allowed_count == 0
    assert result.ci_exit_code == 0


# Scenario U: Large Dataset Benchmark (1000+ findings, 100+ rules, 100+ suppressions)
def test_scenario_u_large_dataset_benchmark():
    # 1. Generate 1000+ match results
    matches: list[MatchResult] = []
    for i in range(1200):
        matches.append(
            _make_match(
                package_name=f"pkg-{i % 100}",
                version=f"1.{i % 10}.0",
                cve_id=f"CVE-2024-{1000 + i}",
                severity="HIGH" if i % 2 == 0 else "MEDIUM",
                risk_level=RiskLevel.HIGH if i % 2 == 0 else RiskLevel.MEDIUM,
                dep_type=DependencyType.DIRECT if i % 3 == 0 else DependencyType.TRANSITIVE,
            )
        )

    # 2. Generate 100+ rules
    rules: list[PolicyRule] = []
    for r in range(120):
        rules.append(
            PolicyRule(
                id=f"rule-{r}",
                description=f"Rule targeting pkg-{r % 100}",
                when=PolicyCondition(package_name=f"pkg-{r % 100}"),
                action=PolicyAction.BLOCK if r % 4 == 0 else PolicyAction.ALLOW,
                priority=r,
            )
        )

    # 3. Generate 100+ suppressions
    suppressions: list[Suppression] = []
    now = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
    for s in range(150):
        suppressions.append(
            Suppression(
                id=f"SUP-{s}",
                reason=f"Exemption #{s}",
                owner=f"engineer-{s % 10}@company.com",
                reference=f"TICKET-{s}",
                match_criteria=SuppressionMatchCriteria(vulnerability_id=f"CVE-2024-{1000 + s}"),
                expires_at=now + timedelta(days=10) if s % 5 != 0 else now - timedelta(days=1),
                enabled=True,
            )
        )

    policy = Policy(
        name="benchmark-policy",
        rules=rules,
        default_action=PolicyAction.ALLOW,
    )

    clock = FixedClock(now)
    engine = PolicyEngine(policy=policy, suppressions=suppressions, clock=clock)

    start_t = time.perf_counter()
    result = engine.evaluate(matches)
    elapsed = time.perf_counter() - start_t

    assert result.total_findings == 1200
    assert len(result.evaluations) == 1200
    # Benchmark assertion: 1200 findings evaluated against 120 rules and 150 suppressions in under 2.0 seconds
    assert elapsed < 2.0, f"Evaluation took {elapsed:.3f}s, expected < 2.0s"
