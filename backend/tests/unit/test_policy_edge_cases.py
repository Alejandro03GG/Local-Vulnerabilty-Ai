"""Targeted unit tests for Policy Engine edge cases and full branch coverage."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

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
from vuln_ai.policy.clock import FixedClock, SystemClock
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
)
from vuln_ai.policy.parser import (
    MAX_POLICY_FILE_SIZE_BYTES,
    load_policy_file,
    parse_policy_dict,
    parse_policy_yaml,
)
from vuln_ai.policy.service import PolicyService
from vuln_ai.policy.suppression import SuppressionMatcher
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


def _dummy_match(
    name: str = "demo-pkg",
    version: str = "1.2.3",
    cve: str = "CVE-2024-1111",
    severity: str = "HIGH",
    risk_level: str = "HIGH",
    cvss: float | None = 8.5,
    dep_type: DependencyType = DependencyType.DIRECT,
    scope: DependencyScope = DependencyScope.RUNTIME,
    ecosystem: Ecosystem = Ecosystem.PYPI,
    source: str = "NVD",
) -> MatchResult:
    comp = DetectedComponent(
        name=name,
        version=version,
        ecosystem=ecosystem,
        source_file="manifest.txt",
        is_direct=(dep_type == DependencyType.DIRECT),
        dependency_type=dep_type,
        scope=scope,
    )
    vuln = VulnerabilityRecord(
        cve_id=cve,
        source_name=source,
        vendor_project=name,
        product=name,
        severity=severity,
        cvss_score=cvss,
    )
    risk = RiskAssessment(
        status=RiskStatus.LIKELY_AFFECTED,
        risk_level=RiskLevel(risk_level.lower()),
        certainty=0.9,
        rationale="Edge case test",
        recommended_action="None",
        final_score=8.5,
    )
    return MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=risk,
    )


# --- Clock Tests ---
def test_clock_edge_cases():
    sys_clock = SystemClock()
    assert sys_clock.now().tzinfo is not None

    clock_none = FixedClock()
    assert clock_none.now().tzinfo is not None

    clock_str = FixedClock("2026-10-01T12:00:00")
    assert clock_str.now().year == 2026

    clock_str.set_time("2026-12-31T23:59:59")
    assert clock_str.now().month == 12

    clock_str.set_time(datetime(2027, 1, 1, 0, 0, 0))
    assert clock_str.now().year == 2027


# --- Parser Tests ---
def test_parser_edge_cases(tmp_path: Path):
    with pytest.raises(PolicyValidationError, match="mapping"):
        parse_policy_dict("not-a-dict")  # type: ignore

    with pytest.raises(PolicyValidationError, match="Content under 'policy'"):
        parse_policy_dict({"policy": "string-not-dict"})

    with pytest.raises(PolicyParseError, match="maximum allowed size"):
        large_yaml = "policy:\n  name: x\n" + ("# filler\n" * 150000)
        parse_policy_yaml(large_yaml)

    with pytest.raises(PolicyValidationError, match="root must be a dictionary"):
        parse_policy_yaml("- list item")

    # load_policy_file errors
    non_existent = tmp_path / "does_not_exist.yaml"
    with pytest.raises(PolicyParseError, match="not found"):
        load_policy_file(non_existent)

    dir_path = tmp_path / "some_dir"
    dir_path.mkdir()
    with pytest.raises(PolicyParseError, match="not a file"):
        load_policy_file(dir_path)

    # Large file on disk
    oversized = tmp_path / "oversized.yaml"
    oversized.write_bytes(b"a" * (MAX_POLICY_FILE_SIZE_BYTES + 10))
    with pytest.raises(PolicyParseError, match="exceeds limit"):
        load_policy_file(oversized)


# --- SuppressionMatcher Tests ---
def test_suppression_matcher_criteria():
    match = _dummy_match(name="auth-lib", version="2.0.0", ecosystem=Ecosystem.NPM)

    # 1. Project ID mismatch
    sup_proj = Suppression(
        project_id="proj-123",
        reason="Scoped",
        owner="sec",
        reference="REF",
        match_criteria=SuppressionMatchCriteria(package_name="auth-lib"),
    )
    assert not SuppressionMatcher.matches_finding(sup_proj, match, project_id="proj-999")
    assert SuppressionMatcher.matches_finding(sup_proj, match, project_id="proj-123")

    # 2. Finding ID match and mismatch
    sup_fid = Suppression(
        reason="Specific finding",
        owner="sec",
        reference="REF",
        match_criteria=SuppressionMatchCriteria(finding_id="npm:auth-lib:2.0.0:CVE-2024-1111"),
    )
    assert SuppressionMatcher.matches_finding(
        sup_fid, match, finding_id="npm:auth-lib:2.0.0:CVE-2024-1111"
    )
    assert not SuppressionMatcher.matches_finding(sup_fid, match, finding_id="other-finding")

    # 3. Ecosystem mismatch
    sup_eco = Suppression(
        reason="Ecosystem mismatch",
        owner="sec",
        reference="REF",
        match_criteria=SuppressionMatchCriteria(package_name="auth-lib", ecosystem="cargo"),
    )
    assert not SuppressionMatcher.matches_finding(sup_eco, match)

    # 4. Version mismatch
    sup_ver = Suppression(
        reason="Version mismatch",
        owner="sec",
        reference="REF",
        match_criteria=SuppressionMatchCriteria(package_name="auth-lib", package_version="1.0.0"),
    )
    assert not SuppressionMatcher.matches_finding(sup_ver, match)

    # 5. Empty criteria matches nothing
    sup_empty = Suppression(
        reason="No criteria",
        owner="sec",
        reference="REF",
        match_criteria=SuppressionMatchCriteria(),
    )
    assert not SuppressionMatcher.matches_finding(sup_empty, match)


# --- ConditionEvaluator & Engine Tests ---
def test_condition_evaluator_all_operators():
    match = _dummy_match(
        name="web-server",
        version="3.1.0",
        cvss=7.5,
        scope=DependencyScope.DEV,
        ecosystem=Ecosystem.CARGO,
        source="OSV",
    )

    # Scope condition
    assert ConditionEvaluator.evaluate(PolicyCondition(scope="DEV"), match)
    assert not ConditionEvaluator.evaluate(PolicyCondition(scope="RUNTIME"), match)

    # Ecosystem condition
    assert ConditionEvaluator.evaluate(PolicyCondition(ecosystem="cargo"), match)
    assert not ConditionEvaluator.evaluate(PolicyCondition(ecosystem="pypi"), match)

    # Package version condition
    assert ConditionEvaluator.evaluate(PolicyCondition(package_version="3.1.0"), match)
    assert not ConditionEvaluator.evaluate(PolicyCondition(package_version="4.0.0"), match)

    # Source condition
    assert ConditionEvaluator.evaluate(PolicyCondition(source="OSV"), match)
    assert not ConditionEvaluator.evaluate(PolicyCondition(source="NVD"), match)

    # CVSS comparators: GT, EQ, LT, LTE
    assert ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=7.0, cvss_comparator=CVSSComparator.GT), match
    )
    assert not ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=7.5, cvss_comparator=CVSSComparator.GT), match
    )

    assert ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=7.5, cvss_comparator=CVSSComparator.EQ), match
    )
    assert not ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=8.0, cvss_comparator=CVSSComparator.EQ), match
    )

    assert ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=8.0, cvss_comparator=CVSSComparator.LT), match
    )
    assert not ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=7.5, cvss_comparator=CVSSComparator.LT), match
    )

    assert ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=7.5, cvss_comparator=CVSSComparator.LTE), match
    )
    assert not ConditionEvaluator.evaluate(
        PolicyCondition(cvss_score=7.0, cvss_comparator=CVSSComparator.LTE), match
    )


def test_policy_engine_default_action():
    match = _dummy_match(name="unmatched-pkg", version="1.0.0")

    # Policy with no matching rules and default BLOCK
    policy = Policy(
        name="strict-default-block",
        rules=[
            PolicyRule(
                id="rule-for-other",
                when=PolicyCondition(package_name="other-pkg"),
                action=PolicyAction.ALLOW,
            )
        ],
        default_action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([match])

    assert result.has_violations is True
    assert result.violations_count == 1
    assert result.evaluations[0].action == PolicyAction.BLOCK
    assert result.evaluations[0].status == PolicyStatus.VIOLATION
    assert "policy default action" in result.evaluations[0].reason.lower()


# --- PolicyService Tests ---
@pytest.mark.asyncio
async def test_policy_service_resolve_file_in_project(tmp_path: Path):
    proj_dir = tmp_path / "project_with_policy"
    proj_dir.mkdir()
    policy_file = proj_dir / ".vuln-ai.yaml"
    policy_file.write_text("""
version: "1"
policy:
  name: "project-local-policy"
  rules:
    - id: "block-test"
      when:
        severity: "CRITICAL"
      action: "BLOCK"
""")
    from unittest.mock import MagicMock

    mock_session = MagicMock()
    service = PolicyService(mock_session)

    # 1. Resolve from project dir
    pol = await service.resolve_policy(project_path=proj_dir)
    assert pol.name == "project-local-policy"

    # 2. Resolve default when no policy file
    empty_dir = tmp_path / "empty_proj"
    empty_dir.mkdir()
    def_pol = await service.resolve_policy(project_path=empty_dir)
    assert def_pol.name == "default-baseline-policy"


def test_condition_evaluator_all_filter_mismatches():
    """Verify that every filter in PolicyCondition properly filters out non-matching findings."""
    match = _dummy_match(
        name="demo-pkg",
        version="1.0.0",
        cve="CVE-2024-1111",
        severity="HIGH",
        risk_level="HIGH",
        cvss=8.0,
        dep_type=DependencyType.DIRECT,
        scope=DependencyScope.RUNTIME,
        ecosystem=Ecosystem.PYPI,
        source="NVD",
    )

    # 1. Risk level mismatch
    cond = PolicyCondition(risk_level=["CRITICAL", "LOW"])
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 2. Applicability mismatch
    cond = PolicyCondition(applicability=["NOT_AFFECTED"])
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 3. Dependency type mismatch
    cond = PolicyCondition(dependency_type=["TRANSITIVE"])
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 4. Scope mismatch
    cond = PolicyCondition(scope=["DEV"])
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 5. Ecosystem mismatch
    cond = PolicyCondition(ecosystem=["NPM"])
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 6. Package version mismatch
    cond = PolicyCondition(package_version="2.0.0")
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 7. Vulnerability ID mismatch
    cond = PolicyCondition(vulnerability_id=["CVE-2099-0000"])
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 8. Source mismatch
    cond = PolicyCondition(source=["OSV"])
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 9. KEV evidence mismatch
    cond = PolicyCondition(has_kev_evidence=True)
    assert ConditionEvaluator.evaluate(cond, match) is False

    # 10. CVSS comparators
    cond_gt = PolicyCondition(cvss_score=8.5, cvss_comparator=CVSSComparator.GT)
    assert ConditionEvaluator.evaluate(cond_gt, match) is False

    cond_eq = PolicyCondition(cvss_score=9.0, cvss_comparator=CVSSComparator.EQ)
    assert ConditionEvaluator.evaluate(cond_eq, match) is False

    cond_lt = PolicyCondition(cvss_score=7.0, cvss_comparator=CVSSComparator.LT)
    assert ConditionEvaluator.evaluate(cond_lt, match) is False

    cond_lte = PolicyCondition(cvss_score=7.0, cvss_comparator=CVSSComparator.LTE)
    assert ConditionEvaluator.evaluate(cond_lte, match) is False

    # CVSS when match has no cvss score
    match_no_cvss = _dummy_match(cvss=None)
    assert ConditionEvaluator.evaluate(PolicyCondition(cvss_score=5.0), match_no_cvss) is False

    # 11. Human review mismatch
    match.risk_assessment.requires_human_review = False
    match.applicability = Applicability.LIKELY_AFFECTED
    cond_rev = PolicyCondition(requires_human_review=True)
    assert ConditionEvaluator.evaluate(cond_rev, match) is False

    # 12. Conflict detected mismatch
    cond_conf = PolicyCondition(conflict_detected=True)
    assert ConditionEvaluator.evaluate(cond_conf, match) is False

    # 13. Conflict type mismatch
    cond_ctype = PolicyCondition(conflict_type="SEVERITY_DISCREPANCY")
    assert ConditionEvaluator.evaluate(cond_ctype, match) is False


def test_threshold_fail_on_review():
    """Verify that fail_on_review triggers a CI violation if finding requires review."""
    match = _dummy_match(severity="MEDIUM", risk_level="MEDIUM")
    match.risk_assessment.requires_human_review = True

    policy = Policy(
        name="fail-on-review-policy",
        thresholds=PolicyThresholds(fail_on_review=True),
        rules=[],
        default_action=PolicyAction.ALLOW,
    )
    engine = PolicyEngine(policy=policy)
    result = engine.evaluate([match])

    assert result.requires_review_count == 1
    assert result.ci_exit_code == 1
    assert result.evaluations[0].status == PolicyStatus.REQUIRES_REVIEW
    assert "human review" in result.evaluations[0].reason.lower()


@pytest.mark.asyncio
async def test_policy_service_evaluate_scan_not_found():
    """Verify PolicyService.evaluate_scan raises PolicyError if scan not found."""
    from unittest.mock import AsyncMock, MagicMock

    from vuln_ai.policy.errors import PolicyError

    mock_session = MagicMock()
    service = PolicyService(mock_session)
    service.scan_repo.get_by_id = AsyncMock(return_value=None)

    with pytest.raises(PolicyError, match="Scan 'scan-999' not found"):
        await service.evaluate_scan("scan-999")


def test_load_policy_file_not_found(tmp_path: Path):
    """Verify load_policy_file raises PolicyParseError when file is missing."""
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(PolicyParseError, match="Policy file not found"):
        load_policy_file(missing)
