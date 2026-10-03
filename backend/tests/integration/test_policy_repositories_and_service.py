"""Integration tests for PolicyRepository, SuppressionRepository, and PolicyService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    VulnerabilityRecord,
)
from vuln_ai.db.repositories import (
    ComponentRepository,
    MatchRepository,
    PolicyRepository,
    ProjectRepository,
    ScanRepository,
    SourceRepository,
    SuppressionRepository,
    VulnerabilityRepository,
)
from vuln_ai.policy.clock import FixedClock
from vuln_ai.policy.models import (
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyRule,
    PolicyThresholds,
    Suppression,
    SuppressionMatchCriteria,
)
from vuln_ai.policy.service import PolicyService


@pytest.mark.asyncio
async def test_policy_repository_crud(db_session: AsyncSession):
    repo = PolicyRepository(db_session)

    policy = Policy(
        name="sec-ops-policy",
        description="Security operations policy",
        thresholds=PolicyThresholds(fail_on=["CRITICAL"]),
        rules=[
            PolicyRule(
                id="block-crit",
                description="Block critical",
                when=PolicyCondition(severity="CRITICAL"),
                action=PolicyAction.BLOCK,
            )
        ],
    )

    # 1. Create
    created = await repo.create(policy)
    assert created.id == policy.id
    assert created.name == "sec-ops-policy"

    # 2. Get by ID
    fetched = await repo.get_by_id(policy.id)
    assert fetched is not None
    assert fetched.name == "sec-ops-policy"
    domain_pol = repo.to_domain(fetched)
    assert len(domain_pol.rules) == 1
    assert domain_pol.rules[0].id == "block-crit"

    # 3. List
    all_pols = await repo.list_all()
    assert any(p.id == policy.id for p in all_pols)

    # 4. Update
    policy.description = "Updated description"
    policy.rules.append(
        PolicyRule(
            id="review-conflicts",
            when=PolicyCondition(conflict_detected=True),
            action=PolicyAction.REQUIRE_REVIEW,
        )
    )
    updated = await repo.update(policy.id, policy)
    assert updated is not None
    refetched = await repo.get_by_id(policy.id)
    assert refetched is not None
    domain_updated = repo.to_domain(refetched)
    assert len(domain_updated.rules) == 2

    # 5. Delete
    deleted = await repo.delete(policy.id)
    assert deleted is True
    assert await repo.get_by_id(policy.id) is None


@pytest.mark.asyncio
async def test_suppression_repository_crud(db_session: AsyncSession):
    repo = SuppressionRepository(db_session)

    sup = Suppression(
        reason="Vendor hotfix pending deployment",
        owner="security-team@corp.com",
        reference="SEC-4040",
        expires_at=datetime.now(UTC) + timedelta(days=14),
        match_criteria=SuppressionMatchCriteria(
            vulnerability_id="CVE-2024-9999",
            package_name="django",
            ecosystem="pypi",
        ),
    )

    created = await repo.create(sup)
    assert created.id == sup.id

    fetched = await repo.get_by_id(sup.id)
    assert fetched is not None
    domain_sup = repo.to_domain(fetched)
    assert domain_sup.owner == "security-team@corp.com"
    assert domain_sup.match_criteria.vulnerability_id == "CVE-2024-9999"

    all_sups = await repo.list_all()
    assert any(s.id == sup.id for s in all_sups)

    # Update
    updated = await repo.update(sup.id, {"reason": "Updated justification"})
    assert updated is not None
    assert updated.reason == "Updated justification"

    # Delete
    deleted = await repo.delete(sup.id)
    assert deleted is True
    assert await repo.get_by_id(sup.id) is None


@pytest.mark.asyncio
async def test_policy_service_evaluate_scan(db_session: AsyncSession):
    clock = FixedClock("2026-10-03T12:00:00Z")
    service = PolicyService(db_session, clock=clock)

    # 1. Setup project and scan in DB
    proj_repo = ProjectRepository(db_session)
    scan_repo = ScanRepository(db_session)
    comp_repo = ComponentRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    match_repo = MatchRepository(db_session)
    source_repo = SourceRepository(db_session)

    source, _ = await source_repo.get_or_create(name="NVD", source_type="nvd")
    project = await proj_repo.create(name="pol-test-proj", path="/tmp/pol-test")
    scan = await scan_repo.create(project.id)
    await scan_repo.complete(scan.id)
    components = await comp_repo.save_components(
        project_id=project.id,
        components=[
            DetectedComponent(
                name="log4j",
                version="2.14.0",
                ecosystem=Ecosystem.MAVEN,
                source_file="pom.xml",
            )
        ],
    )
    component = components[0]

    await vuln_repo.upsert_vulnerabilities(
        source.id,
        [
            VulnerabilityRecord(
                canonical_id="CVE-2021-44228",
                source_name="NVD",
                severity="CRITICAL",
                cvss_score=10.0,
            )
        ],
    )
    db_vuln = await vuln_repo.get_by_cve("CVE-2021-44228")
    assert db_vuln is not None

    domain_comp = DetectedComponent(
        name="log4j",
        version="2.14.0",
        ecosystem=Ecosystem.MAVEN,
        source_file="pom.xml",
    )
    domain_match = MatchResult(
        component=domain_comp,
        vulnerability=VulnerabilityRecord(
            canonical_id="CVE-2021-44228",
            source_name="NVD",
            severity="CRITICAL",
            cvss_score=10.0,
        ),
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
    )
    await match_repo.save_matches(
        scan_id=scan.id,
        matches=[domain_match],
        component_id_map={domain_comp.normalized_name(): component.id},
        vulnerability_id_map={"CVE-2021-44228": db_vuln[0].id},
    )

    # 2. Evaluate with default policy -> triggers BLOCK (CRITICAL) -> exit code 1
    eval_res = await service.evaluate_scan(scan.id)
    assert eval_res.total_findings == 1
    assert eval_res.violations_count == 1
    assert eval_res.ci_exit_code == 1

    # Check persistence of evaluation
    saved_eval = await service.policy_repo.get_evaluation_by_scan_id(scan.id)
    assert saved_eval is not None
    assert saved_eval.violations_count == 1

    # 3. Add active suppression for CVE-2021-44228
    sup_repo = SuppressionRepository(db_session)
    await sup_repo.create(
        Suppression(
            project_id=project.id,
            reason="WAF mitigation active in production",
            owner="secops@corp.com",
            reference="SEC-LOG4J",
            expires_at=datetime(2026, 12, 1, tzinfo=UTC),
            match_criteria=SuppressionMatchCriteria(vulnerability_id="CVE-2021-44228"),
        )
    )

    # 4. Re-evaluate scan -> finding is now SUPPRESSED -> exit code 0
    re_eval = await service.evaluate_scan(scan.id)
    assert re_eval.total_findings == 1
    assert re_eval.violations_count == 0
    assert re_eval.suppressed_count == 1
    assert re_eval.ci_exit_code == 0
