"""Unit tests for AI, Decision, and RiskAssessment repositories."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.models import AIAnalysis, DecisionResult
from vuln_ai.db.models import MatchDB, ProjectComponentDB, ProjectDB, ScanDB, VulnerabilityDB
from vuln_ai.db.repositories import (
    AIAnalysisRepository,
    DecisionRepository,
    RiskAssessmentRepository,
)
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


@pytest.fixture
async def sample_db_match(db_session: AsyncSession) -> MatchDB:
    """Create persistent project, scan, component, vuln, and match rows for foreign keys."""
    proj = ProjectDB(name="TestProj", path="/tmp/test", description="")
    db_session.add(proj)
    await db_session.flush()

    scan = ScanDB(project_id=proj.id)
    db_session.add(scan)

    comp = ProjectComponentDB(
        project_id=proj.id,
        name="requests",
        version="2.31.0",
        ecosystem="pypi",
        source_file="requirements.txt",
    )
    db_session.add(comp)

    vuln = VulnerabilityDB(
        cve_id="CVE-2024-4000",
        source_id="dummy-src",
        vendor_project="psf",
        product="requests",
        vulnerability_name="SSRF",
    )
    db_session.add(vuln)
    await db_session.flush()

    match = MatchDB(
        scan_id=scan.id,
        component_id=comp.id,
        vulnerability_id=vuln.id,
        match_type="exact_name",
        match_confidence=1.0,
    )
    db_session.add(match)
    await db_session.flush()

    return match


@pytest.mark.asyncio
async def test_ai_analysis_repository_lifecycle(
    db_session: AsyncSession, sample_db_match: MatchDB
):
    """Save, retrieve, and convert AIAnalysis."""
    repo = AIAnalysisRepository(db_session)
    domain_analysis = AIAnalysis(
        provider="ollama",
        model="llama3.2",
        explanation="Test explanation",
        evidence=["Evidence 1", "Evidence 2"],
        contextual_findings=["Finding 1"],
        requires_human_review=True,
        analysis_duration_seconds=1.5,
        tokens_used=120,
    )

    # 1. Save
    db_obj = await repo.save_analysis(sample_db_match.id, domain_analysis)
    assert db_obj.id is not None
    assert db_obj.match_id == sample_db_match.id

    # 2. Retrieve
    retrieved = await repo.get_by_match_id(sample_db_match.id)
    assert retrieved is not None
    assert retrieved.explanation == "Test explanation"
    assert retrieved.tokens_used == 120

    # 3. Convert to domain
    converted = repo.to_domain(retrieved)
    assert converted.provider == "ollama"
    assert converted.evidence == ["Evidence 1", "Evidence 2"]
    assert converted.requires_human_review is True

    # 4. Update existing
    domain_analysis.explanation = "Updated explanation"
    updated_obj = await repo.save_analysis(sample_db_match.id, domain_analysis)
    assert updated_obj.id == db_obj.id
    assert updated_obj.explanation == "Updated explanation"


@pytest.mark.asyncio
async def test_decision_repository_lifecycle(db_session: AsyncSession, sample_db_match: MatchDB):
    """Save, retrieve, and convert DecisionResult."""
    repo = DecisionRepository(db_session)
    domain_decision = DecisionResult(
        provider="ollama_systemone",
        model="tev1:4b",
        responses={"applicability": "yes", "exposure": "direct"},
        decision_probabilities={"applicability": {"yes": 0.85, "no": 0.15}},
        applicability_probability=0.85,
        urgency_score=7.5,
        latency_seconds=0.35,
        raw_response={"debug": "sample"},
    )

    # 1. Save
    db_obj = await repo.save_decision(sample_db_match.id, domain_decision)
    assert db_obj.id is not None
    assert db_obj.applicability_probability == 0.85

    # 2. Retrieve
    retrieved = await repo.get_by_match_id(sample_db_match.id)
    assert retrieved is not None
    assert retrieved.urgency_score == 7.5

    # 3. Convert to domain
    converted = repo.to_domain(retrieved)
    assert converted.applicability_probability == 0.85
    assert converted.responses["exposure"] == "direct"
    assert converted.raw_response == {"debug": "sample"}

    # 4. Update existing
    domain_decision.urgency_score = 9.0
    updated_obj = await repo.save_decision(sample_db_match.id, domain_decision)
    assert updated_obj.id == db_obj.id
    assert updated_obj.urgency_score == 9.0


@pytest.mark.asyncio
async def test_risk_assessment_repository_lifecycle(
    db_session: AsyncSession, sample_db_match: MatchDB
):
    """Save, retrieve, and convert RiskAssessment."""
    repo = RiskAssessmentRepository(db_session)
    domain_assessment = RiskAssessment(
        status=RiskStatus.REQUIRES_REVIEW,
        risk_level=RiskLevel.HIGH,
        certainty=0.65,
        rationale="Needs investigation",
        recommended_action="Upgrade to patched version",
        requires_human_review=True,
        rule_ids=["MATCH_COMPONENT_ONLY", "NO_VERSION_EVIDENCE"],
    )

    # 1. Save
    db_obj = await repo.save_assessment(sample_db_match.id, domain_assessment)
    assert db_obj.id is not None
    assert db_obj.status == "requires_review"

    # 2. Retrieve
    retrieved = await repo.get_by_match_id(sample_db_match.id)
    assert retrieved is not None
    assert retrieved.risk_level == "high"

    # 3. Convert to domain
    converted = repo.to_domain(retrieved)
    assert converted.status == RiskStatus.REQUIRES_REVIEW
    assert converted.risk_level == RiskLevel.HIGH
    assert converted.rule_ids == ["MATCH_COMPONENT_ONLY", "NO_VERSION_EVIDENCE"]

    # 4. Update existing
    domain_assessment.certainty = 0.90
    updated_obj = await repo.save_assessment(sample_db_match.id, domain_assessment)
    assert updated_obj.id == db_obj.id
    assert updated_obj.certainty == 0.90
