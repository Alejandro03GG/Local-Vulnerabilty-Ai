"""Integration tests for the full Phase 2 AI and Risk Engine pipeline.

Tests the complete flow:
    Scanner
       ↓
    CISA KEV
       ↓
    Deterministic Matcher
       ↓
    AI Contextual Analysis
       ↓
    SystemOne Probabilistic Decision
       ↓
    Deterministic Risk Engine
       ↓
    Persistence (Database)
       ↓
    Rich ScanResultSummary
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.models import (
    AIAnalysis,
    AnalysisContext,
    DecisionQuestion,
    DecisionResult,
)
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import ScanStatus
from vuln_ai.db.models import (
    AIAnalysisDB,
    DecisionResultDB,
    RiskAssessmentDB,
)
from vuln_ai.db.repositories import (
    SourceRepository,
    VulnerabilityRepository,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.risk.models import RiskLevel, RiskStatus
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.cisa_kev import CISAKEVSource
from vuln_ai.sources.registry import SourceRegistry


class MockAIProvider:
    """Mock LLM provider returning controlled AIAnalysis."""

    @property
    def name(self) -> str:
        return "MockAIProvider"

    @property
    def provider_type(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        return True

    async def analyze(self, context: AnalysisContext) -> AIAnalysis:
        return AIAnalysis(
            provider=self.name,
            model="llama3.2-mock",
            explanation=f"Analysis for {context.component_name} and {context.cve_id}",
            evidence=[f"Matched component {context.component_name}"],
            contextual_findings=["Potential SSRF exposure if external requests permitted"],
            requires_human_review=False,
            analysis_duration_seconds=0.25,
            tokens_used=150,
        )


class MockDecisionProvider:
    """Mock SystemOne provider returning controlled DecisionResult."""

    @property
    def name(self) -> str:
        return "MockDecisionProvider"

    @property
    def provider_type(self) -> str:
        return "ollama_systemone"

    async def is_available(self) -> bool:
        return True

    async def decide(
        self, context: AnalysisContext, questions: list[DecisionQuestion]
    ) -> DecisionResult:
        return DecisionResult(
            provider=self.name,
            model="tev1:4b-mock",
            responses={"applicability": "yes", "exposure": "direct", "urgency": 8.5},
            decision_probabilities={"applicability": {"yes": 0.85, "no": 0.15}},
            applicability_probability=0.85,
            urgency_score=8.5,
            latency_seconds=0.15,
        )


@pytest.mark.asyncio
async def test_full_pipeline_with_ai_and_risk_engine(
    db_session: AsyncSession,
    tmp_path: Path,
    sample_kev_data: dict,
):
    """Complete scan with active AI and Decision providers enriched by Risk Engine."""
    # 1. Setup sample project with vulnerable component
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

    # 2. Populate CISA KEV catalog in database
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    db_src, _ = await source_repo.get_or_create(
        name="CISA KEV",
        source_type="kev",
        url="https://cisagov.github.io/kev-data/jsonFiles/knownExploitedVulnerabilities.json",
    )
    kev_source = CISAKEVSource()
    records = kev_source._parse(sample_kev_data)
    await vuln_repo.upsert_vulnerabilities(db_src.id, records)
    await db_session.commit()

    # 3. Setup registries
    scanner_reg = ScannerRegistry()
    scanner_reg.register(PythonScanner())

    source_reg = SourceRegistry()
    source_reg.register(kev_source)

    ai_reg = AIRegistry()
    ai_reg.register_ai_provider(MockAIProvider())
    ai_reg.register_decision_provider(MockDecisionProvider())

    # 4. Initialize engine
    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
        ai_registry=ai_reg,
        risk_engine=DeterministicRiskEngine(),
        ai_enabled=True,
        decision_enabled=True,
    )

    # 5. Execute scan
    result = await engine.scan(tmp_path)

    # 6. Verify scan summary
    assert result.scan_status == ScanStatus.COMPLETED
    assert result.components_found == 1
    assert result.matches_found >= 1

    match = result.matches[0]
    assert match.component.name == "requests"
    assert match.vulnerability.cve_id == "CVE-2024-4000"

    # Verify AI enrichment
    assert match.ai_analysis is not None
    assert match.ai_analysis.provider == "MockAIProvider"
    assert "requests" in match.ai_analysis.explanation

    # Verify Decision enrichment
    assert match.decision is not None
    assert match.decision.applicability_probability == 0.85
    assert match.decision.urgency_score == 8.5

    # Verify Risk Assessment
    assert match.risk_assessment is not None
    assert match.risk_assessment.status == RiskStatus.LIKELY_AFFECTED
    assert match.risk_assessment.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert "AI_APPLICABILITY_HIGH" in match.risk_assessment.rule_ids
    assert "EXPOSURE_DIRECT" in match.risk_assessment.rule_ids

    # 7. Verify persistence in database
    ai_rows = (await db_session.execute(select(AIAnalysisDB))).scalars().all()
    assert len(ai_rows) >= 1
    assert ai_rows[0].provider == "MockAIProvider"

    dec_rows = (await db_session.execute(select(DecisionResultDB))).scalars().all()
    assert len(dec_rows) >= 1
    assert dec_rows[0].applicability_probability == 0.85

    risk_rows = (await db_session.execute(select(RiskAssessmentDB))).scalars().all()
    assert len(risk_rows) >= 1
    assert risk_rows[0].status == "likely_affected"


@pytest.mark.asyncio
async def test_full_pipeline_with_ai_disabled_fallback(
    db_session: AsyncSession,
    tmp_path: Path,
    sample_kev_data: dict,
):
    """Complete scan when AI is disabled falls back to conservative risk assessment."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    db_src, _ = await source_repo.get_or_create(
        name="CISA KEV",
        source_type="kev",
        url="https://cisagov.github.io/kev-data/jsonFiles/knownExploitedVulnerabilities.json",
    )
    kev_source = CISAKEVSource()
    records = kev_source._parse(sample_kev_data)
    await vuln_repo.upsert_vulnerabilities(db_src.id, records)
    await db_session.commit()

    scanner_reg = ScannerRegistry()
    scanner_reg.register(PythonScanner())

    source_reg = SourceRegistry()
    source_reg.register(kev_source)

    # No AI providers registered, and AI disabled
    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
        ai_enabled=False,
        decision_enabled=False,
    )

    result = await engine.scan(tmp_path)

    assert result.scan_status == ScanStatus.COMPLETED
    assert result.matches_found >= 1

    match = result.matches[0]
    assert match.ai_analysis is None
    assert match.decision is None
    assert match.risk_assessment is not None
    assert "AI_UNAVAILABLE_FALLBACK" in match.risk_assessment.rule_ids
    assert match.risk_assessment.status in (RiskStatus.DETECTED, RiskStatus.REQUIRES_REVIEW)
    assert match.risk_assessment.requires_human_review is True

    # Assessment persisted
    risk_rows = (await db_session.execute(select(RiskAssessmentDB))).scalars().all()
    assert len(risk_rows) >= 1
