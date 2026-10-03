"""Tests for matches, AI analysis, decision, and risk endpoints."""

from __future__ import annotations

from pathlib import Path

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.base import AIProvider, DecisionProvider
from vuln_ai.ai.models import AIAnalysis, DecisionResult
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.api.deps import get_ai_registry
from vuln_ai.api.main import app
from vuln_ai.core.models import VulnerabilityRecord
from vuln_ai.db.repositories import (
    AIAnalysisRepository,
    DecisionRepository,
    SourceRepository,
    VulnerabilityRepository,
)


class MockAI(AIProvider):
    def __init__(self, available: bool = True):
        self._available = available

    @property
    def name(self) -> str:
        return "mock_ollama"

    @property
    def provider_type(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        return self._available

    async def analyze(self, context) -> AIAnalysis:
        return AIAnalysis(
            provider=self.name,
            model="mock-llama",
            explanation="Detailed analysis of match",
            evidence=["Version match suspected"],
            contextual_findings=["High impact"],
            requires_human_review=False,
            analysis_duration_seconds=0.1,
            tokens_used=42,
        )


class MockDecision(DecisionProvider):
    def __init__(self, available: bool = True):
        self._available = available

    @property
    def name(self) -> str:
        return "mock_systemone"

    @property
    def provider_type(self) -> str:
        return "ollama_systemone"

    async def is_available(self) -> bool:
        return self._available

    async def decide(self, context, questions) -> DecisionResult:
        return DecisionResult(
            provider=self.name,
            model="mock-tev1",
            responses={"applicability": "yes", "exposure": "direct", "urgency": 0.8},
            decision_probabilities={"applicability": {"yes": 0.95, "no": 0.05}},
            applicability_probability=0.95,
            urgency_score=0.8,
            latency_seconds=0.05,
        )


async def _setup_scan_with_match(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
) -> str:
    """Helper to run a scan and return the created match ID."""
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="cisa_kev")

    await vuln_repo.upsert_vulnerabilities(
        source.id,
        [
            VulnerabilityRecord(
                cve_id="CVE-2024-1000",
                source_name="CISA KEV",
                vendor_project="Django",
                product="Django",
                vulnerability_name="Django SQLi",
                short_description="SQL injection vulnerability",
            )
        ],
    )

    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "ai-match-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    scan_res = await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    matches = scan_res.json()["matches"]
    assert len(matches) > 0
    return matches[0]["id"]


async def test_get_match_by_id(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """GET /api/v1/matches/{id} returns complete match structure."""
    match_id = await _setup_scan_with_match(api_client, db_session, sample_project_dir)

    response = await api_client.get(f"/api/v1/matches/{match_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == match_id
    assert data["match_type"] == "exact_name"
    assert data["component"]["name"] == "django"
    assert data["vulnerability"]["cve_id"] == "CVE-2024-1000"


async def test_get_match_not_found(api_client: AsyncClient):
    """GET /api/v1/matches/{missing} returns 404."""
    response = await api_client.get("/api/v1/matches/missing-match-uuid")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "MATCH_NOT_FOUND"


async def test_get_ai_analysis_and_not_found(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """GET /api/v1/matches/{id}/analysis returns persisted AI analysis or 404."""
    match_id = await _setup_scan_with_match(api_client, db_session, sample_project_dir)

    # Initially none
    res404 = await api_client.get(f"/api/v1/matches/{match_id}/analysis")
    assert res404.status_code == 404
    assert res404.json()["error"]["code"] == "ANALYSIS_NOT_FOUND"

    # Persist one
    ai_repo = AIAnalysisRepository(db_session)
    await ai_repo.save_analysis(
        match_id,
        AIAnalysis(
            provider="ollama",
            model="llama3.2",
            explanation="Test explanation",
            evidence=["ev1"],
            contextual_findings=["f1"],
            requires_human_review=False,
            analysis_duration_seconds=0.5,
            tokens_used=100,
        ),
    )

    res200 = await api_client.get(f"/api/v1/matches/{match_id}/analysis")
    assert res200.status_code == 200
    data = res200.json()
    assert data["provider"] == "ollama"
    assert data["model"] == "llama3.2"
    assert data["tokens_used"] == 100


async def test_get_decision_and_not_found(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """GET /api/v1/matches/{id}/decision returns persisted decision or 404."""
    match_id = await _setup_scan_with_match(api_client, db_session, sample_project_dir)

    # Initially none
    res404 = await api_client.get(f"/api/v1/matches/{match_id}/decision")
    assert res404.status_code == 404
    assert res404.json()["error"]["code"] == "DECISION_NOT_FOUND"

    # Persist one
    dec_repo = DecisionRepository(db_session)
    await dec_repo.save_decision(
        match_id,
        DecisionResult(
            provider="ollama_systemone",
            model="tev1:4b",
            responses={"q1": "a1"},
            decision_probabilities={"q1": {"yes": 0.85, "no": 0.15}},
            applicability_probability=0.85,
            urgency_score=0.75,
            latency_seconds=0.2,
        ),
    )

    res200 = await api_client.get(f"/api/v1/matches/{match_id}/decision")
    assert res200.status_code == 200
    data = res200.json()
    assert data["model"] == "tev1:4b"
    assert data["applicability_probability"] == 0.85
    assert data["urgency_score"] == 0.75


async def test_get_risk_assessment_and_not_found(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """GET /api/v1/matches/{id}/risk returns risk assessment."""
    match_id = await _setup_scan_with_match(api_client, db_session, sample_project_dir)

    res = await api_client.get(f"/api/v1/matches/{match_id}/risk")
    assert res.status_code == 200
    data = res.json()
    assert data["status"].upper() in ["REQUIRES_REVIEW", "DETECTED"]
    assert "rule_ids" in data
    assert "MATCH_COMPONENT_ONLY" in data["rule_ids"]


async def test_reanalyze_match_success(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """POST /api/v1/matches/{id}/reanalyze triggers AI, Decision, and Risk Engine."""
    match_id = await _setup_scan_with_match(api_client, db_session, sample_project_dir)

    registry = AIRegistry()
    registry.register_ai_provider(MockAI(available=True))
    registry.register_decision_provider(MockDecision(available=True))

    app.dependency_overrides[get_ai_registry] = lambda: registry

    try:
        response = await api_client.post(f"/api/v1/matches/{match_id}/reanalyze")
        assert response.status_code == 200
        data = response.json()
        assert data["ai_analysis"] is not None
        assert data["ai_analysis"]["provider"] == "mock_ollama"
        assert data["decision_result"] is not None
        assert data["decision_result"]["applicability_probability"] == 0.95
        assert data["risk_assessment"] is not None
        assert "AI_APPLICABILITY_HIGH" in data["risk_assessment"]["rule_ids"]
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


async def test_reanalyze_match_ai_offline_fallback(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """POST /api/v1/matches/{id}/reanalyze handles Ollama offline gracefully."""
    match_id = await _setup_scan_with_match(api_client, db_session, sample_project_dir)

    registry = AIRegistry()
    registry.register_ai_provider(MockAI(available=False))
    registry.register_decision_provider(MockDecision(available=False))

    app.dependency_overrides[get_ai_registry] = lambda: registry

    try:
        response = await api_client.post(f"/api/v1/matches/{match_id}/reanalyze")
        assert response.status_code == 200
        data = response.json()
        assert data["risk_assessment"] is not None
        assert "AI_UNAVAILABLE_FALLBACK" in data["risk_assessment"]["rule_ids"]
        assert data["risk_assessment"]["requires_human_review"] is True
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


async def test_reanalyze_match_not_found(api_client: AsyncClient):
    """POST /api/v1/matches/{missing}/reanalyze returns 404."""
    response = await api_client.post("/api/v1/matches/missing-id/reanalyze")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "MATCH_NOT_FOUND"


async def test_list_matches_paginated(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """GET /api/v1/matches returns paginated matches with structured evidences and conflicts."""
    match_id = await _setup_scan_with_match(api_client, db_session, sample_project_dir)

    response = await api_client.get("/api/v1/matches?page=1&page_size=10")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] >= 1
    assert any(m["id"] == match_id for m in data["items"])
    target = next(m for m in data["items"] if m["id"] == match_id)
    assert "structured_evidences" in target
    assert "conflicts" in target
