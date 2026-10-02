"""Unit tests for AI and Decision domain models."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from vuln_ai.ai.models import (
    AIAnalysis,
    AnalysisContext,
    DecisionQuestion,
    DecisionResult,
    QuestionType,
)
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


def test_analysis_context_from_match():
    """AnalysisContext accurately captures all relevant match and catalog fields."""
    comp = DetectedComponent(
        name="requests",
        version="2.31.0",
        version_type=VersionType.EXACT,
        version_constraint="==2.31.0",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
        component_type=ComponentType.LIBRARY,
    )
    vuln = VulnerabilityRecord(
        cve_id="CVE-2024-4000",
        source_name="CISA KEV",
        vendor_project="Python",
        product="Requests",
        vulnerability_name="SSRF vulnerability",
        short_description="SSRF in requests library.",
        required_action="Upgrade to 2.32.0",
        known_ransomware_use="Known",
        cwes=["CWE-918"],
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.DETECTED,
        evidence=["Product name matches component name exactly."],
    )

    ctx = AnalysisContext.from_match(match)

    assert ctx.component_name == "requests"
    assert ctx.component_version == "2.31.0"
    assert ctx.ecosystem == Ecosystem.PYPI
    assert ctx.cve_id == "CVE-2024-4000"
    assert ctx.product == "Requests"
    assert ctx.known_ransomware_use == "Known"
    assert ctx.cwes == ["CWE-918"]
    assert ctx.match_confidence == 1.0
    assert len(ctx.match_evidence) == 1


def test_ai_analysis_validation():
    """AIAnalysis holds narrative fields without acting as authoritative risk level."""
    analysis = AIAnalysis(
        provider="ollama",
        model="llama3.2",
        explanation="The vulnerability applies if certificates are disabled.",
        evidence=["Component matches product"],
        contextual_findings=["Cert validation disabled"],
        requires_human_review=True,
        analysis_duration_seconds=1.25,
        tokens_used=180,
    )

    assert analysis.provider == "ollama"
    assert analysis.model == "llama3.2"
    assert analysis.requires_human_review is True
    assert analysis.tokens_used == 180
    assert isinstance(analysis.analyzed_at, datetime)


def test_decision_question_types():
    """DecisionQuestion validates supported question types: noul, choice, score."""
    q_noul = DecisionQuestion(
        id="app",
        question="Is it applicable?",
        question_type=QuestionType.NOUL,
    )
    assert q_noul.question_type == "noul"

    q_choice = DecisionQuestion(
        id="exp",
        question="What is the exposure?",
        question_type=QuestionType.CHOICE,
        options=["direct", "indirect", "unknown"],
    )
    assert q_choice.options == ["direct", "indirect", "unknown"]

    q_score = DecisionQuestion(
        id="urg",
        question="What is the urgency?",
        question_type=QuestionType.SCORE,
        min_score=1.0,
        max_score=10.0,
    )
    assert q_score.min_score == 1.0
    assert q_score.max_score == 10.0


def test_decision_result_metrics():
    """DecisionResult stores specific probability and priority score fields."""
    res = DecisionResult(
        provider="ollama_systemone",
        model="tev1:4b",
        responses={"applicability": "yes", "exposure": "direct", "urgency": 8.0},
        decision_probabilities={
            "applicability": {"yes": 0.88, "no": 0.12},
            "exposure": {"direct": 0.80, "indirect": 0.20},
        },
        applicability_probability=0.88,
        urgency_score=8.0,
        latency_seconds=0.45,
    )

    assert res.applicability_probability == 0.88
    assert res.urgency_score == 8.0
    assert res.latency_seconds == 0.45
    assert res.responses["exposure"] == "direct"


def test_decision_result_probability_bounds():
    """Probabilities outside [0.0, 1.0] must raise validation error."""
    with pytest.raises(ValidationError):
        DecisionResult(
            provider="test",
            model="test",
            applicability_probability=1.5,  # Exceeds 1.0
        )

    with pytest.raises(ValidationError):
        DecisionResult(
            provider="test",
            model="test",
            applicability_probability=-0.1,  # Negative
        )
