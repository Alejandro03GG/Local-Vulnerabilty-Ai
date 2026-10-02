"""Unit tests for the DeterministicRiskEngine."""

from __future__ import annotations

import pytest

from vuln_ai.ai.models import AIAnalysis, DecisionResult
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


@pytest.fixture
def base_match() -> MatchResult:
    comp = DetectedComponent(
        name="django",
        version="4.2.11",
        version_type=VersionType.EXACT,
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
        component_type=ComponentType.FRAMEWORK,
    )
    vuln = VulnerabilityRecord(
        cve_id="CVE-2024-1000",
        source_name="CISA KEV",
        vendor_project="Django",
        product="Django",
        vulnerability_name="SQL Injection",
        short_description="SQL injection in admin",
        required_action="Apply vendor patch",
        known_ransomware_use="Unknown",
    )
    return MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.DETECTED,
        evidence=["Product name matches component name exactly."],
    )


def test_ai_unavailable_fallback(base_match: MatchResult):
    """When AI models are absent, risk engine falls back to conservative rule."""
    engine = DeterministicRiskEngine()
    assessment = engine.assess(base_match, ai_analysis=None, decision=None)

    assert "AI_UNAVAILABLE_FALLBACK" in assessment.rule_ids
    assert "MATCH_COMPONENT_ONLY" in assessment.rule_ids
    assert assessment.status == RiskStatus.DETECTED
    assert assessment.requires_human_review is True
    assert assessment.certainty <= 0.6


def test_no_version_evidence_forces_requires_review(base_match: MatchResult):
    """Missing version evidence triggers NO_VERSION_EVIDENCE rule and REQUIRES_REVIEW."""
    base_match.component.version = None
    base_match.component.version_type = VersionType.UNKNOWN

    engine = DeterministicRiskEngine()
    assessment = engine.assess(base_match, ai_analysis=None, decision=None)

    assert "NO_VERSION_EVIDENCE" in assessment.rule_ids
    assert assessment.status == RiskStatus.REQUIRES_REVIEW
    assert assessment.requires_human_review is True


def test_ransomware_campaign_associated_elevates_risk(base_match: MatchResult):
    """Known ransomware history triggers rule and elevates risk level."""
    base_match.vulnerability.known_ransomware_use = "Known"

    engine = DeterministicRiskEngine()
    assessment = engine.assess(base_match, ai_analysis=None, decision=None)

    assert "RANSOMWARE_CAMPAIGN_ASSOCIATED" in assessment.rule_ids
    assert assessment.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_high_applicability_with_version_and_direct_exposure(base_match: MatchResult):
    """High decision probability with declared version leads to LIKELY_AFFECTED."""
    engine = DeterministicRiskEngine()

    ai_analysis = AIAnalysis(
        provider="ollama",
        model="llama3.2",
        explanation="Version 4.2.11 is explicitly covered in the advisory.",
        evidence=["Advisory mentions 4.2 branches"],
        requires_human_review=False,
    )
    decision = DecisionResult(
        provider="ollama_systemone",
        model="tev1:4b",
        responses={"applicability": "yes", "exposure": "direct", "urgency": 9.0},
        decision_probabilities={"applicability": {"yes": 0.85, "no": 0.15}},
        applicability_probability=0.85,
        urgency_score=9.0,
    )

    assessment = engine.assess(base_match, ai_analysis=ai_analysis, decision=decision)

    assert "AI_APPLICABILITY_HIGH" in assessment.rule_ids
    assert "EXPOSURE_DIRECT" in assessment.rule_ids
    assert "URGENCY_HIGH" in assessment.rule_ids
    assert assessment.status == RiskStatus.LIKELY_AFFECTED
    assert assessment.risk_level == RiskLevel.CRITICAL


def test_low_applicability_produces_likely_not_affected(base_match: MatchResult):
    """Low applicability probability leads to LIKELY_NOT_AFFECTED and LOW risk."""
    engine = DeterministicRiskEngine()

    decision = DecisionResult(
        provider="ollama_systemone",
        model="tev1:4b",
        responses={"applicability": "no", "exposure": "indirect", "urgency": 2.0},
        decision_probabilities={"applicability": {"yes": 0.10, "no": 0.90}},
        applicability_probability=0.10,
        urgency_score=2.0,
    )

    assessment = engine.assess(base_match, ai_analysis=None, decision=decision)

    assert "AI_APPLICABILITY_LOW" in assessment.rule_ids
    assert "EXPOSURE_INDIRECT" in assessment.rule_ids
    assert assessment.status == RiskStatus.LIKELY_NOT_AFFECTED
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.requires_human_review is False


def test_conflicting_signals_triggers_requires_review(base_match: MatchResult):
    """Discrepancy between AI analysis flagging review and high probability triggers CONFLICTING_SIGNALS."""
    engine = DeterministicRiskEngine()

    ai_analysis = AIAnalysis(
        provider="ollama",
        model="llama3.2",
        explanation="Major uncertainty exists regarding whether patch backport is present.",
        requires_human_review=True,
    )
    decision = DecisionResult(
        provider="ollama_systemone",
        model="tev1:4b",
        applicability_probability=0.92,
    )

    assessment = engine.assess(base_match, ai_analysis=ai_analysis, decision=decision)

    assert "CONFLICTING_SIGNALS" in assessment.rule_ids
    assert assessment.status == RiskStatus.REQUIRES_REVIEW
    assert assessment.requires_human_review is True


def test_moderate_applicability_and_unknown_exposure(base_match: MatchResult):
    """Moderate applicability probability triggers moderate rule and DETECTED baseline status."""
    engine = DeterministicRiskEngine()

    decision = DecisionResult(
        provider="ollama_systemone",
        model="tev1:4b",
        responses={"applicability": "uncertain", "exposure": "unknown", "urgency": 5.0},
        applicability_probability=0.50,
        urgency_score=5.0,
    )

    assessment = engine.assess(base_match, ai_analysis=None, decision=decision)

    assert "AI_APPLICABILITY_MODERATE" in assessment.rule_ids
    assert "EXPOSURE_UNKNOWN" in assessment.rule_ids
    assert assessment.status == RiskStatus.DETECTED
    assert assessment.risk_level == RiskLevel.MEDIUM
    assert assessment.requires_human_review is True
