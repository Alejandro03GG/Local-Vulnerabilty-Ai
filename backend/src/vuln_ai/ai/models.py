"""Domain models for AI analysis and SystemOne decision layers."""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from vuln_ai.core.models import (
    Ecosystem,
    MatchType,
    VersionType,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class QuestionType(enum.StrEnum):
    """Question types supported by the SystemOne decision API."""

    NOUL = "noul"  # Binary / yes-no probabilistic evaluation
    CHOICE = "choice"  # Multi-class categorical choice
    SCORE = "score"  # Continuous score / priority evaluation


class AnalysisContext(BaseModel):
    """Contextual data prepared for AI and Decision providers to evaluate a match."""

    # Component details
    component_name: str = Field(description="Normalized component name")
    component_version: str | None = Field(
        default=None, description="Component version if declared"
    )
    version_type: VersionType = Field(
        default=VersionType.UNKNOWN, description="How the version was declared"
    )
    version_constraint: str | None = Field(default=None, description="Original version constraint")
    ecosystem: Ecosystem = Field(
        default=Ecosystem.UNKNOWN, description="Component ecosystem (e.g., pypi)"
    )
    source_file: str = Field(
        default="", description="File where component was detected (e.g., requirements.txt)"
    )

    # Vulnerability details
    cve_id: str = Field(default="", description="CVE identifier or canonical ID")
    source_name: str = Field(default="CISA KEV", description="Catalog source")
    vendor_project: str = Field(description="Target vendor or open-source project")
    product: str = Field(description="Target product name")
    vulnerability_name: str = Field(default="", description="Name or title of vulnerability")
    short_description: str = Field(default="", description="Catalog summary description")
    required_action: str = Field(default="", description="Catalog remediation instructions")
    cwes: list[str] = Field(default_factory=list, description="Associated CWEs")
    known_ransomware_use: str = Field(default="Unknown", description="Ransomware campaign history")
    date_added: datetime | None = Field(default=None, description="Date cataloged")
    due_date: datetime | None = Field(default=None, description="Remediation deadline")

    # Match evidence
    match_type: MatchType = Field(
        default=MatchType.EXACT_NAME, description="Deterministic match mechanism"
    )
    match_confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Matcher confidence")
    match_evidence: list[str] = Field(
        default_factory=list, description="Deterministic evidence strings"
    )

    @classmethod
    def from_match(cls, match: Any) -> AnalysisContext:
        """Create an AnalysisContext from a deterministic MatchResult."""

        comp = match.component
        vuln = match.vulnerability
        return cls(
            component_name=comp.name,
            component_version=comp.version,
            version_type=comp.version_type,
            version_constraint=comp.version_constraint,
            ecosystem=comp.ecosystem,
            source_file=comp.source_file,
            cve_id=vuln.cve_id or vuln.canonical_id or "UNKNOWN-VULN",
            source_name=vuln.source_name,
            vendor_project=vuln.vendor_project,
            product=vuln.product,
            vulnerability_name=vuln.vulnerability_name,
            short_description=vuln.short_description,
            required_action=vuln.required_action,
            cwes=list(vuln.cwes),
            known_ransomware_use=vuln.known_ransomware_use,
            date_added=vuln.date_added,
            due_date=vuln.due_date,
            match_type=match.match_type,
            match_confidence=match.match_confidence,
            match_evidence=list(match.evidence),
        )


class AIAnalysis(BaseModel):
    """Contextual narrative analysis produced by an LLM provider.

    Note: This model represents the contextual reasoning of the LLM.
    It does NOT determine final risk levels or replace deterministic matching.
    """

    provider: str = Field(description="Provider name (e.g. 'ollama')")
    model: str = Field(description="Model identifier (e.g. 'llama3.2')")
    explanation: str = Field(description="Contextual explanation of findings")
    evidence: list[str] = Field(
        default_factory=list, description="Extracted contextual evidence points"
    )
    contextual_findings: list[str] = Field(
        default_factory=list, description="Specific contextual nuances identified"
    )
    requires_human_review: bool = Field(
        default=True, description="Whether LLM flagged need for human audit"
    )
    analysis_duration_seconds: float = Field(
        default=0.0, ge=0.0, description="Inference latency in seconds"
    )
    tokens_used: int | None = Field(default=None, description="Tokens consumed if available")
    analyzed_at: datetime = Field(default_factory=_utcnow, description="Analysis timestamp")


class DecisionQuestion(BaseModel):
    """A structured question evaluated by a probabilistic decision provider."""

    id: str = Field(description="Unique question key (e.g. 'applicability')")
    question: str = Field(description="Natural language question")
    question_type: QuestionType = Field(description="Question type: noul, choice, or score")
    options: list[str] | None = Field(
        default=None, description="Valid options for choice questions"
    )
    min_score: float | None = Field(
        default=None, description="Minimum score bound for score questions"
    )
    max_score: float | None = Field(
        default=None, description="Maximum score bound for score questions"
    )


class DecisionResult(BaseModel):
    """Structured responses and probabilities from a decision provider.

    Documented Semantics:
    The probabilities produced by the model represent the model's evaluation over
    the provided options based on context. They do NOT equal a guaranteed real-world
    probability of exploitation or system compromise.
    """

    provider: str = Field(description="Provider name (e.g. 'ollama_systemone')")
    model: str = Field(description="Decision model identifier (e.g. 'tev1:4b')")
    responses: dict[str, Any] = Field(
        default_factory=dict, description="Selected answer or value per question ID"
    )
    decision_probabilities: dict[str, dict[str, float]] = Field(
        default_factory=dict,
        description="Probability distribution per question ID and option",
    )
    applicability_probability: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Assigned probability that the vulnerability applies to the component",
    )
    urgency_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Prioritization score (1-10) for investigation/remediation",
    )
    latency_seconds: float = Field(default=0.0, ge=0.0, description="Decision latency")
    timestamp: datetime = Field(default_factory=_utcnow, description="Decision timestamp")
    raw_response: dict[str, Any] | None = Field(
        default=None, description="Sanitized raw response for debugging"
    )
