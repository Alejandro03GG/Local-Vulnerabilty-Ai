"""Domain models for the deterministic Risk Engine."""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RiskLevel(enum.StrEnum):
    """Categorical risk severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class RiskStatus(enum.StrEnum):
    """Conservative assessment states.

    Note: As per architecture specifications, 'VULNERABLE' is intentionally
    excluded as a direct automatic state because CISA KEV data does not contain
    per-component version range bounds.
    """

    DETECTED = "detected"  # Component matched in catalog, but version applicability unconfirmed
    LIKELY_AFFECTED = "likely_affected"  # Strong corroborated signals of applicability
    LIKELY_NOT_AFFECTED = "likely_not_affected"  # High evidence of non-applicability
    UNKNOWN = "unknown"  # Insufficient or missing evidence
    REQUIRES_REVIEW = "requires_review"  # Human security triage required (ambiguities/conflicts)


class RiskAssessment(BaseModel):
    """Deterministic conclusion produced by rule-based evaluation of all signals.

    Combines scanner evidence, catalog metadata, LLM contextual analysis,
    and SystemOne decision probabilities into an auditable assessment.
    """

    status: RiskStatus = Field(description="Conservative applicability status")
    risk_level: RiskLevel = Field(description="Assessed risk severity level")
    certainty: float = Field(
        ge=0.0,
        le=1.0,
        description="Explicit certainty score indicating evidence strength (0.0 to 1.0)",
    )
    rationale: str = Field(description="Human-readable justification of rule evaluation")
    recommended_action: str = Field(description="Actionable remediation guidance")
    requires_human_review: bool = Field(
        default=True, description="Whether manual triage is mandatory before action"
    )
    rule_ids: list[str] = Field(
        default_factory=list,
        description="Auditable identifiers of specific deterministic rules triggered",
    )
    assessed_at: datetime = Field(default_factory=_utcnow, description="Assessment timestamp")
