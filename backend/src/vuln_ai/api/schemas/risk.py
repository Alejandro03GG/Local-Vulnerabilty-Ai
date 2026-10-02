"""Risk assessment schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RiskAssessmentResponse(BaseModel):
    """Deterministic, auditable conclusion produced by the Risk Engine."""

    status: str = Field(
        description="Assessment status: DETECTED, LIKELY_AFFECTED, LIKELY_NOT_AFFECTED, UNKNOWN, REQUIRES_REVIEW"
    )
    risk_level: str = Field(description="Risk priority tier: LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN")
    certainty: float = Field(
        ge=0.0,
        le=1.0,
        description="Certainty metric based on presence of direct evidence (0.0 to 1.0)",
    )
    rationale: str = Field(description="Explanatory rationale for the assigned assessment")
    recommended_action: str = Field(description="Recommended mitigation or investigative action")
    requires_human_review: bool = Field(
        description="Whether security analyst review is recommended"
    )
    rule_ids: list[str] = Field(
        default_factory=list,
        description="Deterministic rule IDs triggered during evaluation",
    )
    assessed_at: datetime = Field(description="Assessment evaluation timestamp")
