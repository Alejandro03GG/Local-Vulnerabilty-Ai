"""Match schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from vuln_ai.api.schemas.ai import AIAnalysisResponse, DecisionResultResponse
from vuln_ai.api.schemas.components import ComponentResponse
from vuln_ai.api.schemas.risk import RiskAssessmentResponse
from vuln_ai.api.schemas.vulnerabilities import VulnerabilityResponse


class MatchResponse(BaseModel):
    """Detailed match result separating deterministic, AI, and risk layers."""

    id: str = Field(description="Unique match identifier (UUID)")
    scan_id: str = Field(description="Associated scan ID")
    component_id: str = Field(description="Associated component ID")
    vulnerability_id: str = Field(description="Associated vulnerability ID")
    match_type: str = Field(
        description="Deterministic match type: exact, component_only, fuzzy, etc."
    )
    match_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Deterministic matcher confidence score (0.0 to 1.0)",
    )
    applicability: str = Field(
        description="Applicability classification: applicable, not_applicable, unknown"
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Deterministic matcher evidence items",
    )
    matched_at: datetime = Field(description="Timestamp when match was recorded")

    component: ComponentResponse | None = Field(
        default=None,
        description="Matched project component details",
    )
    vulnerability: VulnerabilityResponse | None = Field(
        default=None,
        description="Matched vulnerability catalog record",
    )
    ai_analysis: AIAnalysisResponse | None = Field(
        default=None,
        description="Contextual AI analysis narrative if generated",
    )
    decision_result: DecisionResultResponse | None = Field(
        default=None,
        description="Structured SystemOne decision evaluation if generated",
    )
    risk_assessment: RiskAssessmentResponse | None = Field(
        default=None,
        description="Auditable risk assessment produced by deterministic Risk Engine",
    )
