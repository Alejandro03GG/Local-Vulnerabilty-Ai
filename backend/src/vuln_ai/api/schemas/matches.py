"""Match schemas for the REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from vuln_ai.api.schemas.ai import AIAnalysisResponse, DecisionResultResponse
from vuln_ai.api.schemas.components import ComponentResponse
from vuln_ai.api.schemas.risk import RiskAssessmentResponse
from vuln_ai.api.schemas.vulnerabilities import VulnerabilityResponse


class MatchEvidenceResponse(BaseModel):
    """Structured evidence contributing to a match determination."""

    source_name: str = Field(description="Intelligence source (OSV, NVD, CISA KEV)")
    identifier: str = Field(description="Vulnerability identifier")
    package_name: str = Field(description="Package evaluated")
    ecosystem: str = Field(description="Package ecosystem")
    installed_version: str | None = Field(default=None, description="Installed component version")
    affected_range: str | None = Field(default=None, description="Affected range evaluated")
    fixed_version: str | None = Field(default=None, description="Fixed version if known")
    status: str = Field(description="Applicability verdict from this source")
    evidence_type: str = Field(description="Evidence type (range_confirmed, outside_range, etc.)")
    details: str = Field(default="", description="Detailed human-readable evaluation")


class SourceConflictResponse(BaseModel):
    """Auditable discrepancy between vulnerability intelligence sources."""

    conflict_type: str = Field(description="Category of conflict (applicability, range, severity)")
    severity: str = Field(description="Severity impact (high, medium, low)")
    field: str = Field(description="Divergent domain attribute")
    sources: list[str] = Field(default_factory=list, description="Conflicting sources")
    identifiers: list[str] = Field(default_factory=list, description="Referenced identifiers")
    values: dict[str, Any] = Field(
        default_factory=dict, description="Values reported by each source"
    )
    resolution: str = Field(description="Consolidated resolution status")
    rationale: str = Field(default="", description="Technical justification")


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
    structured_evidences: list[MatchEvidenceResponse] = Field(
        default_factory=list,
        description="Structured evidence records from intelligence sources",
    )
    conflicts: list[SourceConflictResponse] = Field(
        default_factory=list,
        description="Multi-source discrepancies or conflicts detected during correlation",
    )
