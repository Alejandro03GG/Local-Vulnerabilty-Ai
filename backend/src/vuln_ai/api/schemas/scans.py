"""Scan schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from vuln_ai.api.schemas.matches import MatchResponse


class ScanCreateRequest(BaseModel):
    """Request payload to initiate a new project scan."""

    run_ai: bool = Field(
        default=True,
        description="Whether to run contextual LLM analysis and SystemOne decision models if available",
    )


class ScanSummary(BaseModel):
    """High-level metrics summary for a scan."""

    components: int = Field(default=0, description="Total detected components")
    matches: int = Field(default=0, description="Total vulnerability matches found")
    kev_matches: int = Field(default=0, description="Total CISA KEV matches")
    requires_review: int = Field(
        default=0, description="Findings requiring human security analyst review"
    )


class ScanResponse(BaseModel):
    """Scan operation record returned by the API."""

    id: str = Field(description="Unique scan identifier (UUID)")
    project_id: str = Field(description="Associated project ID")
    status: str = Field(description="Scan execution status: running, completed, failed")
    components_found: int = Field(default=0, description="Number of components detected")
    vulnerabilities_found: int = Field(
        default=0, description="Number of catalog vulnerabilities evaluated"
    )
    kev_matches: int = Field(default=0, description="Number of CISA KEV matches")
    duration_seconds: float = Field(default=0.0, description="Scan duration in seconds")
    started_at: datetime = Field(description="Scan start timestamp")
    completed_at: datetime | None = Field(default=None, description="Scan completion timestamp")
    error: str | None = Field(default=None, description="Error message if scan failed")
    summary: ScanSummary = Field(description="Aggregated scan metrics summary")
    matches: list[MatchResponse] | None = Field(
        default=None, description="Detailed match results if requested"
    )
