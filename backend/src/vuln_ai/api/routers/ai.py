"""AI and Risk Engine router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from vuln_ai.api.deps import get_match_service
from vuln_ai.api.schemas.ai import AIAnalysisResponse, DecisionResultResponse
from vuln_ai.api.schemas.matches import MatchResponse
from vuln_ai.api.schemas.risk import RiskAssessmentResponse
from vuln_ai.api.services.match_service import MatchService

router = APIRouter(prefix="/matches", tags=["AI"])


@router.get("/{match_id}/analysis", summary="Get match AI contextual analysis")
async def get_match_analysis(
    match_id: str,
    service: Annotated[MatchService, Depends(get_match_service)],
) -> AIAnalysisResponse:
    """Retrieve the persisted Ollama LLM contextual analysis for a match."""
    return await service.get_match_analysis(match_id)


@router.get("/{match_id}/decision", summary="Get match SystemOne decision")
async def get_match_decision(
    match_id: str,
    service: Annotated[MatchService, Depends(get_match_service)],
) -> DecisionResultResponse:
    """Retrieve the persisted Ollama SystemOne decision evaluation for a match."""
    return await service.get_match_decision(match_id)


@router.post("/{match_id}/reanalyze", summary="Re-analyze match with AI and Risk Engine")
async def reanalyze_match(
    match_id: str,
    service: Annotated[MatchService, Depends(get_match_service)],
) -> MatchResponse:
    """Re-run AI contextual analysis, SystemOne decision, and the deterministic Risk Engine."""
    return await service.reanalyze_match(match_id)


@router.get("/{match_id}/risk", summary="Get match risk assessment")
async def get_match_risk(
    match_id: str,
    service: Annotated[MatchService, Depends(get_match_service)],
) -> RiskAssessmentResponse:
    """Retrieve the deterministic Risk Engine assessment and triggered rule IDs for a match."""
    return await service.get_match_risk(match_id)
