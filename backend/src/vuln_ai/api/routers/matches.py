"""Matches router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from vuln_ai.api.deps import get_match_service
from vuln_ai.api.schemas.matches import MatchResponse
from vuln_ai.api.services.match_service import MatchService

router = APIRouter(prefix="/matches", tags=["Matches"])


@router.get("/{match_id}", summary="Get match details")
async def get_match(
    match_id: str,
    service: Annotated[MatchService, Depends(get_match_service)],
) -> MatchResponse:
    """Retrieve full details of a vulnerability match including AI analysis and risk assessment."""
    return await service.get_match(match_id)
