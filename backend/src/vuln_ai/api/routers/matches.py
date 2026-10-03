"""Matches router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from vuln_ai.api.deps import get_match_service
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.matches import MatchResponse
from vuln_ai.api.services.match_service import MatchService

router = APIRouter(prefix="/matches", tags=["Matches"])


@router.get("", summary="List matches")
async def list_matches(
    service: Annotated[MatchService, Depends(get_match_service)],
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    scan_id: str | None = Query(None, description="Filter by scan ID"),
    applicability: str | None = Query(None, description="Filter by applicability"),
) -> PaginatedResponse[MatchResponse]:
    """Retrieve paginated vulnerability matches across all scans."""
    return await service.list_matches(
        page=page,
        page_size=page_size,
        scan_id=scan_id,
        applicability=applicability,
    )


@router.get("/{match_id}", summary="Get match details")
async def get_match(
    match_id: str,
    service: Annotated[MatchService, Depends(get_match_service)],
) -> MatchResponse:
    """Retrieve full details of a vulnerability match including AI analysis and risk assessment."""
    return await service.get_match(match_id)
