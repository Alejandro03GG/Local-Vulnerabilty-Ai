"""Scans router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from vuln_ai.api.deps import get_scan_service
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.scans import ScanCreateRequest, ScanResponse
from vuln_ai.api.services.scan_service import ScanService

router = APIRouter(tags=["Scans"])


@router.post(
    "/projects/{project_id}/scans",
    status_code=status.HTTP_201_CREATED,
    summary="Trigger a project scan",
)
async def create_scan(
    project_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
    body: ScanCreateRequest | None = None,
) -> ScanResponse:
    """Execute a vulnerability scan on a project using the core ScanEngine."""
    run_ai = body.run_ai if body is not None else True
    return await service.run_scan(project_id=project_id, run_ai=run_ai)


@router.get("/scans", summary="List scans")
async def list_scans(
    service: Annotated[ScanService, Depends(get_scan_service)],
    project_id: Annotated[str | None, Query(description="Optional project ID filter")] = None,
    page: Annotated[int, Query(ge=1, description="Page number (1-based)")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[ScanResponse]:
    """Retrieve a paginated list of scans with optional project filtering."""
    return await service.list_scans(project_id=project_id, page=page, page_size=page_size)


@router.get("/scans/{scan_id}", summary="Get scan details")
async def get_scan(
    scan_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> ScanResponse:
    """Retrieve details and findings of a specific scan by ID."""
    return await service.get_scan(scan_id)
