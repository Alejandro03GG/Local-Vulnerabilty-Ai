"""Vulnerabilities router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from vuln_ai.api.deps import get_vulnerability_service
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.vulnerabilities import VulnerabilityResponse
from vuln_ai.api.services.vulnerability_service import VulnerabilityService

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", summary="List catalog vulnerabilities")
async def list_vulnerabilities(
    service: Annotated[VulnerabilityService, Depends(get_vulnerability_service)],
    cve: Annotated[str | None, Query(description="Filter by CVE identifier substring")] = None,
    source: Annotated[str | None, Query(description="Filter by source name or ID")] = None,
    vendor: Annotated[str | None, Query(description="Filter by vendor name substring")] = None,
    product: Annotated[str | None, Query(description="Filter by product name substring")] = None,
    page: Annotated[int, Query(ge=1, description="Page number (1-based)")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[VulnerabilityResponse]:
    """Retrieve a paginated list of catalog vulnerabilities with optional filters."""
    return await service.list_vulnerabilities(
        cve=cve,
        source=source,
        vendor=vendor,
        product=product,
        page=page,
        page_size=page_size,
    )


@router.get("/{vulnerability_id}", summary="Get vulnerability details")
async def get_vulnerability(
    vulnerability_id: str,
    service: Annotated[VulnerabilityService, Depends(get_vulnerability_service)],
) -> VulnerabilityResponse:
    """Retrieve details of a catalog vulnerability by ID."""
    return await service.get_vulnerability(vulnerability_id)
