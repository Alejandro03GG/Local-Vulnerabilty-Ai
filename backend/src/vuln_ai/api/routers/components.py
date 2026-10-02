"""Components router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from vuln_ai.api.deps import get_component_service
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.components import ComponentResponse
from vuln_ai.api.services.component_service import ComponentService

router = APIRouter(tags=["Components"])


@router.get(
    "/projects/{project_id}/components",
    summary="List components for a project",
)
async def list_project_components(
    project_id: str,
    service: Annotated[ComponentService, Depends(get_component_service)],
    page: Annotated[int, Query(ge=1, description="Page number (1-based)")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[ComponentResponse]:
    """Retrieve detected software dependencies for a specific project."""
    return await service.list_by_project(project_id=project_id, page=page, page_size=page_size)


@router.get("/components/{component_id}", summary="Get component details")
async def get_component(
    component_id: str,
    service: Annotated[ComponentService, Depends(get_component_service)],
) -> ComponentResponse:
    """Retrieve details of a specific detected component by ID."""
    return await service.get_component(component_id)
