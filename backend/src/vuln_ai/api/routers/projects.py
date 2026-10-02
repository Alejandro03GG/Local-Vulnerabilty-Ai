"""Projects router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from vuln_ai.api.deps import get_project_service
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.projects import ProjectCreate, ProjectResponse, ProjectUpdate
from vuln_ai.api.services.project_service import ProjectService

router = APIRouter(prefix="/projects", tags=["Projects"])


@router.get("", summary="List projects with pagination")
async def list_projects(
    service: Annotated[ProjectService, Depends(get_project_service)],
    page: Annotated[int, Query(ge=1, description="Page number (1-based)")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[ProjectResponse]:
    """Retrieve a paginated list of registered projects."""
    return await service.list_projects(page=page, page_size=page_size)


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Register a new project",
)
async def create_project(
    data: ProjectCreate,
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> ProjectResponse:
    """Register a new project for vulnerability scanning."""
    return await service.create_project(data)


@router.get("/{project_id}", summary="Get project details")
async def get_project(
    project_id: str,
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> ProjectResponse:
    """Retrieve details for a specific project by ID."""
    return await service.get_project(project_id)


@router.patch("/{project_id}", summary="Update an existing project")
async def update_project(
    project_id: str,
    data: ProjectUpdate,
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> ProjectResponse:
    """Update metadata or filesystem path of an existing project."""
    return await service.update_project(project_id, data)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a project",
)
async def delete_project(
    project_id: str,
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> None:
    """Delete a project and its associated scans and detected components."""
    await service.delete_project(project_id)
