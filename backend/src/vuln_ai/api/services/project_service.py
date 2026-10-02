"""Service for project management."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.api.errors import ConflictError, NotFoundError
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.projects import ProjectCreate, ProjectResponse, ProjectUpdate
from vuln_ai.db.models import ProjectDB
from vuln_ai.db.repositories import ProjectRepository


class ProjectService:
    """Business logic for project operations."""

    def __init__(self, project_repo: ProjectRepository) -> None:
        self._repo = project_repo

    @staticmethod
    def _to_response(db_project: ProjectDB) -> ProjectResponse:
        return ProjectResponse(
            id=db_project.id,
            name=db_project.name,
            path=db_project.path,
            description=db_project.description,
            created_at=db_project.created_at,
            updated_at=db_project.updated_at,
        )

    async def list_projects(
        self, page: int = 1, page_size: int = 20
    ) -> PaginatedResponse[ProjectResponse]:
        """List registered projects with pagination."""
        items, total = await self._repo.list_paginated(page=page, page_size=page_size)
        return PaginatedResponse(
            items=[self._to_response(p) for p in items],
            page=page,
            page_size=page_size,
            total=total,
        )

    async def get_project(self, project_id: str) -> ProjectResponse:
        """Get project details by ID."""
        project = await self._repo.get_by_id(project_id)
        if project is None:
            raise NotFoundError(
                message=f"Project with ID '{project_id}' not found",
                code="PROJECT_NOT_FOUND",
            )
        return self._to_response(project)

    async def create_project(self, data: ProjectCreate) -> ProjectResponse:
        """Register a new project."""
        normalized_path = str(Path(data.path).expanduser().resolve())
        existing = await self._repo.get_by_path(normalized_path)
        if existing is not None:
            raise ConflictError(
                message=f"A project with path '{normalized_path}' already exists",
                code="PROJECT_ALREADY_EXISTS",
            )

        project = await self._repo.create(
            name=data.name,
            path=normalized_path,
            description=data.description,
        )
        return self._to_response(project)

    async def update_project(self, project_id: str, data: ProjectUpdate) -> ProjectResponse:
        """Update an existing project."""
        path_to_update = (
            str(Path(data.path).expanduser().resolve()) if data.path is not None else None
        )
        if path_to_update is not None:
            existing = await self._repo.get_by_path(path_to_update)
            if existing is not None and existing.id != project_id:
                raise ConflictError(
                    message=f"Another project with path '{path_to_update}' already exists",
                    code="PROJECT_ALREADY_EXISTS",
                )

        updated = await self._repo.update(
            project_id=project_id,
            name=data.name,
            path=path_to_update,
            description=data.description,
        )
        if updated is None:
            raise NotFoundError(
                message=f"Project with ID '{project_id}' not found",
                code="PROJECT_NOT_FOUND",
            )
        return self._to_response(updated)

    async def delete_project(self, project_id: str) -> None:
        """Delete a project and its associated scans and components."""
        deleted = await self._repo.delete(project_id)
        if not deleted:
            raise NotFoundError(
                message=f"Project with ID '{project_id}' not found",
                code="PROJECT_NOT_FOUND",
            )
