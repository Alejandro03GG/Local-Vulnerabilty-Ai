"""Service for component querying."""

from __future__ import annotations

from vuln_ai.api.errors import NotFoundError
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.components import ComponentResponse
from vuln_ai.db.models import ProjectComponentDB
from vuln_ai.db.repositories import ComponentRepository, ProjectRepository


class ComponentService:
    """Business logic for component operations."""

    def __init__(
        self,
        component_repo: ComponentRepository,
        project_repo: ProjectRepository,
    ) -> None:
        self._repo = component_repo
        self._project_repo = project_repo

    @staticmethod
    def to_response(db_comp: ProjectComponentDB) -> ComponentResponse:
        return ComponentResponse(
            id=db_comp.id,
            project_id=db_comp.project_id,
            name=db_comp.name,
            version=db_comp.version,
            version_type=db_comp.version_type,
            version_constraint=db_comp.version_constraint,
            source_file=db_comp.source_file,
            ecosystem=db_comp.ecosystem,
            component_type=db_comp.component_type,
            detected_at=db_comp.detected_at,
        )

    async def list_by_project(
        self, project_id: str, page: int = 1, page_size: int = 20
    ) -> PaginatedResponse[ComponentResponse]:
        """List detected components for a specific project."""
        project = await self._project_repo.get_by_id(project_id)
        if project is None:
            raise NotFoundError(
                message=f"Project with ID '{project_id}' not found",
                code="PROJECT_NOT_FOUND",
            )

        items, total = await self._repo.get_by_project_paginated(
            project_id=project_id,
            page=page,
            page_size=page_size,
        )
        return PaginatedResponse(
            items=[self.to_response(c) for c in items],
            page=page,
            page_size=page_size,
            total=total,
        )

    async def get_component(self, component_id: str) -> ComponentResponse:
        """Get component details by ID."""
        comp = await self._repo.get_by_id(component_id)
        if comp is None:
            raise NotFoundError(
                message=f"Component with ID '{component_id}' not found",
                code="COMPONENT_NOT_FOUND",
            )
        return self.to_response(comp)
