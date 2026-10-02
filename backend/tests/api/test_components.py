"""Tests for components API endpoints."""

from __future__ import annotations

from pathlib import Path

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import (
    ComponentType,
    DetectedComponent,
    Ecosystem,
    VersionType,
)
from vuln_ai.db.repositories import ComponentRepository, ProjectRepository


async def test_list_components_by_project(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
):
    """GET /api/v1/projects/{id}/components returns paginated list of components."""
    proj_repo = ProjectRepository(db_session)
    comp_repo = ComponentRepository(db_session)

    project = await proj_repo.create(name="comp-proj", path=str(tmp_path))
    sample_comps = [
        DetectedComponent(
            name="requests",
            version="2.31.0",
            version_type=VersionType.EXACT,
            source_file="requirements.txt",
            ecosystem=Ecosystem.PYPI,
            component_type=ComponentType.LIBRARY,
        ),
        DetectedComponent(
            name="flask",
            version="3.0.0",
            version_type=VersionType.EXACT,
            source_file="requirements.txt",
            ecosystem=Ecosystem.PYPI,
            component_type=ComponentType.FRAMEWORK,
        ),
    ]
    await comp_repo.save_components(project.id, sample_comps)

    response = await api_client.get(
        f"/api/v1/projects/{project.id}/components?page=1&page_size=10"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2
    names = {item["name"] for item in data["items"]}
    assert names == {"requests", "flask"}


async def test_list_components_project_not_found(api_client: AsyncClient):
    """GET /api/v1/projects/{missing}/components returns 404."""
    response = await api_client.get("/api/v1/projects/missing-id/components")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROJECT_NOT_FOUND"


async def test_get_component_by_id(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
):
    """GET /api/v1/components/{id} returns component details."""
    proj_repo = ProjectRepository(db_session)
    comp_repo = ComponentRepository(db_session)

    project = await proj_repo.create(name="comp-proj2", path=str(tmp_path))
    db_comps = await comp_repo.save_components(
        project.id,
        [
            DetectedComponent(
                name="django",
                version="4.2.0",
                version_type=VersionType.EXACT,
                version_constraint="==4.2.0",
                source_file="requirements.txt",
                ecosystem=Ecosystem.PYPI,
                component_type=ComponentType.FRAMEWORK,
            )
        ],
    )
    comp_id = db_comps[0].id

    response = await api_client.get(f"/api/v1/components/{comp_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == comp_id
    assert data["name"] == "django"
    assert data["version"] == "4.2.0"
    assert data["ecosystem"] == "pypi"
    assert data["component_type"] == "framework"


async def test_get_component_not_found(api_client: AsyncClient):
    """GET /api/v1/components/{missing} returns 404."""
    response = await api_client.get("/api/v1/components/missing-uuid")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "COMPONENT_NOT_FOUND"
