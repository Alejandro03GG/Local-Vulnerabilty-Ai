"""H3: GET /api/v1/components must return existing components (frontend contract)."""

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


async def test_global_components_list_non_empty(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
):
    """Frontend ComponentsPage calls GET /api/v1/components — must not be empty when data exists."""
    proj_repo = ProjectRepository(db_session)
    comp_repo = ComponentRepository(db_session)
    project = await proj_repo.create(name="h3-proj", path=str(tmp_path / "h3"))
    await comp_repo.save_components(
        project.id,
        [
            DetectedComponent(
                name="requests",
                version="2.31.0",
                version_type=VersionType.EXACT,
                source_file="requirements.txt",
                ecosystem=Ecosystem.PYPI,
                component_type=ComponentType.LIBRARY,
            )
        ],
    )

    response = await api_client.get("/api/v1/components?page=1&page_size=50")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] >= 1
    assert any(item["name"] == "requests" for item in data["items"])


async def test_global_components_filter_by_project_id(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
):
    proj_repo = ProjectRepository(db_session)
    comp_repo = ComponentRepository(db_session)
    p1 = await proj_repo.create(name="h3-a", path=str(tmp_path / "a"))
    p2 = await proj_repo.create(name="h3-b", path=str(tmp_path / "b"))
    await comp_repo.save_components(
        p1.id,
        [
            DetectedComponent(
                name="flask",
                version="3.0.0",
                version_type=VersionType.EXACT,
                source_file="requirements.txt",
                ecosystem=Ecosystem.PYPI,
                component_type=ComponentType.FRAMEWORK,
            )
        ],
    )
    await comp_repo.save_components(
        p2.id,
        [
            DetectedComponent(
                name="lodash",
                version="4.17.21",
                version_type=VersionType.EXACT,
                source_file="package-lock.json",
                ecosystem=Ecosystem.NPM,
                component_type=ComponentType.LIBRARY,
            )
        ],
    )

    response = await api_client.get(f"/api/v1/components?project_id={p1.id}")
    assert response.status_code == 200
    names = {item["name"] for item in response.json()["items"]}
    assert names == {"flask"}
