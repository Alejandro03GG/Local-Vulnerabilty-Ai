"""Tests for projects API endpoints."""

from __future__ import annotations

from pathlib import Path

from httpx import AsyncClient


async def test_create_project(api_client: AsyncClient, tmp_path: Path):
    """POST /api/v1/projects creates a new project."""
    payload = {
        "name": "my-project",
        "path": str(tmp_path),
        "description": "Test project description",
    }
    response = await api_client.post("/api/v1/projects", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "my-project"
    assert data["path"] == str(tmp_path)
    assert data["description"] == "Test project description"
    assert "id" in data
    assert "created_at" in data
    assert "updated_at" in data


async def test_create_project_conflict(api_client: AsyncClient, tmp_path: Path):
    """POST /api/v1/projects with existing path returns 409 Conflict."""
    payload = {
        "name": "first-project",
        "path": str(tmp_path),
    }
    res1 = await api_client.post("/api/v1/projects", json=payload)
    assert res1.status_code == 201

    # Attempt to create another project with same path
    res2 = await api_client.post("/api/v1/projects", json=payload)
    assert res2.status_code == 409
    data = res2.json()
    assert data["error"]["code"] == "PROJECT_ALREADY_EXISTS"


async def test_create_project_validation_error(api_client: AsyncClient):
    """POST /api/v1/projects with invalid payload returns 422."""
    response = await api_client.post("/api/v1/projects", json={"name": ""})
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


async def test_list_projects_pagination(api_client: AsyncClient, tmp_path: Path):
    """GET /api/v1/projects returns paginated projects."""
    p1 = tmp_path / "proj1"
    p2 = tmp_path / "proj2"
    p3 = tmp_path / "proj3"
    for p in (p1, p2, p3):
        p.mkdir()
        await api_client.post(
            "/api/v1/projects",
            json={"name": p.name, "path": str(p)},
        )

    # Page 1, size 2
    res = await api_client.get("/api/v1/projects?page=1&page_size=2")
    assert res.status_code == 200
    data = res.json()
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total"] == 3
    assert len(data["items"]) == 2

    # Page 2, size 2
    res2 = await api_client.get("/api/v1/projects?page=2&page_size=2")
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2["items"]) == 1


async def test_get_project_by_id(api_client: AsyncClient, tmp_path: Path):
    """GET /api/v1/projects/{id} returns project details."""
    created = await api_client.post(
        "/api/v1/projects",
        json={"name": "single-proj", "path": str(tmp_path)},
    )
    proj_id = created.json()["id"]

    response = await api_client.get(f"/api/v1/projects/{proj_id}")
    assert response.status_code == 200
    assert response.json()["id"] == proj_id


async def test_get_project_not_found(api_client: AsyncClient):
    """GET /api/v1/projects/{nonexistent} returns 404."""
    response = await api_client.get("/api/v1/projects/non-existent-uuid")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "PROJECT_NOT_FOUND"


async def test_update_project(api_client: AsyncClient, tmp_path: Path):
    """PATCH /api/v1/projects/{id} updates project fields."""
    created = await api_client.post(
        "/api/v1/projects",
        json={"name": "old-name", "path": str(tmp_path)},
    )
    proj_id = created.json()["id"]

    update_res = await api_client.patch(
        f"/api/v1/projects/{proj_id}",
        json={"name": "new-name", "description": "updated desc"},
    )
    assert update_res.status_code == 200
    data = update_res.json()
    assert data["name"] == "new-name"
    assert data["description"] == "updated desc"


async def test_update_project_conflict(api_client: AsyncClient, tmp_path: Path):
    """PATCH /api/v1/projects/{id} with conflicting path returns 409."""
    p1 = tmp_path / "p1"
    p2 = tmp_path / "p2"
    p1.mkdir()
    p2.mkdir()

    await api_client.post("/api/v1/projects", json={"name": "p1", "path": str(p1)})
    res2 = await api_client.post("/api/v1/projects", json={"name": "p2", "path": str(p2)})

    id2 = res2.json()["id"]
    # Attempt to update p2 with path of p1
    patch_res = await api_client.patch(f"/api/v1/projects/{id2}", json={"path": str(p1)})
    assert patch_res.status_code == 409
    assert patch_res.json()["error"]["code"] == "PROJECT_ALREADY_EXISTS"


async def test_update_project_not_found(api_client: AsyncClient):
    """PATCH /api/v1/projects/{nonexistent} returns 404."""
    response = await api_client.patch("/api/v1/projects/missing-id", json={"name": "foo"})
    assert response.status_code == 404


async def test_delete_project(api_client: AsyncClient, tmp_path: Path):
    """DELETE /api/v1/projects/{id} removes the project."""
    created = await api_client.post(
        "/api/v1/projects",
        json={"name": "to-delete", "path": str(tmp_path)},
    )
    proj_id = created.json()["id"]

    del_res = await api_client.delete(f"/api/v1/projects/{proj_id}")
    assert del_res.status_code == 204

    # Verification: should now return 404
    get_res = await api_client.get(f"/api/v1/projects/{proj_id}")
    assert get_res.status_code == 404


async def test_delete_project_not_found(api_client: AsyncClient):
    """DELETE /api/v1/projects/{nonexistent} returns 404."""
    response = await api_client.delete("/api/v1/projects/missing-id")
    assert response.status_code == 404
