"""Tests for scans API endpoints."""

from __future__ import annotations

from pathlib import Path

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import VulnerabilityRecord
from vuln_ai.db.repositories import ProjectRepository, SourceRepository, VulnerabilityRepository


async def test_create_scan_success(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """POST /api/v1/projects/{id}/scans executes full scan and returns summary."""
    # Seed vulnerabilities
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="cisa_kev")

    await vuln_repo.upsert_vulnerabilities(
        source.id,
        [
            VulnerabilityRecord(
                cve_id="CVE-2024-1000",
                source_name="CISA KEV",
                vendor_project="Django",
                product="Django",
                vulnerability_name="Django SQLi",
                short_description="SQL injection vulnerability",
            )
        ],
    )

    # Register project
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "scan-target", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    # Trigger scan
    scan_res = await api_client.post(
        f"/api/v1/projects/{proj_id}/scans",
        json={"run_ai": False},
    )
    assert scan_res.status_code == 201
    data = scan_res.json()
    assert data["project_id"] == proj_id
    assert data["status"] == "completed"
    assert data["components_found"] > 0
    assert data["summary"]["components"] > 0
    assert data["summary"]["matches"] >= 1
    assert "matches" in data
    assert len(data["matches"]) >= 1


async def test_create_scan_project_not_found(api_client: AsyncClient):
    """POST /api/v1/projects/{missing}/scans returns 404."""
    response = await api_client.post(
        "/api/v1/projects/missing-project-id/scans",
        json={"run_ai": False},
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROJECT_NOT_FOUND"


async def test_create_scan_invalid_path(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
):
    """POST /api/v1/projects/{id}/scans where path does not exist returns 400."""
    nonexistent = tmp_path / "does_not_exist"
    proj_repo = ProjectRepository(db_session)
    project = await proj_repo.create(name="bad-path", path=str(nonexistent))

    response = await api_client.post(f"/api/v1/projects/{project.id}/scans")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "SCAN_EXECUTION_FAILED"


async def test_list_scans_pagination_and_filter(
    api_client: AsyncClient,
    sample_project_dir: Path,
):
    """GET /api/v1/scans returns paginated scans and supports project_id filter."""
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "multi-scan-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    # Run two scans
    await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})

    # List all scans
    all_res = await api_client.get("/api/v1/scans?page=1&page_size=10")
    assert all_res.status_code == 200
    assert all_res.json()["total"] == 2

    # Filter by project_id
    filter_res = await api_client.get(f"/api/v1/scans?project_id={proj_id}")
    assert filter_res.status_code == 200
    assert filter_res.json()["total"] == 2


async def test_list_scans_filter_nonexistent_project(api_client: AsyncClient):
    """GET /api/v1/scans?project_id=missing returns 404."""
    response = await api_client.get("/api/v1/scans?project_id=missing-id")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROJECT_NOT_FOUND"


async def test_get_scan_by_id(
    api_client: AsyncClient,
    sample_project_dir: Path,
):
    """GET /api/v1/scans/{id} returns full scan details."""
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "get-scan-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    scan_res = await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    scan_id = scan_res.json()["id"]

    get_res = await api_client.get(f"/api/v1/scans/{scan_id}")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["id"] == scan_id
    assert data["project_id"] == proj_id
    assert "summary" in data


async def test_get_scan_not_found(api_client: AsyncClient):
    """GET /api/v1/scans/{missing} returns 404."""
    response = await api_client.get("/api/v1/scans/missing-id")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"


async def test_get_scan_dependencies(
    api_client: AsyncClient,
    sample_project_dir: Path,
):
    """GET /api/v1/scans/{id}/dependencies returns component list with direct/transitive flags."""
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "scan-deps-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    scan_res = await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    scan_id = scan_res.json()["id"]

    deps_res = await api_client.get(f"/api/v1/scans/{scan_id}/dependencies")
    assert deps_res.status_code == 200
    data = deps_res.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "is_direct" in data[0]
    assert "dependency_type" in data[0]

    # 404 case
    not_found = await api_client.get("/api/v1/scans/non-existent-scan/dependencies")
    assert not_found.status_code == 404


async def test_get_scan_dependency_graph(
    api_client: AsyncClient,
    sample_project_dir: Path,
):
    """GET /api/v1/scans/{id}/dependencies/graph returns nodes, edges, and counts."""
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "scan-graph-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    scan_res = await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    scan_id = scan_res.json()["id"]

    graph_res = await api_client.get(f"/api/v1/scans/{scan_id}/dependencies/graph")
    assert graph_res.status_code == 200
    data = graph_res.json()
    assert data["project_id"] == proj_id
    assert "components" in data
    assert "edges" in data
    assert "direct_count" in data
    assert "transitive_count" in data

    # 404 case
    not_found = await api_client.get("/api/v1/scans/non-existent-scan/dependencies/graph")
    assert not_found.status_code == 404
