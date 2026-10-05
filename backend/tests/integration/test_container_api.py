"""Integration tests for Container Image and Dockerfile REST API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.fixtures.container_fixtures import create_docker_image_archive


@pytest.mark.asyncio
async def test_container_image_scan_and_query_endpoints(
    api_client: AsyncClient,
    tmp_path,
):
    """Test full cycle: scan container archive, get details, layers, components, policy, graph.

    Uses the shared ``api_client`` fixture (in-memory DB) so local developer
    databases with many prior scans cannot hide the new image on page 1.
    """
    archive_path = tmp_path / "test_api_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="api-test:1.0.0",
        os_release='ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n',
        dpkg_status="Package: curl\nVersion: 7.88.1-10\nStatus: install ok installed\n",
    )

    # 1. POST /api/v1/images/scan
    scan_res = await api_client.post(
        "/api/v1/images/scan",
        json={
            "archive_path": str(archive_path),
            "reference": "api-test:1.0.0",
            "no_ai": True,
        },
    )
    assert scan_res.status_code == 201, scan_res.text
    data = scan_res.json()
    image_id = data["id"]
    assert data["reference"] == "api-test:1.0.0"
    assert data["os"] == "Debian GNU/Linux"
    assert data["layer_count"] == 1
    assert len(data["layers"]) == 1

    # 2. GET /api/v1/images — newest scan must appear on the default first page
    # even when the OCI config "created" timestamp is old (fixture uses 2026-01-01).
    list_res = await api_client.get("/api/v1/images")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert list_data["items"], "expected at least one listed image"
    assert list_data["items"][0]["id"] == image_id
    assert any(img["id"] == image_id for img in list_data["items"])

    # 3. GET /api/v1/images/{image_id}
    get_res = await api_client.get(f"/api/v1/images/{image_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == image_id

    # 4. GET /api/v1/images/{image_id}/layers
    layers_res = await api_client.get(f"/api/v1/images/{image_id}/layers")
    assert layers_res.status_code == 200
    assert len(layers_res.json()) == 1

    # 5. GET /api/v1/images/{image_id}/components
    comps_res = await api_client.get(f"/api/v1/images/{image_id}/components")
    assert comps_res.status_code == 200
    comps = comps_res.json()
    assert len(comps) == 1
    assert comps[0]["name"] == "curl"
    assert comps[0]["version"] == "7.88.1-10"
    assert comps[0]["ecosystem"] == "deb"

    # 6. GET /api/v1/images/{image_id}/vulnerabilities
    vulns_res = await api_client.get(f"/api/v1/images/{image_id}/vulnerabilities")
    assert vulns_res.status_code == 200
    assert isinstance(vulns_res.json(), list)

    # 7. GET /api/v1/images/{image_id}/dependency-graph
    graph_res = await api_client.get(f"/api/v1/images/{image_id}/dependency-graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert graph_data["image_id"] == image_id
    assert len(graph_data["nodes"]) >= 1

    # 8. GET /api/v1/images/{image_id}/policy
    pol_res = await api_client.get(f"/api/v1/images/{image_id}/policy")
    assert pol_res.status_code == 200
    pol_data = pol_res.json()
    assert "status" in pol_data
    assert "ci_exit_code" in pol_data


@pytest.mark.asyncio
async def test_container_dockerfile_scan_endpoint(api_client: AsyncClient):
    """Test POST /api/v1/container/dockerfile/scan."""
    dockerfile_content = """FROM python:3.12-slim AS runtime
RUN apt-get update && apt-get install -y curl
COPY requirements.txt .
RUN pip install -r requirements.txt
"""
    res = await api_client.post(
        "/api/v1/container/dockerfile/scan",
        json={"content": dockerfile_content},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert len(data["stages"]) == 1
    assert data["stages"][0]["base_image"]["name"] == "python"
    assert len(data["package_installations"]) >= 1
    assert "requirements.txt" in data["dependency_manifests"]


@pytest.mark.asyncio
async def test_container_scan_nonexistent_file(api_client: AsyncClient):
    """Verify 400 error when scanning non-existent archive."""
    res = await api_client.post(
        "/api/v1/images/scan",
        json={"archive_path": "/nonexistent/path/image.tar"},
    )
    assert res.status_code == 400
    msg = res.json().get("detail") or res.json().get("error", {}).get("message", "")
    assert "not found" in msg.lower()
