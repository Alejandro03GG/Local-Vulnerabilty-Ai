"""H9: Dockerfile AST scan must persist and appear on Images API."""

from __future__ import annotations

from httpx import AsyncClient

DOCKERFILE = """
FROM python:3.12-slim AS base
RUN apt-get update && apt-get install -y curl=7.88.1-1
COPY requirements.txt /app/
"""


async def test_dockerfile_scan_persists_ast(api_client: AsyncClient):
    response = await api_client.post(
        "/api/v1/container/dockerfile/scan",
        json={"content": DOCKERFILE, "persist": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["package_installations"]
    assert body["image_id"]
    assert body["scan_id"]

    image_id = body["image_id"]
    detail = await api_client.get(f"/api/v1/images/{image_id}")
    assert detail.status_code == 200, detail.text
    img = detail.json()
    assert img["source_type"] == "dockerfile"
    assert img["dockerfile_ast"] is not None
    assert img["dockerfile_ast"]["package_installations"]
    assert any(
        "curl" in (inst.get("packages") or [])
        for inst in img["dockerfile_ast"]["package_installations"]
    )


async def test_dockerfile_scan_persist_false_skips_db(api_client: AsyncClient):
    response = await api_client.post(
        "/api/v1/container/dockerfile/scan",
        json={"content": "FROM alpine\n", "persist": False},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["image_id"] is None
