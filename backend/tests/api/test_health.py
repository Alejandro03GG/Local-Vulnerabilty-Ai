"""Tests for health and readiness endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock

from httpx import AsyncClient

from vuln_ai.api.deps import get_db
from vuln_ai.api.main import app


async def test_health_check(api_client: AsyncClient):
    """GET /health returns 200 OK and version info."""
    response = await api_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


async def test_readiness_check_success(api_client: AsyncClient):
    """GET /health/ready returns 200 and ready state when DB is healthy."""
    response = await api_client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"


async def test_readiness_check_db_failure(api_client: AsyncClient):
    """GET /health/ready returns 503 when DB connection fails."""
    mock_failing_session = AsyncMock()
    mock_failing_session.execute.side_effect = RuntimeError("Database unreachable")

    async def _failing_get_db():
        yield mock_failing_session

    app.dependency_overrides[get_db] = _failing_get_db
    try:
        response = await api_client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unavailable"
        assert data["database"] == "disconnected"
        assert "Database unreachable" in data["error"]
    finally:
        app.dependency_overrides.pop(get_db, None)


async def test_readiness_check_with_ai_diagnostics(api_client: AsyncClient):
    """GET /health/ready returns diagnostic AI status without compromising readiness."""
    from vuln_ai.ai.base import AIProvider
    from vuln_ai.ai.registry import AIRegistry
    from vuln_ai.api.deps import get_ai_registry

    class MockHealthyAI(AIProvider):
        @property
        def name(self) -> str:
            return "mock"

        async def is_available(self) -> bool:
            return True

        async def analyze(self, *args, **kwargs):
            raise NotImplementedError

    reg = AIRegistry()
    reg.register_ai_provider(MockHealthyAI())

    app.dependency_overrides[get_ai_registry] = lambda: reg
    try:
        response = await api_client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["ai"] == "available"
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)
