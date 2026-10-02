"""Tests for API errors, exception handlers, and middlewares."""

from __future__ import annotations

from httpx import AsyncClient

from vuln_ai.api.errors import BadRequestError, ConflictError, NotFoundError, ValidationError
from vuln_ai.api.main import app


async def test_middleware_request_id_and_timing(api_client: AsyncClient):
    """RequestContextMiddleware attaches X-Request-ID and X-Process-Time."""
    # 1. Without client request ID -> auto generated
    res1 = await api_client.get("/health")
    assert res1.status_code == 200
    assert "x-request-id" in res1.headers
    assert "x-process-time" in res1.headers
    assert res1.headers["x-process-time"].endswith("s")

    # 2. With client-supplied request ID -> preserved
    client_req_id = "test-custom-trace-12345"
    res2 = await api_client.get("/health", headers={"X-Request-ID": client_req_id})
    assert res2.status_code == 200
    assert res2.headers["x-request-id"] == client_req_id


async def test_cors_headers(api_client: AsyncClient):
    """CORS middleware returns allow headers for configured origins."""
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
    }
    response = await api_client.options("/api/v1/projects", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


async def test_structured_error_handlers(api_client: AsyncClient):
    """Test custom APIError subclasses produce standard JSON envelope."""

    @app.get("/test-error/bad-request")
    async def _test_bad_request():
        raise BadRequestError(message="Invalid query syntax", code="BAD_SYNTAX")

    @app.get("/test-error/conflict")
    async def _test_conflict():
        raise ConflictError(message="Resource exists", code="RESOURCE_CONFLICT")

    @app.get("/test-error/not-found")
    async def _test_not_found():
        raise NotFoundError(message="Item missing", code="ITEM_NOT_FOUND")

    @app.get("/test-error/validation")
    async def _test_val():
        raise ValidationError(message="Semantic rule violated", code="INVALID_RULE")

    @app.get("/test-error/unhandled")
    async def _test_unhandled():
        raise ZeroDivisionError("division by zero")

    # Bad Request (400)
    res_br = await api_client.get("/test-error/bad-request")
    assert res_br.status_code == 400
    assert res_br.json() == {
        "error": {
            "code": "BAD_SYNTAX",
            "message": "Invalid query syntax",
            "details": {},
        }
    }

    # Conflict (409)
    res_conf = await api_client.get("/test-error/conflict")
    assert res_conf.status_code == 409
    assert res_conf.json()["error"]["code"] == "RESOURCE_CONFLICT"

    # Not Found (404)
    res_nf = await api_client.get("/test-error/not-found")
    assert res_nf.status_code == 404
    assert res_nf.json()["error"]["code"] == "ITEM_NOT_FOUND"

    # Validation (422)
    res_val = await api_client.get("/test-error/validation")
    assert res_val.status_code == 422
    assert res_val.json()["error"]["code"] == "INVALID_RULE"

    # Unhandled Exception (500) - hides internal details
    res_500 = await api_client.get("/test-error/unhandled")
    assert res_500.status_code == 500
    data_500 = res_500.json()
    assert data_500["error"]["code"] == "INTERNAL_SERVER_ERROR"
    assert "division by zero" not in data_500["error"]["message"]
