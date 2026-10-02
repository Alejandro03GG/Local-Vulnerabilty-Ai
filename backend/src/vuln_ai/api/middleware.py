"""FastAPI middleware for request tracing and timing."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware attaching request ID and measuring execution latency."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.monotonic()

        response = await call_next(request)

        duration = time.monotonic() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{duration:.4f}s"

        logger.debug(
            "%s %s -> %d in %.4fs (Request-ID: %s)",
            request.method,
            request.url.path,
            response.status_code,
            duration,
            request_id,
        )
        return response


def register_middleware(app: FastAPI) -> None:
    """Register custom middlewares on the FastAPI application."""
    app.add_middleware(RequestContextMiddleware)
