"""Main FastAPI application factory and entrypoint."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vuln_ai.api.errors import register_error_handlers
from vuln_ai.api.middleware import register_middleware
from vuln_ai.api.routers import (
    ai_router,
    components_router,
    health_router,
    matches_router,
    projects_router,
    scans_router,
    sources_router,
    vulnerabilities_router,
)
from vuln_ai.config import Settings, get_settings
from vuln_ai.db.database import close_db, init_db


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a new FastAPI application instance."""
    app_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        # Startup: initialize database tables
        await init_db(app_settings)
        yield
        # Shutdown: close connection pool
        await close_db()

    app = FastAPI(
        title=app_settings.api.title,
        version=app_settings.api.version,
        description=(
            "Local-first vulnerability analysis platform combining deterministic "
            "catalog matching with local AI analysis and deterministic risk scoring."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Middlewares & error handlers
    register_middleware(app)
    register_error_handlers(app)

    # CORS configuration
    if app_settings.api.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=app_settings.api.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Mount Health routes outside API version
    app.include_router(health_router)

    # API v1 prefix router
    api_v1 = APIRouter(prefix="/api/v1")
    api_v1.include_router(projects_router)
    api_v1.include_router(scans_router)
    api_v1.include_router(components_router)
    api_v1.include_router(vulnerabilities_router)
    api_v1.include_router(sources_router)
    api_v1.include_router(matches_router)
    api_v1.include_router(ai_router)

    app.include_router(api_v1)

    return app


# Default app instance for uvicorn (e.g. uvicorn vuln_ai.api.main:app)
app = create_app()
