"""Shared context and service wiring for CLI execution."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.ollama_provider import OllamaProvider
from vuln_ai.ai.ollama_systemone_provider import OllamaSystemOneProvider
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.config import Settings, get_settings
from vuln_ai.db.database import get_session_factory
from vuln_ai.scanners import (
    CargoLockScanner,
    NpmLockScanner,
    PnpmLockScanner,
    PoetryLockScanner,
    PythonScanner,
    ScannerRegistry,
)
from vuln_ai.sources.cisa_kev import CISAKEVSource
from vuln_ai.sources.nvd import NVDSource
from vuln_ai.sources.osv import OSVSource
from vuln_ai.sources.registry import SourceRegistry

logger = logging.getLogger(__name__)


def build_scanner_registry() -> ScannerRegistry:
    """Instantiate scanner registry with all supported scanners."""
    registry = ScannerRegistry()
    registry.register(PythonScanner())
    registry.register(PoetryLockScanner())
    registry.register(NpmLockScanner())
    registry.register(PnpmLockScanner())
    registry.register(CargoLockScanner())
    return registry


def build_source_registry(settings: Settings) -> SourceRegistry:
    """Instantiate source registry with configured sources."""
    registry = SourceRegistry()
    registry.register(CISAKEVSource(settings=settings.kev))
    registry.register(OSVSource(settings=settings.osv))
    registry.register(NVDSource(settings=settings.nvd))
    return registry


def build_ai_registry(settings: Settings, enabled: bool = True) -> AIRegistry:
    """Instantiate AI provider registry."""
    registry = AIRegistry()
    if enabled and settings.ai.enabled:
        if settings.ai.ollama.enabled:
            registry.register_ai_provider(OllamaProvider(settings=settings.ai.ollama))
        if settings.ai.decision.enabled:
            registry.register_decision_provider(
                OllamaSystemOneProvider(settings=settings.ai.decision)
            )
    return registry


async def is_db_schema_ready(session: AsyncSession) -> bool:
    """Verify that required database tables exist."""
    try:
        await session.execute(text("SELECT 1 FROM vulnerabilities LIMIT 1"))
        return True
    except Exception:
        return False


@asynccontextmanager
async def get_cli_session(settings: Settings | None = None) -> AsyncGenerator[AsyncSession, None]:
    """Provide an async database session for CLI commands."""
    s = settings or get_settings()
    factory = get_session_factory(s)
    try:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    finally:
        from vuln_ai.db.database import close_db

        await close_db()


def run_async_cli(coro: Any) -> Any:
    """Run an async coroutine safely, supporting both normal CLI and pytest event loops."""
    import asyncio
    import concurrent.futures

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(asyncio.run, coro).result()
    return asyncio.run(coro)
