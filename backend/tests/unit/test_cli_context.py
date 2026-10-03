"""Unit tests for CLI context helpers and registries."""

from __future__ import annotations

import pytest

from vuln_ai.cli.context import (
    build_ai_registry,
    build_scanner_registry,
    build_source_registry,
    get_cli_session,
    is_db_schema_ready,
    run_async_cli,
)
from vuln_ai.config import Settings


def test_build_scanner_registry():
    registry = build_scanner_registry()
    assert len(registry) == 5


def test_build_source_registry():
    settings = Settings()
    registry = build_source_registry(settings)
    assert len(registry) == 3


def test_build_ai_registry_enabled():
    settings = Settings(
        ai={"enabled": True, "ollama": {"enabled": True}, "decision": {"enabled": True}}
    )
    registry = build_ai_registry(settings, enabled=True)
    assert registry.get_ai_provider() is not None
    assert registry.get_decision_provider() is not None


@pytest.mark.asyncio
async def test_get_cli_session_rollback():
    settings = Settings()
    with pytest.raises(RuntimeError):
        async with get_cli_session(settings) as session:
            assert await is_db_schema_ready(session) is True
            raise RuntimeError("Forced rollback")


def test_run_async_cli_no_loop():
    async def dummy():
        return 42

    result = run_async_cli(dummy())
    assert result == 42
