"""Tests for database engine, session lifecycle, and init/close functions."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.config import DatabaseSettings, Settings
from vuln_ai.db.database import (
    close_db,
    get_engine,
    get_session,
    get_session_factory,
    init_db,
)


@pytest.fixture(autouse=True)
async def cleanup_db_engine():
    """Ensure engine is closed before and after each test."""
    await close_db()
    yield
    await close_db()


@pytest.mark.asyncio
async def test_get_engine_singleton(tmp_path: Path):
    """get_engine returns the same AsyncEngine instance on successive calls."""
    settings = Settings(database=DatabaseSettings(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"))

    engine1 = get_engine(settings)
    engine2 = get_engine(settings)
    assert engine1 is engine2


@pytest.mark.asyncio
async def test_get_session_factory(tmp_path: Path):
    """get_session_factory returns a functional async sessionmaker."""
    settings = Settings(database=DatabaseSettings(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"))

    factory1 = get_session_factory(settings)
    factory2 = get_session_factory(settings)
    assert factory1 is factory2


@pytest.mark.asyncio
async def test_init_db_creates_tables(tmp_path: Path):
    """init_db creates all schema tables in the database."""
    db_path = tmp_path / "init_test.db"
    settings = Settings(database=DatabaseSettings(url=f"sqlite+aiosqlite:///{db_path}"))

    await init_db(settings)

    # Verify tables exist by querying sqlite_master
    engine = get_engine(settings)
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        table_names = {row[0] for row in result.fetchall()}

    assert "projects" in table_names
    assert "vulnerabilities" in table_names
    assert "scans" in table_names
    assert "matches" in table_names
    assert "project_components" in table_names
    assert "ai_analyses" in table_names
    assert "decision_results" in table_names
    assert "risk_assessments" in table_names


@pytest.mark.asyncio
async def test_get_session_commit_on_success(tmp_path: Path):
    """get_session automatically commits changes if no exception is raised."""
    db_path = tmp_path / "session_commit.db"
    settings = Settings(database=DatabaseSettings(url=f"sqlite+aiosqlite:///{db_path}"))
    await init_db(settings)

    async for session in get_session(settings):
        assert isinstance(session, AsyncSession)
        await session.execute(
            text(
                "INSERT INTO projects (id, name, path, description, created_at, updated_at) "
                "VALUES ('proj-1', 'Test', '/path/test', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )

    # Verify row was committed
    engine = get_engine(settings)
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT count(*) FROM projects WHERE id='proj-1'"))
        assert result.scalar() == 1


@pytest.mark.asyncio
async def test_get_session_rollback_on_error(tmp_path: Path):
    """get_session rolls back uncommitted changes when an exception is raised."""
    db_path = tmp_path / "session_rollback.db"
    settings = Settings(database=DatabaseSettings(url=f"sqlite+aiosqlite:///{db_path}"))
    await init_db(settings)

    with pytest.raises(RuntimeError, match="Simulated failure"):
        async for session in get_session(settings):
            await session.execute(
                text(
                    "INSERT INTO projects (id, name, path, description, created_at, updated_at) "
                    "VALUES ('proj-fail', 'Fail', '/path/fail', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                )
            )
            raise RuntimeError("Simulated failure")

    # Verify row was rolled back
    engine = get_engine(settings)
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT count(*) FROM projects WHERE id='proj-fail'"))
        assert result.scalar() == 0


@pytest.mark.asyncio
async def test_close_db_multiple_calls_safe():
    """close_db can be called multiple times without error."""
    await close_db()
    await close_db()
