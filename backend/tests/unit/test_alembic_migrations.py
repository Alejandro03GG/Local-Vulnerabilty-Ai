"""Tests for Alembic database migrations."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_alembic_upgrade_and_downgrade(tmp_path: Path):
    """Verify that Alembic can run upgrade to head and downgrade to base."""
    db_file = tmp_path / "migration_test.db"
    async_db_url = f"sqlite+aiosqlite:///{db_file}"
    sync_db_url = f"sqlite:///{db_file}"

    root_dir = Path(__file__).parent.parent.parent
    ini_path = root_dir / "alembic.ini"

    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(root_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", async_db_url)

    # 1. Upgrade to head
    command.upgrade(cfg, "head")

    # Verify tables created
    sync_engine = create_engine(sync_db_url)

    inspector = inspect(sync_engine)
    table_names = set(inspector.get_table_names())

    assert "projects" in table_names
    assert "vulnerabilities" in table_names
    assert "matches" in table_names
    assert "scans" in table_names
    assert "project_components" in table_names
    assert "vulnerability_sources" in table_names
    assert "ai_analyses" in table_names
    assert "decision_results" in table_names
    assert "risk_assessments" in table_names
    assert "alembic_version" in table_names

    sync_engine.dispose()

    # 2. Downgrade back to base
    command.downgrade(cfg, "base")

    # Verify tables removed
    sync_engine = create_engine(sync_db_url)
    inspector = inspect(sync_engine)

    remaining_tables = set(inspector.get_table_names()) - {"alembic_version"}
    assert len(remaining_tables) == 0

    sync_engine.dispose()
