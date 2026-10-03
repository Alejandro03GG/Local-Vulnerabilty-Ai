"""Tests for 'vuln-ai sources' subcommands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.main import app
from vuln_ai.config import Settings
from vuln_ai.core.models import SyncResult
from vuln_ai.db.database import close_db, init_db

runner = CliRunner()


@pytest.mark.asyncio
async def test_sources_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify 'sources list' displays configured catalogs."""
    await close_db()
    db_file = tmp_path / "test_sources.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.sources.get_settings", lambda: settings)

    result = runner.invoke(app, ["sources", "list"])
    assert result.exit_code == CLIExitCode.SUCCESS
    assert "Configured Vulnerability Sources" in result.stdout
    assert "CISA KEV" in result.stdout
    assert "OSV" in result.stdout
    assert "NVD" in result.stdout


@pytest.mark.asyncio
async def test_sources_sync_all_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify 'sources sync' runs synchronization on registered sources."""
    await close_db()
    db_file = tmp_path / "test_sources_sync.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.sources.get_settings", lambda: settings)

    mock_sync_result = SyncResult(
        source_name="CISA KEV",
        success=True,
        records_synced=10,
        records_total=10,
        duration_seconds=0.2,
    )

    with (
        patch("vuln_ai.sources.cisa_kev.CISAKEVSource.sync", new_callable=AsyncMock) as m_cisa,
        patch("vuln_ai.sources.osv.OSVSource.sync", new_callable=AsyncMock) as m_osv,
        patch("vuln_ai.sources.nvd.NVDSource.sync", new_callable=AsyncMock) as m_nvd,
    ):
        m_cisa.return_value = mock_sync_result
        m_osv.return_value = SyncResult(
            source_name="OSV", success=True, records_synced=5, duration_seconds=0.1
        )
        m_nvd.return_value = SyncResult(
            source_name="NVD", success=True, records_synced=2, duration_seconds=0.1
        )

        result = runner.invoke(app, ["sources", "sync"])
        assert result.exit_code == CLIExitCode.SUCCESS
        assert "Synchronization Results" in result.stdout
        assert "SUCCESS" in result.stdout


@pytest.mark.asyncio
async def test_sources_sync_unknown_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify syncing an invalid source name fails with exit code 2."""
    await close_db()
    db_file = tmp_path / "test_sources_bad.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.sources.get_settings", lambda: settings)

    result = runner.invoke(app, ["sources", "sync", "--source", "NonExistentCatalog"])
    assert result.exit_code == CLIExitCode.USAGE_ERROR
    assert "not found" in result.output
