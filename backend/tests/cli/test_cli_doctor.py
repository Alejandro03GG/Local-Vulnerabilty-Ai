"""Tests for 'vuln-ai doctor' diagnostic command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.main import app
from vuln_ai.config import Settings
from vuln_ai.db.database import close_db, init_db

runner = CliRunner()


@pytest.mark.asyncio
async def test_doctor_healthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify 'vuln-ai doctor' reports OK for healthy environment and initialized database."""
    await close_db()
    db_file = tmp_path / "doctor_healthy.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.doctor.get_settings", lambda: settings)

    with patch("vuln_ai.cli.commands.doctor._check_ollama", new_callable=AsyncMock) as m_ollama:
        m_ollama.return_value = (True, "Online (test mock)")
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == CLIExitCode.SUCCESS
        assert "System & Environment Diagnostics" in result.stdout
        assert "Python Runtime" in result.stdout
        assert "SQLite Database" in result.stdout
        assert "diagnostics passed successfully" in result.stdout


@pytest.mark.asyncio
async def test_doctor_uninitialized_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify 'vuln-ai doctor' flags uninitialized database schema."""
    await close_db()
    db_file = tmp_path / "doctor_uninit.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    # Do NOT call init_db

    monkeypatch.setattr("vuln_ai.cli.commands.doctor.get_settings", lambda: settings)

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == CLIExitCode.USAGE_ERROR
    assert "System & Environment Diagnostics" in result.stdout
    assert "FAIL" in result.stdout


@pytest.mark.asyncio
async def test_doctor_ollama_non_200_and_network_error(tmp_path: Path) -> None:
    """Verify _check_ollama returns appropriate diagnostic messages on non-200 and exceptions."""
    from vuln_ai.cli.commands.doctor import _check_ollama

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as m_get:
        # Non-200 response
        mock_resp = AsyncMock()
        mock_resp.status_code = 500
        m_get.return_value = mock_resp
        ok, msg = await _check_ollama("http://localhost:11434", "llama3.2")
        assert not ok
        assert "500" in msg

        # Network error
        m_get.side_effect = Exception("network unreachable")
        ok, msg = await _check_ollama("http://localhost:11434", "llama3.2")
        assert not ok
        assert "network unreachable" in msg
