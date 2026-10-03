"""Tests for main CLI entrypoint and options."""

from __future__ import annotations

from typer.testing import CliRunner

from vuln_ai import __version__
from vuln_ai.cli.main import app

runner = CliRunner()


def test_cli_help() -> None:
    """Verify that --help exits with 0 and displays all core commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "vuln-ai" in result.stdout
    assert "scan" in result.stdout
    assert "version" in result.stdout
    assert "doctor" in result.stdout
    assert "sources" in result.stdout


def test_cli_version_command() -> None:
    """Verify that 'version' command prints canonical version."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert f"Local Vulnerability AI {__version__}" in result.stdout


def test_cli_version_flag() -> None:
    """Verify that '--version' and '-v' print canonical version and exit."""
    result_long = runner.invoke(app, ["--version"])
    assert result_long.exit_code == 0
    assert f"Local Vulnerability AI {__version__}" in result_long.stdout

    result_short = runner.invoke(app, ["-v"])
    assert result_short.exit_code == 0
    assert f"Local Vulnerability AI {__version__}" in result_short.stdout


def test_cli_unknown_command() -> None:
    """Verify that unknown commands exit with non-zero code."""
    result = runner.invoke(app, ["nonexistent-command"])
    assert result.exit_code != 0
