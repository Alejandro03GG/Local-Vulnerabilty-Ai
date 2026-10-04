"""Regression tests for Stage 18 CLI image command surface."""

from __future__ import annotations

from typer.testing import CliRunner

from vuln_ai.cli.main import app

runner = CliRunner()


def test_image_help_lists_scan_only() -> None:
    """1.0 CLI exposes `image scan`; list/info/dockerfile are not separate commands."""
    result = runner.invoke(app, ["image", "--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "image list" not in result.stdout
    # Subcommand table should not advertise unimplemented inventory commands.
    assert "list" not in result.stdout.split("Commands")[-1]
    assert "info" not in result.stdout.split("Commands")[-1]
    assert "dockerfile" not in result.stdout.split("Commands")[-1]


def test_image_scan_help_mentions_archive_or_dockerfile() -> None:
    """`image scan` accepts a local archive or Dockerfile path."""
    result = runner.invoke(app, ["image", "scan", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.stdout
    assert "--no-ai" in result.stdout
    assert "--policy" in result.stdout
    help_text = result.stdout.lower()
    assert "dockerfile" in help_text or "archive" in help_text
