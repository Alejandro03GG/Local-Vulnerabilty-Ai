"""Regression tests for Stage 18 CLI image command surface."""

from __future__ import annotations

import re

from typer.testing import CliRunner

from vuln_ai.cli.main import app

runner = CliRunner()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip ANSI styling so assertions work under CI force-color terminals."""
    return _ANSI_RE.sub("", text)


def test_image_help_lists_scan_only() -> None:
    """1.0 CLI exposes `image scan`; list/info/dockerfile are not separate commands."""
    result = runner.invoke(app, ["image", "--help"])
    assert result.exit_code == 0
    help_text = _plain(result.stdout)
    assert "scan" in help_text
    assert "image list" not in help_text
    # Subcommand table should not advertise unimplemented inventory commands.
    assert "list" not in help_text.split("Commands")[-1]
    assert "info" not in help_text.split("Commands")[-1]
    assert "dockerfile" not in help_text.split("Commands")[-1]


def test_image_scan_help_mentions_archive_or_dockerfile() -> None:
    """`image scan` accepts a local archive or Dockerfile path."""
    result = runner.invoke(app, ["image", "scan", "--help"])
    assert result.exit_code == 0
    help_text = _plain(result.stdout)
    assert "--format" in help_text
    assert "--no-ai" in help_text
    assert "--policy" in help_text
    lowered = help_text.lower()
    assert "dockerfile" in lowered or "archive" in lowered
