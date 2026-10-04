"""End-to-End subprocess execution tests for Local Vulnerability AI CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from vuln_ai import __version__
from vuln_ai.cli.errors import CLIExitCode

SRC_DIR = str(Path(__file__).parent.parent.parent / "src")


def _get_base_env() -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{SRC_DIR}:{existing}" if existing else SRC_DIR
    return env


def test_cli_subprocess_help() -> None:
    """Execute 'python -m vuln_ai.cli --help' as external process."""
    res = subprocess.run(
        [sys.executable, "-m", "vuln_ai.cli", "--help"],
        capture_output=True,
        text=True,
        env=_get_base_env(),
        check=False,
    )
    assert res.returncode == 0
    assert "Usage: " in res.stdout
    assert "scan" in res.stdout


def test_cli_subprocess_version() -> None:
    """Execute 'python -m vuln_ai.cli version' as external process."""
    res = subprocess.run(
        [sys.executable, "-m", "vuln_ai.cli", "version"],
        capture_output=True,
        text=True,
        env=_get_base_env(),
        check=False,
    )
    assert res.returncode == 0
    assert f"Local Vulnerability AI {__version__}" in res.stdout


def test_cli_subprocess_scan_e2e(tmp_path: Path) -> None:
    """Execute full scan on fixture project with JSON output via subprocess."""
    proj_dir = tmp_path / "target_project"
    proj_dir.mkdir()
    (proj_dir / "requirements.txt").write_text("fastapi==0.115.0\nrequests==2.31.0\n")

    report_path = tmp_path / "out_report.json"

    env = _get_base_env()
    env["VULN_AI_DATABASE__URL"] = f"sqlite+aiosqlite:///{tmp_path / 'e2e.db'}"

    # Initialize DB schema first
    import asyncio

    from vuln_ai.config import Settings
    from vuln_ai.db.database import close_db, init_db

    async def _setup_e2e_db() -> None:
        await close_db()
        await init_db(Settings(database={"url": env["VULN_AI_DATABASE__URL"], "echo": False}))
        await close_db()

    asyncio.run(_setup_e2e_db())

    res = subprocess.run(
        [
            sys.executable,
            "-m",
            "vuln_ai.cli",
            "scan",
            str(proj_dir),
            "--no-ai",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert res.returncode == CLIExitCode.SUCCESS
    assert report_path.exists()
    data = json.loads(report_path.read_text())
    assert data["project_name"] == "target_project"
    assert data["summary"]["components_found"] == 2
