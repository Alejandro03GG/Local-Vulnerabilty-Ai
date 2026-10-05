"""H15: -o must write export file without dumping full document to stdout."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.main import app
from vuln_ai.config import Settings
from vuln_ai.core.models import (
    AffectedVersionRange,
    Ecosystem,
    VulnerabilityRecord,
)
from vuln_ai.db.database import close_db, get_session_factory, init_db
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository

runner = CliRunner()


@pytest.fixture
async def seeded_cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    await close_db()
    db_file = tmp_path / "test_cli_h15.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    session_factory = get_session_factory(settings)
    async with session_factory() as session:
        src_repo = SourceRepository(session)
        vuln_repo = VulnerabilityRepository(session)
        src, _ = await src_repo.get_or_create("OSV", "osv")
        record = VulnerabilityRecord(
            canonical_id="CVE-2023-32681",
            source_name="OSV",
            vendor_project="requests",
            product="requests",
            vulnerability_name="Proxy leak",
            severity="HIGH",
            cvss_score=7.5,
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem=Ecosystem.PYPI,
                    package_name="requests",
                    introduced="0",
                    fixed="2.31.0",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(src.id, [record])
        await session.commit()

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    proj_dir = tmp_path / "target_proj"
    proj_dir.mkdir()
    (proj_dir / "requirements.txt").write_text("requests==2.25.0\n")
    return proj_dir


def test_cli_scan_json_output_file_not_dumped_to_stdout(
    seeded_cli_env: Path, tmp_path: Path
) -> None:
    out = tmp_path / "scan-out.json"
    result = runner.invoke(
        app,
        ["scan", str(seeded_cli_env), "--format", "json", "--no-ai", "-o", str(out)],
    )
    assert result.exit_code == CLIExitCode.SUCCESS, f"OUTPUT: {result.output}"
    assert out.exists()
    doc = json.loads(out.read_text())
    assert isinstance(doc, dict)
    # Full JSON document must not be echoed on stdout when -o is used (H15).
    stdout = result.stdout.strip()
    if stdout:
        with pytest.raises(json.JSONDecodeError):
            json.loads(stdout)
