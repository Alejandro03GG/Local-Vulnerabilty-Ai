"""Tests for CLI scan export formats: SARIF, CycloneDX, SPDX (Etapa 15 §28-§31)."""

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
    """Setup isolated database with seeded vulnerability for CLI test."""
    await close_db()
    db_file = tmp_path / "test_cli_export.db"
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


def test_cli_scan_sarif_format(seeded_cli_env: Path) -> None:
    """Verify --format sarif outputs pure SARIF 2.1.0 document to stdout."""
    result = runner.invoke(app, ["scan", str(seeded_cli_env), "--format", "sarif", "--no-ai"])
    assert result.exit_code == CLIExitCode.SUCCESS, f"OUTPUT: {result.output}"

    # Stdout must parse as valid SARIF
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Local Vulnerability AI"
    assert len(doc["runs"][0]["results"]) >= 1
    assert doc["runs"][0]["results"][0]["ruleId"] == "CVE-2023-32681"


@pytest.mark.asyncio
async def test_cli_scan_cyclonedx_format(seeded_cli_env: Path) -> None:
    """Verify --format cyclonedx outputs pure CycloneDX 1.5 JSON document to stdout."""
    result = runner.invoke(app, ["scan", str(seeded_cli_env), "--format", "cyclonedx", "--no-ai"])
    assert result.exit_code == CLIExitCode.SUCCESS

    doc = json.loads(result.stdout)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert any(c["name"] == "requests" for c in doc["components"])


@pytest.mark.asyncio
async def test_cli_scan_spdx_format(seeded_cli_env: Path) -> None:
    """Verify --format spdx outputs pure SPDX 2.3 JSON document to stdout."""
    result = runner.invoke(app, ["scan", str(seeded_cli_env), "--format", "spdx", "--no-ai"])
    assert result.exit_code == CLIExitCode.SUCCESS

    doc = json.loads(result.stdout)
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert any(p["name"] == "requests" for p in doc["packages"])


@pytest.mark.asyncio
async def test_cli_scan_export_with_output_file(seeded_cli_env: Path, tmp_path: Path) -> None:
    """Verify --output writes atomically to disk for all 3 formats."""
    sarif_file = tmp_path / "results.sarif"
    res_sarif = runner.invoke(
        app,
        ["scan", str(seeded_cli_env), "--format", "sarif", "--output", str(sarif_file), "--no-ai"],
    )
    assert res_sarif.exit_code == CLIExitCode.SUCCESS
    assert sarif_file.exists()
    assert json.loads(sarif_file.read_text())["version"] == "2.1.0"

    cdx_file = tmp_path / "sbom.cdx.json"
    res_cdx = runner.invoke(
        app,
        [
            "scan",
            str(seeded_cli_env),
            "--format",
            "cyclonedx",
            "--output",
            str(cdx_file),
            "--no-ai",
        ],
    )
    assert res_cdx.exit_code == CLIExitCode.SUCCESS
    assert cdx_file.exists()
    assert json.loads(cdx_file.read_text())["bomFormat"] == "CycloneDX"

    spdx_file = tmp_path / "sbom.spdx.json"
    res_spdx = runner.invoke(
        app,
        ["scan", str(seeded_cli_env), "--format", "spdx", "--output", str(spdx_file), "--no-ai"],
    )
    assert res_spdx.exit_code == CLIExitCode.SUCCESS
    assert spdx_file.exists()
    assert json.loads(spdx_file.read_text())["spdxVersion"] == "SPDX-2.3"


@pytest.mark.asyncio
async def test_cli_scan_export_with_policy_violation(seeded_cli_env: Path) -> None:
    """Verify machine-readable format outputs valid document even when exit code is 1 (--fail-on)."""
    result = runner.invoke(
        app,
        ["scan", str(seeded_cli_env), "--format", "sarif", "--fail-on", "high", "--no-ai"],
    )
    # Threshold is violated (HIGH vulnerability present)
    assert result.exit_code == CLIExitCode.THRESHOLD_VIOLATED
    # Valid SARIF must still be output to stdout
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"
