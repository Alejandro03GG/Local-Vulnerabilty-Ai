"""Tests for 'vuln-ai scan' command execution, options, and exit codes."""

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


def test_scan_nonexistent_path(tmp_path: Path) -> None:
    """Verify that scanning a nonexistent path fails with exit code 2."""
    bad_path = tmp_path / "does_not_exist"
    result = runner.invoke(app, ["scan", str(bad_path)])
    assert result.exit_code == CLIExitCode.USAGE_ERROR
    assert "does not exist" in result.output


def test_scan_path_is_file(tmp_path: Path) -> None:
    """Verify that passing a file instead of a directory fails with exit code 2."""
    dummy_file = tmp_path / "requirements.txt"
    dummy_file.write_text("requests==2.31.0\n")
    result = runner.invoke(app, ["scan", str(dummy_file)])
    assert result.exit_code == CLIExitCode.USAGE_ERROR
    assert "is not a directory" in result.output


def test_scan_invalid_format(tmp_path: Path) -> None:
    """Verify that invalid --format values fail with exit code 2."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "yaml"])
    assert result.exit_code == CLIExitCode.USAGE_ERROR
    assert "Invalid --format" in result.output


def test_scan_invalid_fail_on(tmp_path: Path) -> None:
    """Verify that invalid --fail-on values fail with exit code 2."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "supercritical"])
    assert result.exit_code == CLIExitCode.USAGE_ERROR
    assert "Invalid --fail-on" in result.output


@pytest.mark.asyncio
async def test_scan_empty_project_table_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify clean scan on a project with no dependencies outputs table and exits 0."""
    await close_db()
    db_file = tmp_path / "test_cli.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    proj_dir = tmp_path / "my_project"
    proj_dir.mkdir()

    result = runner.invoke(app, ["scan", str(proj_dir), "--no-ai"])
    assert result.exit_code == CLIExitCode.SUCCESS
    assert "Local Vulnerability AI" in result.stdout
    assert "No vulnerability matches found" in result.stdout


@pytest.mark.asyncio
async def test_scan_json_format_and_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify --format json produces machine-readable JSON and writes to --output file."""
    await close_db()
    db_file = tmp_path / "test_cli_json.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    proj_dir = tmp_path / "test_proj"
    proj_dir.mkdir()
    (proj_dir / "requirements.txt").write_text("fastapi==0.115.0\n")

    report_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", str(proj_dir), "--format", "json", "--output", str(report_file), "--no-ai"],
    )
    assert result.exit_code == CLIExitCode.SUCCESS

    # Verify stdout is valid JSON
    data = json.loads(result.stdout)
    assert data["project_name"] == "test_proj"
    assert data["scan_status"] == "completed"
    assert data["summary"]["components_found"] == 1
    assert data["summary"]["matches_found"] == 0

    # Verify report file was written
    assert report_file.exists()
    file_data = json.loads(report_file.read_text())
    assert file_data["project_name"] == "test_proj"


@pytest.mark.asyncio
async def test_scan_with_findings_and_fail_on_thresholds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that --fail-on flags correctly return exit code 1 on threshold violations."""
    await close_db()
    db_file = tmp_path / "test_cli_vulns.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    # Seed database with source and high severity vulnerability
    factory = get_session_factory(settings)
    async with factory() as session:
        src_repo = SourceRepository(session)
        vuln_repo = VulnerabilityRepository(session)

        src, _ = await src_repo.get_or_create(
            name="OSV",
            source_type="osv",
            url="https://api.osv.dev",
        )

        vuln_record = VulnerabilityRecord(
            cve_id="CVE-2023-45803",
            source_name="OSV",
            vendor_project="urllib3",
            product="urllib3",
            vulnerability_name="urllib3 request body leakage",
            short_description="High severity leak in urllib3",
            severity="HIGH",
            cvss_score=7.5,
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem=Ecosystem.PYPI,
                    package_name="urllib3",
                    introduced="2.0.0",
                    fixed="2.0.7",
                )
            ],
        )
        await vuln_repo.upsert_vulnerabilities(src.id, [vuln_record])
        await session.commit()

    # Create project using vulnerable version of urllib3
    proj_dir = tmp_path / "vuln_project"
    proj_dir.mkdir()
    (proj_dir / "requirements.txt").write_text("urllib3==2.0.5\n")

    # 1. Default (fail-on none) -> should succeed with exit code 0
    res_none = runner.invoke(app, ["scan", str(proj_dir), "--no-ai", "--format", "json"])
    assert res_none.exit_code == CLIExitCode.SUCCESS
    data_none = json.loads(res_none.stdout)
    assert data_none["summary"]["matches_found"] == 1
    assert data_none["matches"][0]["risk_level"] == "high"

    # 2. --fail-on low -> should fail (exit code 1) because HIGH >= LOW
    res_low = runner.invoke(app, ["scan", str(proj_dir), "--no-ai", "--fail-on", "low"])
    assert res_low.exit_code == CLIExitCode.THRESHOLD_VIOLATED

    # 3. --fail-on high -> should fail (exit code 1) because HIGH >= HIGH
    res_high = runner.invoke(app, ["scan", str(proj_dir), "--no-ai", "--fail-on", "high"])
    assert res_high.exit_code == CLIExitCode.THRESHOLD_VIOLATED

    # 4. --fail-on critical -> should PASS (exit code 0) because HIGH < CRITICAL
    res_crit = runner.invoke(app, ["scan", str(proj_dir), "--no-ai", "--fail-on", "critical"])
    assert res_crit.exit_code == CLIExitCode.SUCCESS

    # 5. --fail-on-review -> returns THRESHOLD_VIOLATED (code 1) because conservative AI fallback mandates human review
    res_rev_fail = runner.invoke(app, ["scan", str(proj_dir), "--no-ai", "--fail-on-review"])
    assert res_rev_fail.exit_code == CLIExitCode.THRESHOLD_VIOLATED


@pytest.mark.asyncio
async def test_scan_missing_db_schema_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that uninitialized database returns USAGE_ERROR with clear instructions."""
    await close_db()
    db_file = tmp_path / "empty_db.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    # Do NOT call init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    proj_dir = tmp_path / "proj"
    proj_dir.mkdir()

    result = runner.invoke(app, ["scan", str(proj_dir)])
    assert result.exit_code == CLIExitCode.USAGE_ERROR
    assert "alembic upgrade head" in result.output


@pytest.mark.asyncio
async def test_scan_table_format_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify --format table with --output writes text export to file."""
    await close_db()
    db_file = tmp_path / "table_out.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    proj_dir = tmp_path / "table_proj"
    proj_dir.mkdir()
    (proj_dir / "requirements.txt").write_text("fastapi==0.115.0\n")

    report_file = tmp_path / "report.txt"
    result = runner.invoke(app, ["scan", str(proj_dir), "--output", str(report_file), "--no-ai"])
    assert result.exit_code == CLIExitCode.SUCCESS
    assert report_file.exists()
    assert "Local Vulnerability AI" in report_file.read_text()


@pytest.mark.asyncio
async def test_scan_engine_internal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify scan returns INTERNAL_ERROR when engine fails or raises exception."""
    from unittest.mock import patch

    await close_db()
    db_file = tmp_path / "fail_test.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    proj_dir = tmp_path / "fail_proj"
    proj_dir.mkdir()

    with patch(
        "vuln_ai.core.engine.ScanEngine.scan", side_effect=RuntimeError("disk I/O failure")
    ):
        result = runner.invoke(app, ["scan", str(proj_dir), "--no-ai"])
        assert result.exit_code == CLIExitCode.INTERNAL_ERROR
        assert "Internal scan error" in result.output


@pytest.mark.asyncio
async def test_scan_lockfile_with_dependency_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify CLI scan output presents dependency graph metrics and table columns."""
    await close_db()
    db_file = tmp_path / "dep_metrics.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)

    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    fixtures_poetry = Path(__file__).parent.parent / "fixtures" / "sample_poetry"
    result = runner.invoke(app, ["scan", str(fixtures_poetry), "--no-ai"])
    assert result.exit_code == CLIExitCode.SUCCESS
    assert "1 direct, 6 transitive" in result.output
    assert "Edges: 5" in result.output
    assert "Lockfiles:" in result.output
    assert "poetry.lock" in result.output

    # Also test JSON format includes dependency metrics
    json_result = runner.invoke(app, ["scan", str(fixtures_poetry), "--no-ai", "--format", "json"])
    assert json_result.exit_code == CLIExitCode.SUCCESS
    data = json.loads(json_result.output)
    assert "direct_components" in data["summary"]
    assert "transitive_components" in data["summary"]
    assert "dependency_edges" in data["summary"]
    assert "lockfiles_detected" in data["summary"]
    assert data["summary"]["direct_components"] == 1
    assert data["summary"]["transitive_components"] == 6
