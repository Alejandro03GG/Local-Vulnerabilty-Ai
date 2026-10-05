"""H22: CLI/API policy evaluation must persist policies for GET /policies."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typer.testing import CliRunner

from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.main import app
from vuln_ai.config import Settings
from vuln_ai.db.database import close_db, get_session_factory, init_db
from vuln_ai.db.models import ScanDB
from vuln_ai.db.repositories import PolicyRepository, ProjectRepository, ScanRepository
from vuln_ai.policy.service import PolicyService, get_default_policy

runner = CliRunner()


async def test_h22_ensure_persisted_upserts_by_name(db_session: AsyncSession) -> None:
    svc = PolicyService(db_session)
    first = await svc.ensure_persisted(get_default_policy(), source="default")
    second = await svc.ensure_persisted(get_default_policy(), source="default")
    assert first.id == second.id
    rows = await PolicyRepository(db_session).list_all()
    assert len(rows) == 1
    assert rows[0].name == "default-baseline-policy"


@pytest.mark.asyncio
async def test_h22_cli_scan_persists_policy_and_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    await close_db()
    db_file = tmp_path / "h22_cli.db"
    settings = Settings(database={"url": f"sqlite+aiosqlite:///{db_file}", "echo": False})
    await init_db(settings)
    monkeypatch.setattr("vuln_ai.cli.commands.scan.get_settings", lambda: settings)

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("safe-pkg==1.0.0\n")
    (project / ".vuln-ai.yaml").write_text(
        'version: "1"\n'
        "policy:\n"
        '  name: "h22-cli-policy"\n'
        "  thresholds:\n"
        "    fail_on: []\n"
        "  rules: []\n"
        '  default_action: "ALLOW"\n'
    )

    result = runner.invoke(app, ["scan", str(project), "--format", "json", "--no-ai"])
    assert result.exit_code == CLIExitCode.SUCCESS, result.output

    factory = get_session_factory(settings)
    async with factory() as session:
        policies = await PolicyRepository(session).list_all()
        assert any(p.name == "h22-cli-policy" for p in policies)
        scans = list((await session.execute(select(ScanDB))).scalars().all())
        assert len(scans) == 1
        evaluation = await PolicyRepository(session).get_evaluation_by_scan_id(scans[0].id)
        assert evaluation is not None
        assert evaluation.policy_name == "h22-cli-policy"
        assert evaluation.has_violations is False
        assert evaluation.ci_exit_code == 0

    await close_db()


async def test_h22_evaluate_scan_persists_policy_for_api(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    projects = ProjectRepository(db_session)
    project = await projects.create(name="p", path=str(tmp_path), description="")
    scans = ScanRepository(db_session)
    scan = await scans.create(project_id=project.id)
    await scans.complete(
        scan.id,
        components_found=0,
        vulnerabilities_found=0,
        kev_matches=0,
        duration_seconds=0.01,
    )

    svc = PolicyService(db_session)
    result = await svc.evaluate_scan(scan.id)
    assert result.policy_name == "default-baseline-policy"
    assert result.violations_count == 0
    policies = await PolicyRepository(db_session).list_all()
    assert any(p.name == "default-baseline-policy" for p in policies)
    evaluation = await PolicyRepository(db_session).get_evaluation_by_scan_id(scan.id)
    assert evaluation is not None


async def test_h22_get_policies_api_lists_persisted(api_client, db_session: AsyncSession) -> None:
    await PolicyService(db_session).ensure_persisted(get_default_policy(), source="default")
    resp = await api_client.get("/api/v1/policies")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert any(p["name"] == "default-baseline-policy" for p in body)
