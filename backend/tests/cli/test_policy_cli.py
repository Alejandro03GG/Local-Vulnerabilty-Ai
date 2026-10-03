"""Tests for CLI policy and suppression commands (Etapa 16)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.main import app

runner = CliRunner()


def test_cli_policy_help():
    """Verify vuln-ai policy --help lists validate and check commands."""
    res = runner.invoke(app, ["policy", "--help"])
    assert res.exit_code == CLIExitCode.SUCCESS
    assert "validate" in res.stdout
    assert "check" in res.stdout


def test_cli_suppression_help():
    """Verify vuln-ai suppression --help lists list command."""
    res = runner.invoke(app, ["suppression", "--help"])
    assert res.exit_code == CLIExitCode.SUCCESS
    assert "list" in res.stdout


def test_cli_policy_validate_valid(tmp_path: Path):
    """Verify vuln-ai policy validate on valid policy file."""
    p_file = tmp_path / "valid_policy.yaml"
    p_file.write_text("""
version: "1"
policy:
  name: "valid-policy"
  thresholds:
    fail_on: ["HIGH"]
  rules:
    - id: "block-high"
      when:
        severity: "HIGH"
      action: "BLOCK"
""")
    res = runner.invoke(app, ["policy", "validate", str(p_file)])
    assert res.exit_code == CLIExitCode.SUCCESS
    assert "valid" in res.stdout.lower()


def test_cli_policy_validate_invalid(tmp_path: Path):
    """Verify vuln-ai policy validate on invalid policy file returns usage error."""
    p_file = tmp_path / "invalid_policy.yaml"
    p_file.write_text("invalid: yaml: [[")
    res = runner.invoke(app, ["policy", "validate", str(p_file)])
    assert res.exit_code == CLIExitCode.USAGE_ERROR


def test_cli_policy_validate_missing(tmp_path: Path):
    """Verify vuln-ai policy validate on nonexistent file returns usage error."""
    missing = tmp_path / "nonexistent.yaml"
    res = runner.invoke(app, ["policy", "validate", str(missing)])
    assert res.exit_code == CLIExitCode.USAGE_ERROR


def test_cli_policy_check(tmp_path: Path):
    """Verify vuln-ai policy check renders rules summary."""
    p_file = tmp_path / "check_policy.yaml"
    p_file.write_text("""
version: "1"
policy:
  name: "check-policy"
  rules:
    - id: "block-kev"
      when:
        has_kev_evidence: true
      action: "BLOCK"
""")
    res = runner.invoke(app, ["policy", "check", str(p_file)])
    assert res.exit_code == CLIExitCode.SUCCESS
    assert "check-policy" in res.stdout
    assert "block-kev" in res.stdout


@pytest.mark.asyncio
async def test_cli_suppression_list_with_data():
    """Verify vuln-ai suppression list renders table when suppressions exist."""
    from vuln_ai.config import get_settings
    from vuln_ai.db.database import get_session_factory
    from vuln_ai.db.repositories import SuppressionRepository
    from vuln_ai.policy.models import Suppression, SuppressionMatchCriteria

    settings = get_settings()
    factory = get_session_factory(settings)
    async with factory() as session:
        repo = SuppressionRepository(session)
        await repo.create(
            Suppression(
                reason="Temporary test exemption",
                owner="qa@test.com",
                reference="QA-100",
                match_criteria=SuppressionMatchCriteria(
                    package_name="test-pkg", vulnerability_id="CVE-2024-9999"
                ),
            )
        )
        await session.commit()

    res = runner.invoke(app, ["suppression", "list"])
    assert res.exit_code == CLIExitCode.SUCCESS
    assert "test-pkg" in res.stdout or "QA-100" in res.stdout

    res_json = runner.invoke(app, ["suppression", "list", "--json"])
    assert res_json.exit_code == CLIExitCode.SUCCESS
    data = json.loads(res_json.stdout)
    assert len(data) >= 1


def test_cli_policy_check_missing(tmp_path: Path):
    """Verify vuln-ai policy check on missing file."""
    res = runner.invoke(app, ["policy", "check", str(tmp_path / "missing.yaml")])
    assert res.exit_code == CLIExitCode.USAGE_ERROR


def test_cli_policy_check_invalid(tmp_path: Path):
    """Verify vuln-ai policy check on malformed file."""
    p = tmp_path / "bad.yaml"
    p.write_text("invalid: yaml: [[")
    res = runner.invoke(app, ["policy", "check", str(p)])
    assert res.exit_code == CLIExitCode.USAGE_ERROR


def test_cli_scan_flags(tmp_path: Path):
    """Verify vuln-ai scan with --no-policy, --show-suppressions, and missing policy file."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requests==2.25.0\n")

    # 1. --no-policy
    res_no_pol = runner.invoke(app, ["scan", str(proj), "--no-policy", "--no-ai"])
    assert res_no_pol.exit_code == CLIExitCode.SUCCESS

    # 2. --show-suppressions
    res_show = runner.invoke(app, ["scan", str(proj), "--show-suppressions", "--no-ai"])
    assert res_show.exit_code == CLIExitCode.SUCCESS

    # 3. Missing policy file -> USAGE_ERROR
    res_missing = runner.invoke(app, ["scan", str(proj), "--policy", str(tmp_path / "nope.yaml")])
    assert res_missing.exit_code == CLIExitCode.USAGE_ERROR


def test_cli_scan_with_policy_render_and_json(tmp_path: Path):
    """Verify vuln-ai scan with explicit policy renders compliance panel and handles json output."""
    proj = tmp_path / "proj_render"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requests==2.25.0\n")

    policy_file = tmp_path / "allow_policy.yaml"
    policy_file.write_text("""
version: "1"
policy:
  name: "allow-all-test"
  rules:
    - id: "allow-all"
      when:
        severity: "LOW"
      action: "ALLOW"
""")

    # Table format with --show-policy
    res_show = runner.invoke(
        app, ["scan", str(proj), "--policy", str(policy_file), "--show-policy", "--no-ai"]
    )
    assert res_show.exit_code == CLIExitCode.SUCCESS
    assert "Policy & Compliance Evaluation" in res_show.stdout

    # JSON format with --policy
    res_json = runner.invoke(
        app, ["scan", str(proj), "--policy", str(policy_file), "--format", "json", "--no-ai"]
    )
    assert res_json.exit_code == CLIExitCode.SUCCESS
    data = json.loads(res_json.stdout)
    assert "policyEvaluation" in data
    assert data["policyEvaluation"]["policy_name"] == "allow-all-test"


def test_render_policy_compliance_table_direct():
    """Directly test _render_policy_compliance_table with violations and applied suppressions."""
    from vuln_ai.cli.commands.scan import _render_policy_compliance_table
    from vuln_ai.policy.models import (
        FindingEvaluation,
        PolicyAction,
        PolicyEvaluationResult,
        PolicyStatus,
    )

    p_eval = PolicyEvaluationResult(
        policy_id="pol-1",
        policy_name="test-policy",
        total_findings=2,
        violations_count=1,
        suppressed_count=1,
        allowed_count=0,
        has_violations=True,
        violations=[
            FindingEvaluation(
                finding_id="f1",
                component_name="requests",
                component_version="2.25.0",
                ecosystem="pypi",
                vulnerability_id="CVE-2023-1111",
                action=PolicyAction.BLOCK,
                status=PolicyStatus.VIOLATION,
                matched_rules=["rule-1"],
                reason="Violation test",
                is_violation=True,
            )
        ],
        suppressions_applied=[
            {
                "suppression_id": "sup-12345678",
                "finding_id": "f2",
                "owner": "sec-team",
                "expires_at": "2027-01-01T00:00:00Z",
                "reason": "False positive",
            }
        ],
    )

    _render_policy_compliance_table(p_eval, show_suppressions=True)
