"""Integration tests for Container CLI commands (vuln-ai image scan)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from tests.fixtures.container_fixtures import create_docker_image_archive
from vuln_ai.cli.main import app

runner = CliRunner()


def test_cli_image_scan_table(tmp_path: Path):
    """Test CLI image scan output in default table format."""
    archive_path = tmp_path / "cli_test_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="cli-test:latest",
        dpkg_status="Package: zlib1g\nVersion: 1:1.2.13.dfsg-1\nStatus: install ok installed\n",
    )

    result = runner.invoke(app, ["image", "scan", str(archive_path), "--no-ai"])
    assert result.exit_code == 0
    assert "Container Image Inspection" in result.output
    assert "cli-test:latest" in result.output


def test_cli_image_scan_json(tmp_path: Path):
    """Test CLI image scan output in json format."""
    archive_path = tmp_path / "cli_test_image_json.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="cli-test-json:latest",
        dpkg_status="Package: curl\nVersion: 7.88.1-10\nStatus: install ok installed\n",
    )

    result = runner.invoke(
        app, ["image", "scan", str(archive_path), "--format", "json", "--no-ai"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["components_found"] >= 1


def test_cli_image_scan_sarif_and_cyclonedx(tmp_path: Path):
    """Test CLI image scan output in sarif and cyclonedx formats."""
    archive_path = tmp_path / "cli_test_export.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="cli-export:latest",
        dpkg_status="Package: curl\nVersion: 7.88.1-10\nStatus: install ok installed\n",
    )

    # SARIF
    sarif_file = tmp_path / "out.sarif"
    sarif_res = runner.invoke(
        app,
        [
            "image",
            "scan",
            str(archive_path),
            "--format",
            "sarif",
            "--output",
            str(sarif_file),
            "--no-ai",
        ],
    )
    assert sarif_res.exit_code == 0
    assert sarif_file.is_file()
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"

    # CycloneDX
    cdx_file = tmp_path / "out_cdx.json"
    cdx_res = runner.invoke(
        app,
        [
            "image",
            "scan",
            str(archive_path),
            "--format",
            "cyclonedx",
            "--output",
            str(cdx_file),
            "--no-ai",
        ],
    )
    assert cdx_res.exit_code == 0
    assert cdx_file.is_file()
    cdx_data = json.loads(cdx_file.read_text(encoding="utf-8"))
    assert cdx_data["bomFormat"] == "CycloneDX"


def test_cli_dockerfile_scan(tmp_path: Path):
    """Test CLI scanning a Dockerfile."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:3.19\nRUN apk add curl\n", encoding="utf-8")

    result = runner.invoke(app, ["image", "scan", str(dockerfile)])
    assert result.exit_code == 0
    assert "Dockerfile Static Inspection" in result.output
    assert "curl" in result.output


def test_cli_image_scan_invalid_format_and_missing_file():
    """Verify exit code 2 on invalid format or missing target."""
    res1 = runner.invoke(app, ["image", "scan", "nonexistent.tar", "--format", "xml"])
    assert res1.exit_code == 2

    res2 = runner.invoke(app, ["image", "scan", "nonexistent.tar"])
    assert res2.exit_code == 2


def test_cli_dockerfile_scan_json_and_output(tmp_path: Path):
    """Test CLI scanning a Dockerfile with JSON output and file saving."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\nRUN pip install requests\n", encoding="utf-8")
    out_json = tmp_path / "dockerfile.json"

    result = runner.invoke(
        app, ["image", "scan", str(dockerfile), "--format", "json", "--output", str(out_json)]
    )
    assert result.exit_code == 0
    assert out_json.is_file()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert "package_installations" in data


def test_cli_image_scan_with_policy_and_missing_policy(tmp_path: Path):
    """Test CLI scanning with explicit policy and missing policy error."""
    archive_path = tmp_path / "policy_img.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="policy-img:latest",
        dpkg_status="Package: curl\nVersion: 7.88.1\nStatus: install ok installed\n",
    )

    # Missing policy
    res_miss = runner.invoke(
        app, ["image", "scan", str(archive_path), "--policy", "nonexistent.yaml", "--no-ai"]
    )
    assert res_miss.exit_code == 2

    # Valid policy file
    pol_file = tmp_path / "policy.yaml"
    pol_file.write_text(
        """name: test-policy
thresholds:
  fail_on:
    - CRITICAL
""",
        encoding="utf-8",
    )

    res_ok = runner.invoke(
        app,
        [
            "image",
            "scan",
            str(archive_path),
            "--policy",
            str(pol_file),
            "--fail-on",
            "HIGH",
            "--show-suppressions",
            "--no-ai",
        ],
    )
    assert res_ok.exit_code == 0
