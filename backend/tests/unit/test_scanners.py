"""Tests for the Python scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_ai.core.models import Ecosystem, VersionType
from vuln_ai.scanners.python_scanner import PythonScanner


@pytest.fixture
def scanner() -> PythonScanner:
    return PythonScanner()


class TestPythonScannerCanScan:
    """Tests for can_scan detection."""

    def test_can_scan_with_requirements(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("django==4.2\n")
        assert scanner.can_scan(tmp_path) is True

    def test_can_scan_with_pyproject(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
        assert scanner.can_scan(tmp_path) is True

    def test_cannot_scan_empty_dir(self, tmp_path: Path, scanner: PythonScanner):
        assert scanner.can_scan(tmp_path) is False

    def test_cannot_scan_node_project(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "package.json").write_text("{}")
        assert scanner.can_scan(tmp_path) is False


class TestRequirementsParsing:
    """Tests for requirements.txt parsing."""

    def test_exact_version(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("django==4.2.11\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1
        assert components[0].name == "django"
        assert components[0].version == "4.2.11"
        assert components[0].version_type == VersionType.EXACT
        assert components[0].ecosystem == Ecosystem.PYPI

    def test_range_version(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("pydantic>=2.0,<3.0\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1
        assert components[0].name == "pydantic"
        assert components[0].version is None
        assert components[0].version_type == VersionType.RANGE
        assert components[0].version_constraint == ">=2.0,<3.0"

    def test_minimum_version(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("sqlalchemy>=2.0\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1
        assert components[0].version_type == VersionType.MINIMUM

    def test_no_version(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("numpy\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1
        assert components[0].name == "numpy"
        assert components[0].version is None
        assert components[0].version_type == VersionType.UNKNOWN

    def test_skip_comments(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("# this is a comment\ndjango==4.2\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1

    def test_skip_empty_lines(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("\n\ndjango==4.2\n\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1

    def test_skip_options(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text(
            "-r base.txt\n--index-url https://pypi.org\ndjango==4.2\n"
        )
        components = scanner.scan(tmp_path)
        assert len(components) == 1

    def test_skip_url_dependencies(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text(
            "git+https://github.com/user/repo.git\ndjango==4.2\n"
        )
        components = scanner.scan(tmp_path)
        assert len(components) == 1

    def test_environment_markers(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text('colorama==0.4.6; sys_platform == "win32"\n')
        components = scanner.scan(tmp_path)
        assert len(components) == 1
        assert components[0].name == "colorama"
        assert components[0].version == "0.4.6"

    def test_inline_comments(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("django==4.2 # web framework\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1
        assert components[0].name == "django"

    def test_extras(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("sqlalchemy[asyncio]>=2.0\n")
        components = scanner.scan(tmp_path)
        assert len(components) == 1
        assert components[0].name == "sqlalchemy"

    def test_multiple_packages(self, tmp_path: Path, scanner: PythonScanner):
        content = "django==4.2\nflask==3.0\nrequests==2.31\n"
        (tmp_path / "requirements.txt").write_text(content)
        components = scanner.scan(tmp_path)
        assert len(components) == 3
        names = {c.name for c in components}
        assert names == {"django", "flask", "requests"}

    def test_source_file_recorded(self, tmp_path: Path, scanner: PythonScanner):
        (tmp_path / "requirements.txt").write_text("django==4.2\n")
        components = scanner.scan(tmp_path)
        assert str(tmp_path / "requirements.txt") in components[0].source_file

    def test_sample_requirements_fixture(self, sample_project_dir: Path, scanner: PythonScanner):
        """Test parsing the full sample requirements.txt fixture."""
        req_file = sample_project_dir / "requirements.txt"
        components = scanner._parse_requirements(req_file)
        names = {c.name for c in components}
        # Should find these packages
        assert "fastapi" in names
        assert "requests" in names
        assert "django" in names
        assert "numpy" in names
        assert "flask" in names
        assert "colorama" in names
        # Should NOT find comments, -r, or URL deps
        assert "base.txt" not in names


class TestPyprojectParsing:
    """Tests for pyproject.toml parsing."""

    def test_pep621_dependencies(self, tmp_path: Path, scanner: PythonScanner):
        content = """
[project]
name = "test"
dependencies = [
    "django==4.2",
    "flask>=3.0",
]
"""
        (tmp_path / "pyproject.toml").write_text(content)
        components = scanner.scan(tmp_path)
        names = {c.name for c in components}
        assert "django" in names
        assert "flask" in names

    def test_optional_dependencies(self, tmp_path: Path, scanner: PythonScanner):
        content = """
[project]
name = "test"
dependencies = ["django==4.2"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]
"""
        (tmp_path / "pyproject.toml").write_text(content)
        components = scanner.scan(tmp_path)
        names = {c.name for c in components}
        assert "django" in names
        assert "pytest" in names

    def test_no_project_section(self, tmp_path: Path, scanner: PythonScanner):
        content = """
[build-system]
requires = ["hatchling"]
"""
        (tmp_path / "pyproject.toml").write_text(content)
        components = scanner.scan(tmp_path)
        assert len(components) == 0

    def test_sample_pyproject_fixture(self, sample_project_dir: Path, scanner: PythonScanner):
        """Test parsing the full sample pyproject.toml fixture."""
        pyproject_file = sample_project_dir / "pyproject.toml"
        components = scanner._parse_pyproject(pyproject_file)
        names = {c.name for c in components}
        assert "django" in names
        assert "fastapi" in names
        assert "httpx" in names
        assert "pydantic" in names
        assert "pytest" in names
        assert "ruff" in names
        assert "cryptography" in names
