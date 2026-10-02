"""Extended unit tests for PythonScanner edge cases and error handling."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from vuln_ai.scanners.python_scanner import PythonScanner


def test_scanner_metadata():
    """Verify name and ecosystem metadata properties."""
    scanner = PythonScanner()
    assert scanner.name == "Python Scanner"
    assert scanner.ecosystem == "pypi"


def test_requirements_file_read_error(tmp_path: Path):
    """Gracefully handle unreadable requirements.txt file."""
    scanner = PythonScanner()
    req_file = tmp_path / "requirements.txt"
    req_file.touch()

    with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
        components = scanner._parse_requirements(req_file)
        assert components == []


def test_pyproject_file_read_error(tmp_path: Path):
    """Gracefully handle unreadable pyproject.toml file."""
    scanner = PythonScanner()
    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.touch()

    with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
        components = scanner._parse_pyproject(pyproject_file)
        assert components == []


def test_pyproject_invalid_toml_syntax(tmp_path: Path):
    """Gracefully handle malformed pyproject.toml syntax."""
    scanner = PythonScanner()
    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text("invalid [ [ [ toml syntax :::")

    components = scanner._parse_pyproject(pyproject_file)
    assert components == []


def test_scan_aggregates_both_requirements_and_pyproject(tmp_path: Path):
    """scan() combines components from both requirements.txt and pyproject.toml."""
    scanner = PythonScanner()

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test"\ndependencies = ["urllib3>=2.0.0"]\n'
    )

    components = scanner.scan(tmp_path)
    names = {c.name for c in components}
    assert "requests" in names
    assert "urllib3" in names
    assert len(components) == 2
