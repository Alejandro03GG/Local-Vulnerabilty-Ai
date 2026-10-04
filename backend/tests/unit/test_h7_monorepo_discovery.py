"""H7: safe recursive monorepo discovery."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.scanners.discovery import discover_project_roots
from vuln_ai.scanners.npm_scanner import NpmLockScanner
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry


def _write(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_discover_python_npm_monorepo(tmp_path: Path):
    _write(tmp_path / "services" / "api" / "requirements.txt", "flask==3.0.0\n")
    _write(
        tmp_path / "apps" / "web" / "package-lock.json",
        '{"lockfileVersion": 2, "packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}}\n',
    )
    roots = discover_project_roots(tmp_path)
    rel = {str(r.relative_to(tmp_path)) for r in roots if r != tmp_path.resolve()}
    assert "services/api" in rel or any(p.name == "api" for p in roots)
    assert "apps/web" in rel or any(p.name == "web" for p in roots)


def test_discover_excludes_node_modules_and_venv(tmp_path: Path):
    _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
    _write(tmp_path / "node_modules" / "evil" / "package.json", "{}\n")
    _write(tmp_path / ".venv" / "lib" / "requirements.txt", "secret==1.0\n")
    _write(tmp_path / "target" / "debug" / "Cargo.toml", "[package]\nname=\"x\"\n")
    roots = discover_project_roots(tmp_path)
    root_names = {r.name for r in roots}
    assert "node_modules" not in root_names
    assert ".venv" not in root_names
    assert "target" not in root_names
    assert "evil" not in root_names


def test_discover_skips_symlinks(tmp_path: Path):
    real = tmp_path / "real"
    _write(real / "requirements.txt", "a==1\n")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        return  # platform may block symlinks
    roots = discover_project_roots(tmp_path)
    # Symlink directories must not be entered as discovery roots.
    assert link.resolve() not in {r.resolve() for r in roots if r.name == "link"}
    assert all(not r.is_symlink() for r in roots)
    assert any(r.name == "real" for r in roots)


def test_scan_graph_python_npm(tmp_path: Path):
    _write(tmp_path / "backend" / "requirements.txt", "requests==2.31.0\n")
    _write(
        tmp_path / "frontend" / "package-lock.json",
        '{"lockfileVersion": 2, "packages": {"": {}, "node_modules/ms": {"version": "2.1.3"}}}\n',
    )
    registry = ScannerRegistry()
    registry.register(PythonScanner())
    registry.register(NpmLockScanner())
    comps = registry.scan_all(tmp_path)
    names = {c.name for c in comps}
    assert "requests" in names
    assert "ms" in names
    # provenance preserved
    by_name = {c.name: c for c in comps}
    assert "backend" in by_name["requests"].source_file or by_name["requests"].source_file.endswith(
        "requirements.txt"
    )


def test_scan_graph_multiple_same_ecosystem(tmp_path: Path):
    _write(tmp_path / "svc-a" / "requirements.txt", "django==4.2.0\n")
    _write(tmp_path / "svc-b" / "requirements.txt", "flask==3.0.0\n")
    registry = ScannerRegistry()
    registry.register(PythonScanner())
    comps = registry.scan_all(tmp_path)
    names = {c.name for c in comps}
    assert "django" in names
    assert "flask" in names
