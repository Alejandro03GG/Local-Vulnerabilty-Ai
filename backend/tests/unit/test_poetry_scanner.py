"""Unit tests for PoetryLockScanner."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.core.graph import DependencyScope, DependencyType
from vuln_ai.scanners.poetry_scanner import PoetryLockScanner


def test_poetry_scanner_can_scan(tmp_path: Path):
    scanner = PoetryLockScanner()
    assert not scanner.can_scan(tmp_path)

    (tmp_path / "poetry.lock").write_text("", encoding="utf-8")
    assert scanner.can_scan(tmp_path)


def test_poetry_scanner_parses_dependencies():
    scanner = PoetryLockScanner()
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_poetry"

    graph = scanner.scan_graph(fixtures_dir)
    assert "poetry.lock" in graph.lockfiles_detected
    assert "pyproject.toml" in graph.manifests_detected

    # fastapi is direct
    fastapi_node = graph.get_node("fastapi")
    assert fastapi_node is not None
    assert fastapi_node.version == "0.115.6"
    assert fastapi_node.is_direct is True
    assert fastapi_node.dependency_type == DependencyType.DIRECT

    # starlette is transitive (via fastapi)
    starlette_node = graph.get_node("starlette")
    assert starlette_node is not None
    assert starlette_node.version == "0.41.3"
    assert starlette_node.is_direct is False
    assert starlette_node.dependency_type == DependencyType.TRANSITIVE

    # anyio is transitive (via starlette)
    anyio_node = graph.get_node("anyio")
    assert anyio_node is not None
    assert anyio_node.version == "4.4.0"
    assert anyio_node.is_direct is False

    # pytest is in dev group
    pytest_node = graph.get_node("pytest")
    assert pytest_node is not None
    assert pytest_node.scope == DependencyScope.DEV

    # Test path reconstruction
    components = graph.resolve_components()
    comp_by_name = {c.name: c for c in components}

    assert comp_by_name["fastapi"].is_direct is True
    assert comp_by_name["fastapi"].dependency_path == ["fastapi"]

    assert comp_by_name["starlette"].is_direct is False
    assert comp_by_name["starlette"].parent_name == "fastapi"
    assert comp_by_name["starlette"].dependency_path == ["fastapi", "starlette"]

    assert comp_by_name["anyio"].is_direct is False
    assert comp_by_name["anyio"].dependency_path == ["fastapi", "starlette", "anyio"]


def test_poetry_scanner_missing_pyproject(tmp_path: Path):
    """When pyproject.toml is missing, roots with no incoming edges are treated as direct."""
    lock_content = """
[[package]]
name = "parent-pkg"
version = "1.0.0"

[package.dependencies]
child-pkg = ">=1.0.0"

[[package]]
name = "child-pkg"
version = "2.0.0"
"""
    (tmp_path / "poetry.lock").write_text(lock_content, encoding="utf-8")
    scanner = PoetryLockScanner()

    graph = scanner.scan_graph(tmp_path)
    parent = graph.get_node("parent-pkg")
    child = graph.get_node("child-pkg")

    assert parent is not None and parent.is_direct is True
    assert child is not None and child.is_direct is False


def test_poetry_scanner_corrupt_file(tmp_path: Path):
    (tmp_path / "poetry.lock").write_text("NOT A VALID TOML [[[ ]", encoding="utf-8")
    scanner = PoetryLockScanner()

    components = scanner.scan(tmp_path)
    assert components == []


def test_poetry_scanner_empty_file(tmp_path: Path):
    (tmp_path / "poetry.lock").write_text("", encoding="utf-8")
    scanner = PoetryLockScanner()

    components = scanner.scan(tmp_path)
    assert components == []


def test_poetry_scanner_oversized_file(tmp_path: Path, monkeypatch):
    from vuln_ai.scanners import poetry_scanner

    monkeypatch.setattr(poetry_scanner, "_MAX_LOCKFILE_SIZE", 10)
    (tmp_path / "poetry.lock").write_text(
        "[[package]]\nname='foo'\nversion='1.0'", encoding="utf-8"
    )
    scanner = PoetryLockScanner()
    graph = scanner.scan_graph(tmp_path)
    assert len(graph.nodes) == 0


def test_poetry_scanner_dict_deps_and_markers(tmp_path: Path):
    lock_content = """
[[package]]
name = "complex-parent"
version = "1.0.0"

[package.dependencies]
child-dict = { version = ">=2.0.0", markers = "python_version >= '3.10'" }

[[package]]
name = "child-dict"
version = "2.1.0"
files = [
    {file = "child-dict-2.1.0.whl", hash = "sha256:123456"}
]
"""
    (tmp_path / "poetry.lock").write_text(lock_content, encoding="utf-8")
    scanner = PoetryLockScanner()
    graph = scanner.scan_graph(tmp_path)

    assert len(graph.nodes) == 2
    child = graph.get_node("child-dict")
    assert child is not None
    assert child.metadata.get("files_count") == 1


def test_poetry_scanner_pyproject_groups_and_pep621(tmp_path: Path):
    pyproject_toml = """
[project]
dependencies = [
    "requests>=2.28.0",
    "flask==3.0.0; python_version >= '3.10'",
]

[tool.poetry.dev-dependencies]
flake8 = "^6.0.0"

[tool.poetry.group.docs.dependencies]
sphinx = "^7.0.0"
"""
    lock_toml = """
[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "flask"
version = "3.0.0"

[[package]]
name = "flake8"
version = "6.0.0"

[[package]]
name = "sphinx"
version = "7.0.0"
"""
    (tmp_path / "pyproject.toml").write_text(pyproject_toml, encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(lock_toml, encoding="utf-8")

    scanner = PoetryLockScanner()
    graph = scanner.scan_graph(tmp_path)

    assert len(graph.nodes) == 4
    req = graph.get_node("requests")
    assert req is not None and req.is_direct is True
    flk = graph.get_node("flake8")
    assert flk is not None and flk.scope == DependencyScope.DEV
    sph = graph.get_node("sphinx")
    assert sph is not None and sph.is_direct is True


def test_poetry_scanner_corrupt_pyproject(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[[ BAD TOML ]", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(
        "[[package]]\nname='foo'\nversion='1.0'\n", encoding="utf-8"
    )

    scanner = PoetryLockScanner()
    graph = scanner.scan_graph(tmp_path)
    assert len(graph.nodes) == 1
