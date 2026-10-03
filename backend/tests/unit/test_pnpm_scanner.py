"""Unit tests for PnpmLockScanner."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.core.graph import DependencyType
from vuln_ai.scanners.pnpm_scanner import PnpmLockScanner


def test_pnpm_scanner_can_scan(tmp_path: Path):
    scanner = PnpmLockScanner()
    assert not scanner.can_scan(tmp_path)

    (tmp_path / "pnpm-lock.yaml").write_text("", encoding="utf-8")
    assert scanner.can_scan(tmp_path)


def test_pnpm_scanner_parses_dependencies():
    scanner = PnpmLockScanner()
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_pnpm"

    graph = scanner.scan_graph(fixtures_dir)
    assert "pnpm-lock.yaml" in graph.lockfiles_detected
    assert "package.json" in graph.manifests_detected

    # axios is direct
    axios_node = graph.get_node("axios")
    assert axios_node is not None
    assert axios_node.version == "1.7.2"
    assert axios_node.is_direct is True
    assert axios_node.dependency_type == DependencyType.DIRECT

    # follow-redirects is transitive
    fr_node = graph.get_node("follow-redirects")
    assert fr_node is not None
    assert fr_node.version == "1.15.6"
    assert fr_node.is_direct is False
    assert fr_node.dependency_type == DependencyType.TRANSITIVE

    # form-data is transitive
    fd_node = graph.get_node("form-data")
    assert fd_node is not None
    assert fd_node.version == "4.0.0"
    assert fd_node.is_direct is False

    # Check path resolution
    components = graph.resolve_components()
    comp_map = {c.name: c for c in components}

    assert comp_map["axios"].is_direct is True
    assert comp_map["follow-redirects"].is_direct is False
    assert comp_map["follow-redirects"].parent_name == "axios"
    assert comp_map["follow-redirects"].dependency_path == ["axios", "follow-redirects"]


def test_pnpm_scanner_corrupt_file(tmp_path: Path):
    (tmp_path / "pnpm-lock.yaml").write_text(": : bad yaml [", encoding="utf-8")
    scanner = PnpmLockScanner()
    components = scanner.scan(tmp_path)
    assert components == []


def test_pnpm_scanner_empty_file(tmp_path: Path):
    (tmp_path / "pnpm-lock.yaml").write_text("", encoding="utf-8")
    scanner = PnpmLockScanner()
    components = scanner.scan(tmp_path)
    assert components == []


def test_pnpm_scanner_oversized_file(tmp_path: Path, monkeypatch):
    from vuln_ai.scanners import pnpm_scanner

    monkeypatch.setattr(pnpm_scanner, "_MAX_LOCKFILE_SIZE", 10)
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: 5.4\npackages: {}\n", encoding="utf-8"
    )
    scanner = PnpmLockScanner()
    graph = scanner.scan_graph(tmp_path)
    assert len(graph.nodes) == 0


def test_pnpm_scanner_v5_and_optional(tmp_path: Path):
    v5_yaml = """
lockfileVersion: 5.4

dependencies:
  express: 4.18.2

devDependencies:
  mocha: 10.2.0

packages:
  /express/4.18.2:
    resolution: {integrity: sha512-test}
    optionalDependencies:
      debug: 2.6.9
    dev: false

  /mocha/10.2.0:
    resolution: {integrity: sha512-test}
    dev: true

  /debug/2.6.9:
    resolution: {integrity: sha512-test}
    dev: false
"""
    (tmp_path / "pnpm-lock.yaml").write_text(v5_yaml, encoding="utf-8")
    scanner = PnpmLockScanner()
    graph = scanner.scan_graph(tmp_path)

    assert len(graph.nodes) == 3
    exp = graph.get_node("express")
    assert exp is not None and exp.is_direct is True
    moc = graph.get_node("mocha")
    assert moc is not None and moc.is_direct is True and moc.scope == "dev"
    dbg = graph.get_node("debug")
    assert dbg is not None and dbg.is_direct is False

    # Check optional edge
    opt_edges = [e for e in graph.edges if e.child_name == "debug"]
    assert len(opt_edges) == 1
    assert opt_edges[0].scope == "optional"
