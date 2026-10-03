"""Unit tests for NpmLockScanner."""

from __future__ import annotations

import json
from pathlib import Path

from vuln_ai.core.graph import DependencyScope
from vuln_ai.scanners.npm_scanner import NpmLockScanner


def test_npm_scanner_can_scan(tmp_path: Path):
    scanner = NpmLockScanner()
    assert not scanner.can_scan(tmp_path)

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert scanner.can_scan(tmp_path)


def test_npm_scanner_v3_multiple_versions():
    scanner = NpmLockScanner()
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_npm"

    graph = scanner.scan_graph(fixtures_dir)
    assert "package-lock.json" in graph.lockfiles_detected
    assert "package.json" in graph.manifests_detected

    # express is direct
    express_node = graph.get_node("express")
    assert express_node is not None
    assert express_node.version == "4.19.2"
    assert express_node.is_direct is True

    # debug is transitive
    debug_node = graph.get_node("debug")
    assert debug_node is not None
    assert debug_node.version == "2.6.9"
    assert debug_node.is_direct is False

    # ms is transitive (child of debug)
    ms_node = graph.get_node("ms")
    assert ms_node is not None
    assert ms_node.version == "2.0.0"
    assert ms_node.is_direct is False

    # mocha is dev
    mocha_node = graph.get_node("mocha")
    assert mocha_node is not None
    assert mocha_node.scope == DependencyScope.DEV

    # CRITICAL: Multi-version lodash test!
    # lodash 4.17.21 (root / direct)
    # lodash 3.10.1 (nested inside legacy-module)
    lodash_nodes = [n for n in graph.nodes.values() if n.name == "lodash"]
    assert len(lodash_nodes) == 2

    lodash_v4 = next(n for n in lodash_nodes if n.version == "4.17.21")
    lodash_v3 = next(n for n in lodash_nodes if n.version == "3.10.1")

    assert lodash_v4.is_direct is True
    assert lodash_v3.is_direct is False
    assert lodash_v3.parent_name == "legacy-module"

    # Verify path resolution
    components = graph.resolve_components()
    comp_map = {(c.name, c.version): c for c in components}

    assert comp_map[("lodash", "4.17.21")].is_direct is True
    assert comp_map[("lodash", "3.10.1")].is_direct is False
    assert comp_map[("lodash", "3.10.1")].dependency_path == [
        "express",
        "legacy-module",
        "lodash",
    ]


def test_npm_scanner_v1_legacy(tmp_path: Path):
    v1_lock = {
        "name": "v1-app",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "chalk": {"version": "4.1.2", "dependencies": {"ansi-styles": {"version": "4.3.0"}}}
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(v1_lock), encoding="utf-8")
    scanner = NpmLockScanner()
    graph = scanner.scan_graph(tmp_path)

    chalk = graph.get_node("chalk")
    ansi = graph.get_node("ansi-styles")

    assert chalk is not None and chalk.version == "4.1.2"
    assert ansi is not None and ansi.version == "4.3.0"
    assert ansi.is_direct is False


def test_npm_scanner_manifest_only_fallback(tmp_path: Path):
    pkg_json = {"name": "manifest-only", "dependencies": {"react": "^18.2.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json), encoding="utf-8")
    scanner = NpmLockScanner()
    components = scanner.scan(tmp_path)

    assert len(components) == 1
    assert components[0].name == "react"
    assert components[0].is_direct is True
    assert components[0].version is None
    assert components[0].version_constraint == "^18.2.0"


def test_npm_scanner_corrupt_file(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text("{ NOT JSON }", encoding="utf-8")
    scanner = NpmLockScanner()
    components = scanner.scan(tmp_path)
    assert components == []


def test_npm_scanner_oversized_file(tmp_path: Path, monkeypatch):
    from vuln_ai.scanners import npm_scanner

    monkeypatch.setattr(npm_scanner, "_MAX_LOCKFILE_SIZE", 10)
    (tmp_path / "package-lock.json").write_text('{"name": "test"}', encoding="utf-8")
    scanner = NpmLockScanner()
    graph = scanner.scan_graph(tmp_path)
    assert len(graph.nodes) == 0


def test_npm_scanner_peer_and_optional(tmp_path: Path):
    lock_data = {
        "name": "test-peer-opt",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "test-peer-opt", "dependencies": {"my-lib": "1.0.0"}},
            "node_modules/my-lib": {
                "version": "1.0.0",
                "peerDependencies": {"react": ">=18.0.0"},
                "optionalDependencies": {"fsevents": "2.3.2"},
            },
            "node_modules/react": {"version": "18.2.0"},
            "node_modules/fsevents": {"version": "2.3.2"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_data), encoding="utf-8")
    scanner = NpmLockScanner()
    graph = scanner.scan_graph(tmp_path)

    assert len(graph.nodes) == 3
    peer_edges = [e for e in graph.edges if e.scope == "peer"]
    opt_edges = [e for e in graph.edges if e.scope == "optional"]
    assert len(peer_edges) == 1
    assert peer_edges[0].child_name == "react"
    assert len(opt_edges) == 1
    assert opt_edges[0].child_name == "fsevents"
