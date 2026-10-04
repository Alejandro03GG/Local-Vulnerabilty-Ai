"""Regression: corrupt manifests log warnings instead of failing silently."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from vuln_ai.core.graph import DependencyGraph
from vuln_ai.scanners.cargo_scanner import CargoLockScanner
from vuln_ai.scanners.npm_scanner import NpmLockScanner
from vuln_ai.scanners.pnpm_scanner import PnpmLockScanner


def test_npm_corrupt_package_json_logs_warning(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not-json", encoding="utf-8")
    scanner = NpmLockScanner()
    graph = DependencyGraph()
    with patch("vuln_ai.scanners.npm_scanner.logger.warning") as warn:
        scanner._populate_manifest_only(
            graph, tmp_path / "package.json", set(), set(), set(), set()
        )
    assert warn.called
    assert "Failed to parse" in warn.call_args.args[0]


def test_pnpm_corrupt_package_json_logs_warning(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not-json", encoding="utf-8")
    scanner = PnpmLockScanner()
    with patch("vuln_ai.scanners.pnpm_scanner.logger.warning") as warn:
        direct, dev = scanner._parse_package_json(tmp_path / "package.json")
    assert direct == set()
    assert dev == set()
    assert warn.called
    assert "Failed to parse" in warn.call_args.args[0]


def test_cargo_corrupt_manifest_logs_warning(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("not = toml [[[", encoding="utf-8")
    scanner = CargoLockScanner()
    graph = DependencyGraph()
    with patch("vuln_ai.scanners.cargo_scanner.logger.warning") as warn:
        scanner._populate_manifest_only(graph, tmp_path / "Cargo.toml", set(), set())
    assert warn.called
    assert "Failed to parse" in warn.call_args.args[0]
