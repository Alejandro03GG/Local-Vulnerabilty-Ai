"""Unit tests for UvLockScanner (H18)."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.scanners.uv_scanner import UvLockScanner

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sample_uv"


def test_uv_scanner_can_scan(tmp_path: Path) -> None:
    scanner = UvLockScanner()
    assert scanner.can_scan(tmp_path) is False
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    assert scanner.can_scan(tmp_path) is True


def test_uv_lock_resolves_exact_versions_and_edges(tmp_path: Path) -> None:
    for name in ("uv.lock", "pyproject.toml"):
        (tmp_path / name).write_text((FIXTURES / name).read_text(encoding="utf-8"), encoding="utf-8")

    scanner = UvLockScanner()
    graph = scanner.scan_graph(tmp_path)
    by_name = {n.name: n for n in graph.nodes.values()}
    assert "httpx" in by_name
    assert by_name["httpx"].version == "0.27.2"
    assert by_name["httpx"].is_direct is True
    assert "anyio" in by_name
    assert by_name["anyio"].version == "4.6.0"
    assert by_name["anyio"].is_direct is False
    assert "idna" in by_name
    # incomplete package without version must be skipped (no invented version)
    assert "incomplete-pkg" not in by_name
    parent_children = {(e.parent_name, e.child_name) for e in graph.edges}
    assert ("httpx", "anyio") in parent_children
    assert ("anyio", "idna") in parent_children


def test_uv_lock_scan_components(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text((FIXTURES / "uv.lock").read_text(encoding="utf-8"))
    comps = UvLockScanner().scan(tmp_path)
    versions = {c.name: c.version for c in comps}
    assert versions["httpx"] == "0.27.2"
    assert "incomplete-pkg" not in versions
