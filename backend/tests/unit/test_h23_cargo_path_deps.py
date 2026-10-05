"""H23: Cargo path/workspace dependencies must resolve versions when possible."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.scanners.cargo_scanner import CargoLockScanner
from vuln_ai.scanners.registry import ScannerRegistry

ROOT = Path(__file__).resolve().parents[1]
WS = ROOT / "fixtures" / "sample_cargo_workspace"
PATH_NO_LOCK = ROOT / "fixtures" / "sample_cargo_path_no_lock"
PATH_UNRESOLVED = ROOT / "fixtures" / "sample_cargo_path_unresolved"


def test_h23_workspace_lock_includes_path_member_version() -> None:
    scanner = CargoLockScanner()
    # Scan the app crate; lock is discovered by walking up to the workspace root.
    comps = scanner.scan(WS / "crates" / "app")
    by_name = {c.name: c for c in comps}
    assert "sample-lib" in by_name
    assert by_name["sample-lib"].version == "0.2.5"
    # Scanned root crate itself is not reported as a third-party component.
    assert "sample-app" not in by_name


def test_h23_path_dep_version_from_path_cargo_toml() -> None:
    scanner = CargoLockScanner()
    comps = scanner.scan(PATH_NO_LOCK / "app")
    by_name = {c.name: c for c in comps}
    assert "path-lib" in by_name
    assert by_name["path-lib"].version == "1.4.2"


def test_h23_unresolvable_path_remains_unknown_version() -> None:
    scanner = CargoLockScanner()
    comps = scanner.scan(PATH_UNRESOLVED / "app")
    by_name = {c.name: c for c in comps}
    assert "missing-lib" in by_name
    assert by_name["missing-lib"].version is None


def test_h23_registry_merge_prefers_lock_version_for_path_member() -> None:
    registry = ScannerRegistry()
    registry.register(CargoLockScanner())
    graph = registry.scan_graph(WS)
    comps = graph.resolve_components()
    lib = next(c for c in comps if c.name == "sample-lib")
    assert lib.version == "0.2.5"
