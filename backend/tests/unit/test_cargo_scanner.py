"""Unit tests for CargoLockScanner."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.scanners.cargo_scanner import CargoLockScanner


def test_cargo_scanner_can_scan(tmp_path: Path):
    scanner = CargoLockScanner()
    assert not scanner.can_scan(tmp_path)

    (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
    assert scanner.can_scan(tmp_path)


def test_cargo_scanner_parses_dependencies():
    scanner = CargoLockScanner()
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_cargo"

    graph = scanner.scan_graph(fixtures_dir)
    assert "Cargo.lock" in graph.lockfiles_detected
    assert "Cargo.toml" in graph.manifests_detected

    # tokio is direct
    tokio_node = graph.get_node("tokio")
    assert tokio_node is not None
    assert tokio_node.version == "1.36.0"
    assert tokio_node.is_direct is True

    # bytes is transitive (child of tokio)
    bytes_node = graph.get_node("bytes")
    assert bytes_node is not None
    assert bytes_node.version == "1.5.0"
    assert bytes_node.is_direct is False

    # mio is transitive (child of tokio)
    mio_node = graph.get_node("mio")
    assert mio_node is not None
    assert mio_node.version == "0.8.10"
    assert mio_node.is_direct is False

    # libc is transitive (child of mio)
    libc_node = graph.get_node("libc")
    assert libc_node is not None
    assert libc_node.version == "0.2.153"
    assert libc_node.is_direct is False

    # CRITICAL: Multi-version serde test!
    # serde 1.0.197 (direct from Cargo.toml)
    # serde 0.9.0 (transitive / legacy)
    serde_nodes = [n for n in graph.nodes.values() if n.name == "serde"]
    assert len(serde_nodes) == 2

    serde_v1 = next(n for n in serde_nodes if n.version == "1.0.197")
    serde_v0 = next(n for n in serde_nodes if n.version == "0.9.0")

    assert serde_v1.is_direct is True
    assert serde_v0.is_direct is False

    # Path resolution
    components = graph.resolve_components()
    comp_map = {(c.name, c.version): c for c in components}

    assert comp_map[("libc", "0.2.153")].is_direct is False
    assert comp_map[("libc", "0.2.153")].parent_name == "mio"
    assert comp_map[("libc", "0.2.153")].dependency_path == ["tokio", "mio", "libc"]


def test_cargo_scanner_manifest_only_fallback(tmp_path: Path):
    cargo_toml = """
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
regex = "1.10.0"
"""
    (tmp_path / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    scanner = CargoLockScanner()
    components = scanner.scan(tmp_path)

    assert len(components) == 1
    assert components[0].name == "regex"
    assert components[0].is_direct is True


def test_cargo_scanner_corrupt_file(tmp_path: Path):
    (tmp_path / "Cargo.lock").write_text("[[ NOT TOML ]", encoding="utf-8")
    scanner = CargoLockScanner()
    components = scanner.scan(tmp_path)
    assert components == []


def test_cargo_scanner_oversized_file(tmp_path: Path, monkeypatch):
    from vuln_ai.scanners import cargo_scanner

    monkeypatch.setattr(cargo_scanner, "_MAX_LOCKFILE_SIZE", 10)
    (tmp_path / "Cargo.lock").write_text(
        "[[package]]\nname='foo'\nversion='1.0'", encoding="utf-8"
    )
    scanner = CargoLockScanner()
    graph = scanner.scan_graph(tmp_path)
    assert len(graph.nodes) == 0


def test_cargo_scanner_without_manifest_roots(tmp_path: Path):
    """When Cargo.toml is absent, root nodes are inferred from crates with no incoming edges."""
    lock_content = """
version = 3

[[package]]
name = "root-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
    "child-crate 2.0.0",
]

[[package]]
name = "child-crate"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    (tmp_path / "Cargo.lock").write_text(lock_content, encoding="utf-8")
    scanner = CargoLockScanner()
    graph = scanner.scan_graph(tmp_path)

    assert len(graph.nodes) == 2
    root = graph.get_node("root-crate")
    child = graph.get_node("child-crate")
    assert root is not None and root.is_direct is True
    assert child is not None and child.is_direct is False


def test_cargo_scanner_dev_build_workspace_dependencies(tmp_path: Path):
    cargo_toml = """
[package]
name = "my-workspace-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"

[workspace.dependencies]
shared-lib = "0.2"
"""
    (tmp_path / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    scanner = CargoLockScanner()
    components = scanner.scan(tmp_path)

    names = {c.name for c in components}
    assert "serde" in names
    assert "criterion" in names
    assert "cc" in names


def test_cargo_scanner_corrupt_manifest_only(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("NOT VALID TOML [[", encoding="utf-8")
    scanner = CargoLockScanner()
    components = scanner.scan(tmp_path)
    assert components == []
