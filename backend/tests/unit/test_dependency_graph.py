"""Unit tests for DependencyGraph, cycle detection, path traversal, and stress scalability."""

from __future__ import annotations

import time

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
)
from vuln_ai.core.models import Ecosystem


def test_dependency_graph_cycle_protection():
    """Graph must detect cycles and never recurse infinitely."""
    graph = DependencyGraph()

    node_a = DependencyNode.create("pkg-a", "1.0.0", Ecosystem.PYPI, "mock.lock", is_direct=True)
    node_b = DependencyNode.create("pkg-b", "1.0.0", Ecosystem.PYPI, "mock.lock", is_direct=False)
    node_c = DependencyNode.create("pkg-c", "1.0.0", Ecosystem.PYPI, "mock.lock", is_direct=False)

    graph.add_node(node_a)
    graph.add_node(node_b)
    graph.add_node(node_c)

    # Artificial cycle: A -> B -> C -> A
    graph.add_edge(DependencyEdge(parent_name="pkg-a", child_name="pkg-b"))
    graph.add_edge(DependencyEdge(parent_name="pkg-b", child_name="pkg-c"))
    graph.add_edge(DependencyEdge(parent_name="pkg-c", child_name="pkg-a"))

    # Cycle detection
    cycles = graph.detect_cycles()
    assert len(cycles) > 0

    # Path resolution on cyclic graph must terminate safely
    path_c = graph.get_dependency_path("pkg-c")
    assert path_c is not None
    assert len(path_c) <= 10  # Must not explode

    # Resolve components must complete safely
    comps = graph.resolve_components()
    assert len(comps) == 3


def test_dependency_graph_multi_version_identity():
    """Graph must maintain distinct nodes for multiple versions of the same package."""
    graph = DependencyGraph()

    node_v3 = DependencyNode.create(
        "lodash", "3.10.1", Ecosystem.NPM, "package-lock.json", is_direct=False
    )
    node_v4 = DependencyNode.create(
        "lodash", "4.17.21", Ecosystem.NPM, "package-lock.json", is_direct=True
    )

    graph.add_node(node_v3)
    graph.add_node(node_v4)

    assert len(graph.nodes) == 2
    assert graph.is_direct("lodash", "4.17.21") is True
    assert graph.is_direct("lodash", "3.10.1") is False

    comps = graph.resolve_components()
    assert len(comps) == 2
    versions = {c.version for c in comps}
    assert versions == {"3.10.1", "4.17.21"}


def test_dependency_graph_stress_1000_nodes():
    """Graph must handle 1000+ dependency nodes efficiently without stack overflow."""
    graph = DependencyGraph()

    start_time = time.monotonic()

    # Create 1 root node
    root = DependencyNode.create(
        "root-app", "1.0.0", Ecosystem.PYPI, "stress.lock", is_direct=True
    )
    graph.add_node(root)

    # Create 100 direct packages, each with 9 transitive children
    for i in range(100):
        direct_name = f"direct-pkg-{i}"
        d_node = DependencyNode.create(
            direct_name, "1.0.0", Ecosystem.PYPI, "stress.lock", is_direct=True
        )
        graph.add_node(d_node)
        graph.add_edge(DependencyEdge(parent_name="root-app", child_name=direct_name))

        for j in range(9):
            trans_name = f"trans-pkg-{i}-{j}"
            t_node = DependencyNode.create(
                trans_name, f"{j}.0.0", Ecosystem.PYPI, "stress.lock", is_direct=False
            )
            graph.add_node(t_node)
            graph.add_edge(DependencyEdge(parent_name=direct_name, child_name=trans_name))

    assert len(graph.nodes) == 1 + 100 + 900  # 1001 nodes
    assert len(graph.edges) == 100 + 900  # 1000 edges

    components = graph.resolve_components()
    elapsed = time.monotonic() - start_time

    assert len(components) == 1001
    assert elapsed < 3.0  # Must resolve 1000+ nodes in under 3.0 seconds under coverage!


def test_dependency_graph_node_merging_and_edges():
    """Test node merging, edge idempotency, parents/children queries, and roots."""
    graph = DependencyGraph()

    # 1. Add transitive node first
    node1 = DependencyNode.create(
        "requests", "2.31.0", Ecosystem.PYPI, "poetry.lock", is_direct=False
    )
    graph.add_node(node1)
    assert graph.is_transitive("requests", "2.31.0") is True

    # 2. Re-add same node as direct (from manifest) -> should merge and become direct
    node1_direct = DependencyNode.create(
        "requests",
        "2.31.0",
        Ecosystem.PYPI,
        "poetry.lock",
        is_direct=True,
        manifest_source="pyproject.toml",
    )
    node1_direct.metadata = {"extra": "test"}
    graph.add_node(node1_direct)

    merged = graph.get_node("requests", "2.31.0")
    assert merged is not None
    assert merged.is_direct is True
    assert merged.manifest_source == "pyproject.toml"
    assert merged.metadata.get("extra") == "test"

    # 3. Add child node urllib3
    child = DependencyNode.create(
        "urllib3", "2.0.0", Ecosystem.PYPI, "poetry.lock", is_direct=False
    )
    graph.add_node(child)

    # 4. Add edge idempotently
    edge = DependencyEdge(
        parent_name="requests",
        parent_version="2.31.0",
        child_name="urllib3",
        child_version="2.0.0",
    )
    graph.add_edge(edge)
    graph.add_edge(edge)  # duplicate should be ignored
    assert len(graph.edges) == 1

    # 5. Test parents and children queries
    parents = graph.parents("urllib3", "2.0.0")
    assert len(parents) == 1
    assert parents[0].name == "requests"

    children = graph.children("requests", "2.31.0")
    assert len(children) == 1
    assert children[0].name == "urllib3"

    # 6. Test roots
    roots = graph.roots()
    assert len(roots) == 1
    assert roots[0].name == "requests"

    # 7. Test get_dependency_path
    path = graph.get_dependency_path("urllib3", "2.0.0")
    assert path == ["requests", "urllib3"]

    # Direct node path
    direct_path = graph.get_dependency_path("requests")
    assert direct_path == ["requests"]

    # Unknown node path
    unknown_path = graph.get_dependency_path("non-existent")
    assert unknown_path == ["non-existent"]


def test_scanner_properties_and_wrappers(tmp_path):
    """Verify scanner metadata properties and standard scan() method."""
    from vuln_ai.scanners.cargo_scanner import CargoLockScanner
    from vuln_ai.scanners.npm_scanner import NpmLockScanner
    from vuln_ai.scanners.pnpm_scanner import PnpmLockScanner
    from vuln_ai.scanners.poetry_scanner import PoetryLockScanner

    poetry = PoetryLockScanner()
    assert poetry.name == "Poetry Lock Scanner"
    assert poetry.ecosystem == "pypi"
    assert poetry.scan(tmp_path) == []

    npm = NpmLockScanner()
    assert npm.name == "npm Lock Scanner"
    assert npm.ecosystem == "npm"
    assert npm.scan(tmp_path) == []

    pnpm = PnpmLockScanner()
    assert pnpm.name == "pnpm Lock Scanner"
    assert pnpm.ecosystem == "npm"
    assert pnpm.scan(tmp_path) == []

    cargo = CargoLockScanner()
    assert cargo.name == "Cargo Lock Scanner"
    assert cargo.ecosystem == "cargo"
    assert cargo.scan(tmp_path) == []
