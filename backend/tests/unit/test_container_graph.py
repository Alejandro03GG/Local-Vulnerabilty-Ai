"""Unit tests for Container Dependency Graph integration."""

from __future__ import annotations

from vuln_ai.container.graph import build_container_dependency_graph
from vuln_ai.container.models import ContainerImage, OSPackage
from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
)
from vuln_ai.core.models import Ecosystem


def test_build_container_dependency_graph_topology():
    """Verify unified Container Dependency Graph hierarchy and metadata."""
    image = ContainerImage(
        id="img-1",
        reference="my-service:2.0",
        digest="sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        architecture="amd64",
        os="Debian GNU/Linux 12",
    )

    os_pkgs = [
        OSPackage(
            name="curl",
            version="7.88.1",
            ecosystem=Ecosystem.DEB,
            manager="dpkg",
            source_file="/var/lib/dpkg/status",
            layer_digest="sha256:layer1",
            dependencies=["libcurl4"],
        ),
        OSPackage(
            name="libcurl4",
            version="7.88.1",
            ecosystem=Ecosystem.DEB,
            manager="dpkg",
            source_file="/var/lib/dpkg/status",
            layer_digest="sha256:layer1",
        ),
    ]

    # Create dummy application graph
    app_graph = DependencyGraph()
    fastapi_node = DependencyNode.create(
        name="fastapi",
        version="0.110.0",
        ecosystem=Ecosystem.PYPI,
        source_file="/app/requirements.txt",
        is_direct=True,
    )
    starlette_node = DependencyNode.create(
        name="starlette",
        version="0.36.3",
        ecosystem=Ecosystem.PYPI,
        source_file="/app/requirements.txt",
        is_direct=False,
    )
    app_graph.add_node(fastapi_node)
    app_graph.add_node(starlette_node)
    app_graph.add_edge(
        DependencyEdge(
            parent_name="fastapi",
            parent_version="0.110.0",
            child_name="starlette",
            child_version="0.36.3",
        )
    )
    app_graph.manifests_detected.append("requirements.txt")

    # Build container graph
    unified_graph = build_container_dependency_graph(
        image=image,
        os_packages=os_pkgs,
        app_graphs=[app_graph],
    )

    # 1. Root image node exists
    assert any("container:my-service:2.0" in k for k in unified_graph.nodes)

    # 2. OS Package nodes exist
    assert "deb:curl:7.88.1" in unified_graph.nodes
    assert "deb:libcurl4:7.88.1" in unified_graph.nodes

    # 3. Application dependency nodes merged
    assert "pypi:fastapi:0.110.0" in unified_graph.nodes
    assert "pypi:starlette:0.36.3" in unified_graph.nodes

    # 4. Verified edge connections
    edge_pairs = [(e.parent_name, e.child_name) for e in unified_graph.edges]
    # Root -> OS Package
    assert ("my-service:2.0", "curl") in edge_pairs
    assert ("my-service:2.0", "libcurl4") in edge_pairs
    # Root -> Direct App Dependency
    assert ("my-service:2.0", "fastapi") in edge_pairs
    # Direct App -> Transitive App
    assert ("fastapi", "starlette") in edge_pairs
    # OS Package -> OS Dependency
    assert ("curl", "libcurl4") in edge_pairs

    assert "requirements.txt" in unified_graph.manifests_detected
