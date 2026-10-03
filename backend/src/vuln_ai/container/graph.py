"""Container Dependency Graph builder extending the core DependencyGraph.

Unifies container image hierarchy:
Container Image -> Base Image -> OS Packages -> App Dependencies -> Transitive Dependencies
Preserving layer digests, container paths, package managers, and stages.
"""

from __future__ import annotations

import logging

from vuln_ai.container.models import ContainerImage, OSPackage
from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyScope,
    DependencyType,
)
from vuln_ai.core.models import ComponentType, Ecosystem, VersionType

logger = logging.getLogger(__name__)


def build_container_dependency_graph(
    image: ContainerImage,
    os_packages: list[OSPackage],
    app_graphs: list[DependencyGraph] | None = None,
    stage_name: str = "runtime",
) -> DependencyGraph:
    """Construct a unified DependencyGraph representing container OS and application components."""
    graph = DependencyGraph()

    # 1. Create root Image Node
    image_ref = image.reference or "container-image"
    image_digest = image.digest or "sha256:unknown"
    image_node_id = f"container:{image_ref}:{image_digest[:19]}"

    root_node = DependencyNode(
        node_id=image_node_id,
        name=image_ref,
        version=image_digest[:19],
        ecosystem=Ecosystem.UNKNOWN,
        is_direct=True,
        dependency_type=DependencyType.DIRECT,
        scope=DependencyScope.RUNTIME,
        version_type=VersionType.EXACT,
        source_file=image.source_path or image_ref,
        component_type=ComponentType.RUNTIME,
        metadata={
            "digest": image.digest,
            "architecture": image.architecture,
            "os": image.os,
            "stage": stage_name,
        },
    )
    graph.add_node(root_node)

    # 2. Add OS Packages as nodes and edges from root
    for pkg in os_packages:
        pkg_comp = pkg.to_detected_component()
        eco_str = pkg.ecosystem.value
        node_id = f"{eco_str}:{pkg.name}:{pkg.version}"

        meta = dict(pkg_comp.metadata)
        meta["stage"] = stage_name
        meta["container_image"] = image.reference
        if pkg.layer_digest:
            meta["container_layer"] = pkg.layer_digest
        meta["container_path"] = pkg.source_file
        meta["package_manager"] = pkg.manager

        os_node = DependencyNode(
            node_id=node_id,
            name=pkg.name,
            version=pkg.version,
            ecosystem=pkg.ecosystem,
            is_direct=True,
            dependency_type=DependencyType.DIRECT,
            scope=DependencyScope.RUNTIME,
            version_type=VersionType.EXACT,
            source_file=pkg.source_file,
            manifest_source=pkg.source_file,
            component_type=ComponentType.OS_PACKAGE,
            metadata=meta,
        )
        graph.add_node(os_node)

        # Edge from Image -> OS Package
        graph.add_edge(
            DependencyEdge(
                parent_name=root_node.name,
                parent_version=root_node.version,
                child_name=pkg.name,
                child_version=pkg.version,
                scope=DependencyScope.RUNTIME,
                metadata={"relation": "system_package"},
            )
        )

        # Internal OS package dependencies (e.g. Depends: libc6)
        for dep in pkg.dependencies:
            graph.add_edge(
                DependencyEdge(
                    parent_name=pkg.name,
                    parent_version=pkg.version,
                    child_name=dep,
                    child_version=None,
                    scope=DependencyScope.RUNTIME,
                    metadata={"relation": "package_dependency"},
                )
            )

    # 3. Merge application graphs if present
    if app_graphs:
        for app_g in app_graphs:
            graph.lockfiles_detected.extend(app_g.lockfiles_detected)
            graph.manifests_detected.extend(app_g.manifests_detected)

            for _n_id, app_node in app_g.nodes.items():
                # Attach container metadata to app node
                updated_meta = dict(app_node.metadata)
                updated_meta["stage"] = stage_name
                updated_meta["container_image"] = image.reference
                app_node.metadata = updated_meta

                graph.add_node(app_node)

                # Connect direct app dependencies to the container root
                if app_node.is_direct:
                    graph.add_edge(
                        DependencyEdge(
                            parent_name=root_node.name,
                            parent_version=root_node.version,
                            child_name=app_node.name,
                            child_version=app_node.version,
                            scope=app_node.scope,
                            metadata={"relation": "application_dependency"},
                        )
                    )

            for edge in app_g.edges:
                graph.add_edge(edge)

    # Deduplicate detected manifests and lockfiles
    graph.lockfiles_detected = sorted(set(graph.lockfiles_detected))
    graph.manifests_detected = sorted(set(graph.manifests_detected))

    # Perform cycle detection
    graph.detect_cycles()

    return graph
