"""Registry for project scanners with dependency graph resolution."""

from __future__ import annotations

import logging
from pathlib import Path

from vuln_ai.core.graph import DependencyGraph, DependencyNode, DependencyType
from vuln_ai.core.models import DetectedComponent, normalize_component_name
from vuln_ai.scanners.base import ProjectScanner

logger = logging.getLogger(__name__)


class ScannerRegistry:
    """Registry for scanner implementations and dependency graph resolution."""

    def __init__(self) -> None:
        self._scanners: list[ProjectScanner] = []

    def register(self, scanner: ProjectScanner) -> None:
        """Register a project scanner."""
        self._scanners.append(scanner)

    def get_scanners_for(self, project_path: Path) -> list[ProjectScanner]:
        """Return all scanners that can handle the given project."""
        return [s for s in self._scanners if s.can_scan(project_path)]

    def scan_graph(self, project_path: Path) -> DependencyGraph:
        """Run all applicable scanners and merge results into a unified DependencyGraph.

        Enforces the precedence rule: LOCKFILE > MANIFEST.
        - If an exact resolved version exists from a lockfile, it takes precedence.
        - Manifest packages mark matching lockfile packages as direct dependencies.
        - Unresolved manifest-only packages are preserved.
        """
        combined_graph = DependencyGraph()
        applicable = self.get_scanners_for(project_path)

        lockfile_nodes: dict[str, DependencyNode] = {}
        manifest_nodes: dict[str, list[DependencyNode]] = {}

        for scanner in applicable:
            # 1. Run graph-aware scan if supported
            if hasattr(scanner, "scan_graph"):
                graph = scanner.scan_graph(project_path)
                combined_graph.edges.extend(graph.edges)
                for lf in graph.lockfiles_detected:
                    if lf not in combined_graph.lockfiles_detected:
                        combined_graph.lockfiles_detected.append(lf)
                for mf in graph.manifests_detected:
                    if mf not in combined_graph.manifests_detected:
                        combined_graph.manifests_detected.append(mf)

                for node in graph.nodes.values():
                    if node.lockfile_source:
                        # Lockfile-originated node
                        lockfile_nodes[node.node_id] = node
                    else:
                        norm = normalize_component_name(node.name)
                        manifest_nodes.setdefault(norm, []).append(node)
            else:
                # 2. Legacy scanner returning list[DetectedComponent]
                components = scanner.scan(project_path)
                for comp in components:
                    node = DependencyNode.create(
                        name=comp.name,
                        version=comp.version,
                        ecosystem=comp.ecosystem,
                        source_file=comp.source_file,
                        is_direct=getattr(comp, "is_direct", True),
                        manifest_source=comp.source_file,
                        version_constraint=comp.version_constraint,
                    )
                    norm = normalize_component_name(comp.name)
                    manifest_nodes.setdefault(norm, []).append(node)

        # Apply precedence: Lockfile nodes form the core
        for node in lockfile_nodes.values():
            norm = normalize_component_name(node.name)
            # If this package was declared in a manifest, ensure it's marked direct
            if norm in manifest_nodes:
                m_node = manifest_nodes[norm][0]
                node.is_direct = True
                node.dependency_type = DependencyType.DIRECT
                node.manifest_source = m_node.manifest_source or m_node.source_file
                if not node.version_constraint and m_node.version_constraint:
                    node.version_constraint = m_node.version_constraint

            combined_graph.add_node(node)

        # Add manifest-only nodes if not superseded by a lockfile node
        for norm, m_nodes in manifest_nodes.items():
            has_lockfile_match = any(
                normalize_component_name(ln.name) == norm for ln in lockfile_nodes.values()
            )
            if not has_lockfile_match:
                for m_node in m_nodes:
                    combined_graph.add_node(m_node)

        return combined_graph

    def scan_all(self, project_path: Path) -> list[DetectedComponent]:
        """Run all applicable scanners and return combined, resolved components."""
        graph = self.scan_graph(project_path)
        return graph.resolve_components()

    def list_scanners(self) -> list[ProjectScanner]:
        """List all registered scanners."""
        return list(self._scanners)

    def __len__(self) -> int:
        return len(self._scanners)
