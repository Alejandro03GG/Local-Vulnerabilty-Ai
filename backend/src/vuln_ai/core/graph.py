"""Dependency graph and resolution models for Local Vulnerability AI.

Provides formal representations for DependencyNode, DependencyEdge, and
DependencyGraph with cycle detection, multi-version identity, and deterministic
path reconstruction.
"""

from __future__ import annotations

import enum
import logging
from collections import deque
from typing import Any

from pydantic import BaseModel, Field

from vuln_ai.core.models import (
    ComponentType,
    DetectedComponent,
    Ecosystem,
    VersionType,
    normalize_component_name,
)

logger = logging.getLogger(__name__)


class DependencyType(enum.StrEnum):
    """Direct vs Transitive dependency classification."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class DependencyScope(enum.StrEnum):
    """Dependency installation or runtime scope."""

    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"
    PEER = "peer"
    UNKNOWN = "unknown"


class DependencyNode(BaseModel):
    """Represents a resolved software component in the dependency graph."""

    node_id: str = Field(description="Unique node identity: ecosystem:name:version")
    name: str = Field(description="Package name")
    version: str | None = Field(default=None, description="Exact resolved version")
    ecosystem: Ecosystem | str = Field(default=Ecosystem.UNKNOWN, description="Package ecosystem")
    is_direct: bool = Field(
        default=True, description="True if declared as a direct dependency in manifest"
    )
    dependency_type: DependencyType = Field(
        default=DependencyType.DIRECT, description="Direct or transitive"
    )
    scope: DependencyScope = Field(default=DependencyScope.RUNTIME, description="Lifecycle scope")
    version_type: VersionType = Field(
        default=VersionType.EXACT, description="Version specification certainty"
    )
    version_constraint: str | None = Field(
        default=None, description="Original manifest constraint if known"
    )
    source_file: str = Field(
        default="", description="Primary file originating the component (lockfile or manifest)"
    )
    manifest_source: str | None = Field(
        default=None, description="Manifest path declaring this dependency"
    )
    lockfile_source: str | None = Field(
        default=None, description="Lockfile path resolving this version"
    )
    parent_name: str | None = Field(
        default=None, description="Immediate parent package name if transitive"
    )
    dependency_path: list[str] = Field(
        default_factory=list, description="Chain of ancestors from project root"
    )
    component_type: ComponentType = Field(
        default=ComponentType.LIBRARY, description="Component classification"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Ecosystem-specific metadata (checksums, integrity, etc.)",
    )

    @classmethod
    def create(
        cls,
        name: str,
        version: str | None,
        ecosystem: Ecosystem | str,
        source_file: str,
        is_direct: bool = True,
        scope: DependencyScope = DependencyScope.RUNTIME,
        manifest_source: str | None = None,
        lockfile_source: str | None = None,
        parent_name: str | None = None,
        version_constraint: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DependencyNode:
        """Create a dependency node with standard ID."""
        eco_str = ecosystem.value if isinstance(ecosystem, Ecosystem) else str(ecosystem).lower()
        norm_name = normalize_component_name(name)
        ver_str = version or "unknown"
        node_id = f"{eco_str}:{norm_name}:{ver_str}"
        dep_type = DependencyType.DIRECT if is_direct else DependencyType.TRANSITIVE
        ver_type = VersionType.EXACT if version else VersionType.UNKNOWN

        return cls(
            node_id=node_id,
            name=name,
            version=version,
            ecosystem=ecosystem,
            is_direct=is_direct,
            dependency_type=dep_type,
            scope=scope,
            version_type=ver_type,
            version_constraint=version_constraint,
            source_file=source_file,
            manifest_source=manifest_source,
            lockfile_source=lockfile_source,
            parent_name=parent_name,
            metadata=metadata or {},
        )

    def to_component(self) -> DetectedComponent:
        """Convert this graph node to a domain DetectedComponent."""
        eco = (
            self.ecosystem
            if isinstance(self.ecosystem, Ecosystem)
            else Ecosystem(str(self.ecosystem).lower())
            if str(self.ecosystem).lower() in [e.value for e in Ecosystem]
            else Ecosystem.UNKNOWN
        )
        return DetectedComponent(
            name=self.name,
            version=self.version,
            version_type=self.version_type,
            version_constraint=self.version_constraint,
            ecosystem=eco,
            source_file=self.source_file,
            component_type=self.component_type,
            is_direct=self.is_direct,
            dependency_type=self.dependency_type,
            scope=self.scope,
            manifest_source=self.manifest_source,
            lockfile_source=self.lockfile_source,
            parent_name=self.parent_name,
            dependency_path=self.dependency_path,
            metadata=self.metadata,
        )


class DependencyEdge(BaseModel):
    """Represents a directed dependency relation: parent requires child."""

    parent_name: str = Field(description="Parent package name")
    parent_version: str | None = Field(default=None, description="Parent version if resolved")
    child_name: str = Field(description="Child (dependent) package name")
    child_version: str | None = Field(default=None, description="Child version if resolved")
    scope: DependencyScope = Field(default=DependencyScope.RUNTIME, description="Dependency scope")
    requirement: str | None = Field(
        default=None, description="Constraint requirement string (e.g. '>=1.0.0')"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional relation metadata"
    )


class DependencyGraph(BaseModel):
    """Formal in-memory directed graph of project dependencies."""

    nodes: dict[str, DependencyNode] = Field(
        default_factory=dict, description="Nodes keyed by node_id"
    )
    edges: list[DependencyEdge] = Field(
        default_factory=list, description="Directed parent->child edges"
    )
    lockfiles_detected: list[str] = Field(
        default_factory=list, description="Lockfiles discovered in project"
    )
    manifests_detected: list[str] = Field(
        default_factory=list, description="Manifest files discovered in project"
    )
    cycles: list[list[str]] = Field(
        default_factory=list, description="Detected circular dependencies"
    )

    def add_node(self, node: DependencyNode) -> None:
        """Add or update a dependency node in the graph."""
        existing = self.nodes.get(node.node_id)
        if existing is not None:
            # Merge information: direct manifest flag takes precedence
            if node.is_direct:
                existing.is_direct = True
                existing.dependency_type = DependencyType.DIRECT
            if node.manifest_source and not existing.manifest_source:
                existing.manifest_source = node.manifest_source
            if node.lockfile_source and not existing.lockfile_source:
                existing.lockfile_source = node.lockfile_source
            if node.metadata:
                existing.metadata.update(node.metadata)
            return

        self.nodes[node.node_id] = node

    def add_edge(self, edge: DependencyEdge) -> None:
        """Add a directed edge to the graph (idempotent)."""
        for existing in self.edges:
            if (
                normalize_component_name(existing.parent_name)
                == normalize_component_name(edge.parent_name)
                and existing.parent_version == edge.parent_version
                and normalize_component_name(existing.child_name)
                == normalize_component_name(edge.child_name)
                and existing.child_version == edge.child_version
            ):
                return
        self.edges.append(edge)

    def get_node(self, name: str, version: str | None = None) -> DependencyNode | None:
        """Find a node by name and optional version."""
        norm_name = normalize_component_name(name)
        candidates = [
            n for n in self.nodes.values() if normalize_component_name(n.name) == norm_name
        ]
        if not candidates:
            return None
        if version is not None:
            for c in candidates:
                if c.version == version:
                    return c
        return candidates[0]

    def parents(self, name: str, version: str | None = None) -> list[DependencyNode]:
        """Return parent nodes that directly depend on the given package."""
        norm_name = normalize_component_name(name)
        parent_nodes: list[DependencyNode] = []
        seen: set[str] = set()

        for edge in self.edges:
            if normalize_component_name(edge.child_name) == norm_name:
                if version is not None and edge.child_version and edge.child_version != version:
                    continue
                p_node = self.get_node(edge.parent_name, edge.parent_version)
                if p_node and p_node.node_id not in seen:
                    seen.add(p_node.node_id)
                    parent_nodes.append(p_node)

        return parent_nodes

    def children(self, name: str, version: str | None = None) -> list[DependencyNode]:
        """Return child nodes that the given package depends on."""
        norm_name = normalize_component_name(name)
        child_nodes: list[DependencyNode] = []
        seen: set[str] = set()

        for edge in self.edges:
            if normalize_component_name(edge.parent_name) == norm_name:
                if version is not None and edge.parent_version and edge.parent_version != version:
                    continue
                c_node = self.get_node(edge.child_name, edge.child_version)
                if c_node and c_node.node_id not in seen:
                    seen.add(c_node.node_id)
                    child_nodes.append(c_node)

        return child_nodes

    def roots(self) -> list[DependencyNode]:
        """Return all root (direct) dependency nodes in the graph."""
        return [n for n in self.nodes.values() if n.is_direct]

    def is_direct(self, name: str, version: str | None = None) -> bool:
        """Check if a package is a direct dependency."""
        node = self.get_node(name, version)
        return bool(node and node.is_direct)

    def is_transitive(self, name: str, version: str | None = None) -> bool:
        """Check if a package is a transitive dependency."""
        node = self.get_node(name, version)
        return bool(node and not node.is_direct)

    def get_dependency_path(
        self, name: str, version: str | None = None, max_depth: int = 50
    ) -> list[str]:
        """Reconstruct the dependency chain from a root dependency to this component.

        Uses breadth-first search (BFS) on reverse edges with cycle detection.
        Example: ['my-project', 'fastapi', 'starlette', 'anyio']
        """
        node = self.get_node(name, version)
        if not node:
            return [name]

        if node.is_direct:
            return [node.name]

        # BFS on reverse edges (child -> parent)
        # queue elements: (current_node_id, path_so_far)
        queue: deque[tuple[str, list[str]]] = deque([(node.node_id, [node.name])])
        visited: set[str] = {node.node_id}

        while queue:
            curr_id, path = queue.popleft()
            if len(path) > max_depth:
                break

            curr_node = self.nodes.get(curr_id)
            if not curr_node:
                continue

            if curr_node.is_direct:
                # Reached a direct root! Reverse path so it starts at the direct dependency
                return list(reversed(path))

            for parent in self.parents(curr_node.name, curr_node.version):
                if parent.node_id not in visited:
                    visited.add(parent.node_id)
                    queue.append((parent.node_id, [*path, parent.name]))

        # Fallback if no direct parent could be reached
        return [node.parent_name, node.name] if node.parent_name else [node.name]

    def detect_cycles(self) -> list[list[str]]:
        """Detect circular dependency cycles in the graph safely."""
        adj: dict[str, list[str]] = {}
        for edge in self.edges:
            p = normalize_component_name(edge.parent_name)
            c = normalize_component_name(edge.child_name)
            adj.setdefault(p, []).append(c)

        visited: set[str] = set()
        rec_stack: list[str] = []
        cycles: list[list[str]] = []

        def dfs(curr: str) -> None:
            visited.add(curr)
            rec_stack.append(curr)

            for neighbor in adj.get(curr, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # Found cycle!
                    cycle_start = rec_stack.index(neighbor)
                    cycle = [*list(rec_stack[cycle_start:]), neighbor]
                    cycles.append(cycle)

            rec_stack.pop()

        for node_key in list(adj.keys()):
            if node_key not in visited:
                dfs(node_key)

        self.cycles = cycles
        return cycles

    def resolve_components(self) -> list[DetectedComponent]:
        """Enrich all nodes with paths and parents, returning resolved DetectedComponents."""
        # Detect cycles first for audit trace
        self.detect_cycles()

        # Update paths and parents for each node
        for node in self.nodes.values():
            if not node.is_direct:
                path = self.get_dependency_path(node.name, node.version)
                node.dependency_path = path
                if len(path) >= 2:
                    node.parent_name = path[-2]
            else:
                node.dependency_path = [node.name]
                node.parent_name = None

        return [node.to_component() for node in self.nodes.values()]
