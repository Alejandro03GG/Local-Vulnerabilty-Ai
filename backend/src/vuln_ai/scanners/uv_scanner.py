"""uv.lock scanner.

Parses Astral ``uv.lock`` TOML lockfiles and correlates with ``pyproject.toml``
to resolve exact versions, direct vs transitive dependencies, and graph edges.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Any

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyScope,
    DependencyType,
)
from vuln_ai.core.models import DetectedComponent, Ecosystem, normalize_component_name

logger = logging.getLogger(__name__)

_MAX_LOCKFILE_SIZE = 20 * 1024 * 1024


class UvLockScanner:
    """Scanner for uv.lock dependency lockfiles."""

    @property
    def name(self) -> str:
        return "uv Lock Scanner"

    @property
    def ecosystem(self) -> str:
        return "pypi"

    def can_scan(self, project_path: Path) -> bool:
        """Check if project contains uv.lock."""
        try:
            return (project_path / "uv.lock").is_file()
        except OSError:
            return False

    def scan(self, project_path: Path) -> list[DetectedComponent]:
        """Scan project and return resolved components."""
        graph = self.scan_graph(project_path)
        return graph.resolve_components()

    def scan_graph(self, project_path: Path) -> DependencyGraph:
        """Parse uv.lock and construct full DependencyGraph."""
        graph = DependencyGraph()
        lock_file = project_path / "uv.lock"
        if not lock_file.is_file():
            return graph

        graph.lockfiles_detected.append("uv.lock")
        manifest_file = project_path / "pyproject.toml"
        direct_names: set[str] = set()
        dev_names: set[str] = set()

        if manifest_file.is_file():
            graph.manifests_detected.append("pyproject.toml")
            direct_names, dev_names = self._parse_direct_dependencies(manifest_file)

        try:
            size = lock_file.stat().st_size
            if size > _MAX_LOCKFILE_SIZE:
                logger.error(
                    "Lockfile %s exceeds maximum allowed size (%d bytes)", lock_file, size
                )
                return graph
            content = lock_file.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", lock_file, exc)
            return graph

        packages = data.get("package", [])
        if not isinstance(packages, list):
            return graph

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or version is None or version == "":
                # Skip entries without an exact resolved version (H19: do not invent).
                continue

            norm_name = normalize_component_name(str(name))
            is_direct = norm_name in direct_names
            is_dev = norm_name in dev_names
            scope = DependencyScope.DEV if is_dev else DependencyScope.RUNTIME

            metadata: dict[str, Any] = {}
            source = pkg.get("source")
            if isinstance(source, dict):
                metadata["source"] = source

            node = DependencyNode.create(
                name=str(name),
                version=str(version),
                ecosystem=Ecosystem.PYPI,
                source_file=str(lock_file),
                is_direct=is_direct,
                scope=scope,
                manifest_source=str(manifest_file) if is_direct else None,
                lockfile_source=str(lock_file),
                metadata=metadata,
            )
            graph.add_node(node)

            deps = pkg.get("dependencies", [])
            if isinstance(deps, list):
                for dep in deps:
                    if not isinstance(dep, dict):
                        continue
                    child_name = dep.get("name")
                    if not child_name:
                        continue
                    edge = DependencyEdge(
                        parent_name=str(name),
                        parent_version=str(version),
                        child_name=str(child_name),
                        scope=scope,
                        requirement=None,
                    )
                    graph.add_edge(edge)

        if not direct_names and graph.nodes:
            incoming_children = {normalize_component_name(e.child_name) for e in graph.edges}
            for node in graph.nodes.values():
                if normalize_component_name(node.name) not in incoming_children:
                    node.is_direct = True
                    node.dependency_type = DependencyType.DIRECT

        return graph

    def _parse_direct_dependencies(self, pyproject_path: Path) -> tuple[set[str], set[str]]:
        """Extract declared direct/dev dependency names from pyproject.toml (PEP 621 / uv)."""
        direct: set[str] = set()
        dev: set[str] = set()

        try:
            content = pyproject_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", pyproject_path, exc)
            return direct, dev

        pep_deps = data.get("project", {}).get("dependencies", [])
        if isinstance(pep_deps, list):
            for line in pep_deps:
                pkg_name = (
                    str(line).split(">")[0].split("<")[0].split("=")[0].split(";")[0].strip()
                )
                if pkg_name:
                    direct.add(normalize_component_name(pkg_name))

        optional = data.get("project", {}).get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group_name, group_deps in optional.items():
                if not isinstance(group_deps, list):
                    continue
                target = dev if "dev" in str(group_name).lower() else direct
                for line in group_deps:
                    pkg_name = (
                        str(line).split(">")[0].split("<")[0].split("=")[0].split(";")[0].strip()
                    )
                    if pkg_name:
                        target.add(normalize_component_name(pkg_name))

        # uv / hatch / pep735 dependency-groups
        dep_groups = data.get("dependency-groups", {})
        if isinstance(dep_groups, dict):
            for group_name, group_deps in dep_groups.items():
                if not isinstance(group_deps, list):
                    continue
                target = dev if "dev" in str(group_name).lower() else direct
                for line in group_deps:
                    pkg_name = (
                        str(line).split(">")[0].split("<")[0].split("=")[0].split(";")[0].strip()
                    )
                    if pkg_name:
                        target.add(normalize_component_name(pkg_name))

        return direct, dev
