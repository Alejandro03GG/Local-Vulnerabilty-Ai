"""Poetry lockfile scanner.

Parses poetry.lock files and correlates with pyproject.toml to resolve
exact versions, direct vs transitive dependencies, and graph edges.
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

# Max file size: 20MB to prevent memory exhaustion
_MAX_LOCKFILE_SIZE = 20 * 1024 * 1024


class PoetryLockScanner:
    """Scanner for poetry.lock dependency lockfiles."""

    @property
    def name(self) -> str:
        return "Poetry Lock Scanner"

    @property
    def ecosystem(self) -> str:
        return "pypi"

    def can_scan(self, project_path: Path) -> bool:
        """Check if project contains poetry.lock."""
        try:
            return (project_path / "poetry.lock").is_file()
        except OSError:
            return False

    def scan(self, project_path: Path) -> list[DetectedComponent]:
        """Scan project and return resolved components."""
        graph = self.scan_graph(project_path)
        return graph.resolve_components()

    def scan_graph(self, project_path: Path) -> DependencyGraph:
        """Parse poetry.lock and construct full DependencyGraph."""
        graph = DependencyGraph()
        lock_file = project_path / "poetry.lock"
        if not lock_file.is_file():
            return graph

        graph.lockfiles_detected.append("poetry.lock")
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
            if not name or not version:
                continue

            norm_name = normalize_component_name(name)
            is_direct = norm_name in direct_names
            is_dev = norm_name in dev_names or pkg.get("category") == "dev"
            optional = bool(pkg.get("optional", False))

            scope = (
                DependencyScope.DEV
                if is_dev
                else (DependencyScope.OPTIONAL if optional else DependencyScope.RUNTIME)
            )

            metadata: dict[str, Any] = {}
            if "files" in pkg:
                metadata["files_count"] = len(pkg["files"])
            if "source" in pkg:
                metadata["source"] = pkg["source"]

            node = DependencyNode.create(
                name=name,
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

            # Process dependencies (edges)
            deps = pkg.get("dependencies", {})
            if isinstance(deps, dict):
                for child_name, constraint in deps.items():
                    req_str = (
                        constraint
                        if isinstance(constraint, str)
                        else (constraint.get("version") if isinstance(constraint, dict) else None)
                    )
                    edge = DependencyEdge(
                        parent_name=name,
                        parent_version=str(version),
                        child_name=child_name,
                        scope=scope,
                        requirement=req_str,
                    )
                    graph.add_edge(edge)

        # If pyproject.toml was absent, infer direct dependencies (nodes with no incoming edges)
        if not direct_names and graph.nodes:
            incoming_children = {normalize_component_name(e.child_name) for e in graph.edges}
            for node in graph.nodes.values():
                if normalize_component_name(node.name) not in incoming_children:
                    node.is_direct = True
                    node.dependency_type = DependencyType.DIRECT

        return graph

    def _parse_direct_dependencies(self, pyproject_path: Path) -> tuple[set[str], set[str]]:
        """Extract declared direct and dev dependency names from pyproject.toml."""
        direct: set[str] = set()
        dev: set[str] = set()

        try:
            content = pyproject_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", pyproject_path, exc)
            return direct, dev

        # Poetry standard: [tool.poetry.dependencies]
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for name in poetry_deps:
                if name.lower() != "python":
                    direct.add(normalize_component_name(name))

        # Poetry groups: [tool.poetry.group.<name>.dependencies]
        groups = data.get("tool", {}).get("poetry", {}).get("group", {})
        if isinstance(groups, dict):
            for grp_name, grp_data in groups.items():
                if isinstance(grp_data, dict):
                    grp_deps = grp_data.get("dependencies", {})
                    if isinstance(grp_deps, dict):
                        for name in grp_deps:
                            norm = normalize_component_name(name)
                            if "dev" in grp_name.lower():
                                dev.add(norm)
                            else:
                                direct.add(norm)

        # Legacy poetry dev-dependencies: [tool.poetry.dev-dependencies]
        legacy_dev = data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
        if isinstance(legacy_dev, dict):
            for name in legacy_dev:
                dev.add(normalize_component_name(name))

        # PEP 621: [project.dependencies]
        pep_deps = data.get("project", {}).get("dependencies", [])
        if isinstance(pep_deps, list):
            for line in pep_deps:
                pkg_name = (
                    str(line).split(">")[0].split("<")[0].split("=")[0].split(";")[0].strip()
                )
                if pkg_name:
                    direct.add(normalize_component_name(pkg_name))

        return direct, dev
