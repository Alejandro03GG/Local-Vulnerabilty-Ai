"""pnpm lockfile scanner.

Parses pnpm-lock.yaml (lockfile versions 5, 6, 9) and package.json to resolve
exact versions, direct vs transitive dependencies, and graph edges.
Strictly offline and uses safe YAML deserialization.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyScope,
)
from vuln_ai.core.models import DetectedComponent, Ecosystem, normalize_component_name

logger = logging.getLogger(__name__)

_MAX_LOCKFILE_SIZE = 30 * 1024 * 1024

# Pattern to extract name and version from pnpm package keys
# Handles:
#   /express@4.18.2
#   express@4.18.2
#   /@babel/core@7.24.0
#   @babel/core@7.24.0
#   /lodash@4.17.21(react@18.2.0)  -> version is 4.17.21
_PNPM_PKG_KEY_RE = re.compile(r"^/?(?P<name>(?:@[^/@]+/)?[^/@()]+)[@/](?P<version>[^()_]+)")


def _load_pnpm_lock_yaml(content: str) -> dict:
    """Parse pnpm-lock.yaml, including multi-document streams (pnpm 9+).

    Uses ``yaml.safe_load_all`` only (never unsafe ``yaml.load``). Documents are
    shallow-merged so keys like ``packages`` / ``importers`` survive across ``---``.
    """
    merged: dict = {}
    for doc in yaml.safe_load_all(content):
        if isinstance(doc, dict):
            merged.update(doc)
    return merged


class PnpmLockScanner:
    """Scanner for pnpm-lock.yaml lockfiles."""

    @property
    def name(self) -> str:
        return "pnpm Lock Scanner"

    @property
    def ecosystem(self) -> str:
        return "npm"

    def can_scan(self, project_path: Path) -> bool:
        """Check if project contains pnpm-lock.yaml."""
        try:
            return (project_path / "pnpm-lock.yaml").is_file()
        except OSError:
            return False

    def scan(self, project_path: Path) -> list[DetectedComponent]:
        """Scan project and return resolved components."""
        graph = self.scan_graph(project_path)
        return graph.resolve_components()

    def scan_graph(self, project_path: Path) -> DependencyGraph:
        """Parse pnpm-lock.yaml and construct full DependencyGraph."""
        graph = DependencyGraph()
        lock_file = project_path / "pnpm-lock.yaml"
        pkg_file = project_path / "package.json"

        if not lock_file.is_file():
            return graph

        graph.lockfiles_detected.append("pnpm-lock.yaml")
        manifest_direct: set[str] = set()
        manifest_dev: set[str] = set()

        if pkg_file.is_file():
            graph.manifests_detected.append("package.json")
            manifest_direct, manifest_dev = self._parse_package_json(pkg_file)

        try:
            size = lock_file.stat().st_size
            if size > _MAX_LOCKFILE_SIZE:
                logger.error("Lockfile %s exceeds maximum size (%d bytes)", lock_file, size)
                return graph
            content = lock_file.read_text(encoding="utf-8")
            data = _load_pnpm_lock_yaml(content)
        except Exception as exc:
            logger.warning("Failed to parse %s with safe_load_all: %s", lock_file, exc)
            return graph

        if not data:
            return graph

        direct_names, dev_names = self._extract_root_dependencies(
            data, manifest_direct, manifest_dev
        )

        packages = data.get("packages", {})
        if not isinstance(packages, dict):
            return graph

        for raw_key, pkg_info in packages.items():
            if not isinstance(pkg_info, dict):
                continue

            match = _PNPM_PKG_KEY_RE.match(str(raw_key))
            if not match:
                continue

            name = match.group("name")
            version = match.group("version")
            if not name or not version:
                continue

            norm_name = normalize_component_name(name)
            is_direct = norm_name in direct_names or norm_name in dev_names
            is_dev = norm_name in dev_names or bool(pkg_info.get("dev", False))
            is_optional = bool(pkg_info.get("optional", False))

            scope = (
                DependencyScope.DEV
                if is_dev
                else (DependencyScope.OPTIONAL if is_optional else DependencyScope.RUNTIME)
            )

            metadata: dict[str, Any] = {}
            if "resolution" in pkg_info:
                metadata["resolution"] = pkg_info["resolution"]

            node = DependencyNode.create(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,
                source_file=str(lock_file),
                is_direct=is_direct,
                scope=scope,
                manifest_source=str(pkg_file) if is_direct and pkg_file.is_file() else None,
                lockfile_source=str(lock_file),
                metadata=metadata,
            )
            graph.add_node(node)

            # Record subdependencies (edges)
            deps = pkg_info.get("dependencies", {})
            if isinstance(deps, dict):
                for child_name, child_spec in deps.items():
                    edge = DependencyEdge(
                        parent_name=name,
                        parent_version=version,
                        child_name=child_name,
                        child_version=str(child_spec) if child_spec else None,
                        scope=scope,
                    )
                    graph.add_edge(edge)

            opt_deps = pkg_info.get("optionalDependencies", {})
            if isinstance(opt_deps, dict):
                for child_name, child_spec in opt_deps.items():
                    edge = DependencyEdge(
                        parent_name=name,
                        parent_version=version,
                        child_name=child_name,
                        child_version=str(child_spec) if child_spec else None,
                        scope=DependencyScope.OPTIONAL,
                    )
                    graph.add_edge(edge)

        return graph

    def _extract_root_dependencies(
        self,
        data: dict[str, Any],
        manifest_direct: set[str],
        manifest_dev: set[str],
    ) -> tuple[set[str], set[str]]:
        """Extract declared direct and dev dependency names from pnpm-lock.yaml."""
        direct = set(manifest_direct)
        dev = set(manifest_dev)

        # v6/v9: importers map
        importers = data.get("importers", {})
        if isinstance(importers, dict):
            root_imp = importers.get(".", {})
            if isinstance(root_imp, dict):
                for k in root_imp.get("dependencies", {}):
                    direct.add(normalize_component_name(k))
                for k in root_imp.get("devDependencies", {}):
                    dev.add(normalize_component_name(k))

        # v5: top-level dependencies
        top_deps = data.get("dependencies", {})
        if isinstance(top_deps, dict):
            for k in top_deps:
                direct.add(normalize_component_name(k))

        top_dev = data.get("devDependencies", {})
        if isinstance(top_dev, dict):
            for k in top_dev:
                dev.add(normalize_component_name(k))

        return direct, dev

    def _parse_package_json(self, pkg_path: Path) -> tuple[set[str], set[str]]:
        """Extract declared dependencies from package.json."""
        direct: set[str] = set()
        dev: set[str] = set()

        try:
            content = pkg_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s for dependency names: %s", pkg_path, exc)
            return direct, dev

        for name in data.get("dependencies", {}):
            direct.add(normalize_component_name(name))
        for name in data.get("devDependencies", {}):
            dev.add(normalize_component_name(name))

        return direct, dev
