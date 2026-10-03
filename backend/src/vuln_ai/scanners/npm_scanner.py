"""npm project and lockfile scanner.

Parses package-lock.json (versions 1, 2, 3) and package.json to resolve
exact versions, direct vs transitive dependencies, and graph edges.
Supports multiple versions of the same package simultaneously.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyScope,
)
from vuln_ai.core.models import (
    DetectedComponent,
    Ecosystem,
    VersionType,
)

logger = logging.getLogger(__name__)

_MAX_LOCKFILE_SIZE = 30 * 1024 * 1024


class NpmLockScanner:
    """Scanner for npm package-lock.json and package.json."""

    @property
    def name(self) -> str:
        return "npm Lock Scanner"

    @property
    def ecosystem(self) -> str:
        return "npm"

    def can_scan(self, project_path: Path) -> bool:
        """Check if project contains package-lock.json or package.json."""
        try:
            return (project_path / "package-lock.json").is_file() or (
                project_path / "package.json"
            ).is_file()
        except OSError:
            return False

    def scan(self, project_path: Path) -> list[DetectedComponent]:
        """Scan project and return resolved components."""
        graph = self.scan_graph(project_path)
        return graph.resolve_components()

    def scan_graph(self, project_path: Path) -> DependencyGraph:
        """Parse npm files and construct full DependencyGraph."""
        graph = DependencyGraph()
        lock_file = project_path / "package-lock.json"
        pkg_file = project_path / "package.json"

        direct_deps: set[str] = set()
        dev_deps: set[str] = set()
        peer_deps: set[str] = set()
        opt_deps: set[str] = set()

        if pkg_file.is_file():
            graph.manifests_detected.append("package.json")
            direct_deps, dev_deps, peer_deps, opt_deps = self._parse_package_json(pkg_file)

        if not lock_file.is_file():
            # Manifest-only fallback
            if pkg_file.is_file():
                self._populate_manifest_only(
                    graph, pkg_file, direct_deps, dev_deps, peer_deps, opt_deps
                )
            return graph

        graph.lockfiles_detected.append("package-lock.json")

        try:
            size = lock_file.stat().st_size
            if size > _MAX_LOCKFILE_SIZE:
                logger.error("Lockfile %s exceeds maximum size (%d bytes)", lock_file, size)
                return graph
            content = lock_file.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", lock_file, exc)
            return graph

        lock_version = data.get("lockfileVersion", 1)

        # In v2 and v3: use "packages" map if available
        if lock_version in (2, 3) and "packages" in data:
            self._parse_v2_v3_packages(
                graph,
                data["packages"],
                str(lock_file),
                str(pkg_file) if pkg_file.is_file() else None,
                direct_deps,
                dev_deps,
                opt_deps,
            )
        else:
            # Fallback to v1 dependencies tree
            deps = data.get("dependencies", {})
            self._parse_v1_dependencies(
                graph,
                deps,
                str(lock_file),
                str(pkg_file) if pkg_file.is_file() else None,
                direct_deps,
                dev_deps,
                opt_deps,
            )

        return graph

    def _parse_package_json(self, pkg_path: Path) -> tuple[set[str], set[str], set[str], set[str]]:
        """Extract declared dependencies from package.json."""
        direct: set[str] = set()
        dev: set[str] = set()
        peer: set[str] = set()
        opt: set[str] = set()

        try:
            content = pkg_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", pkg_path, exc)
            return direct, dev, peer, opt

        for name in data.get("dependencies", {}):
            direct.add(name)
        for name in data.get("devDependencies", {}):
            dev.add(name)
        for name in data.get("peerDependencies", {}):
            peer.add(name)
        for name in data.get("optionalDependencies", {}):
            opt.add(name)

        return direct, dev, peer, opt

    def _parse_v2_v3_packages(
        self,
        graph: DependencyGraph,
        packages: dict[str, Any],
        lock_path: str,
        pkg_path: str | None,
        manifest_direct: set[str],
        manifest_dev: set[str],
        manifest_opt: set[str],
    ) -> None:
        """Parse modern v2/v3 package-lock.json packages dictionary."""
        # Root package info is at key ""
        root_pkg = packages.get("", {})
        root_deps = set(root_pkg.get("dependencies", {}).keys())
        root_dev = set(root_pkg.get("devDependencies", {}).keys())
        root_opt = set(root_pkg.get("optionalDependencies", {}).keys())

        effective_direct = manifest_direct or root_deps
        effective_dev = manifest_dev or root_dev
        effective_opt = manifest_opt or root_opt

        for path_key, info in packages.items():
            if not path_key or not isinstance(info, dict):
                continue

            version = info.get("version")
            if not version:
                continue

            # Extract package name and parent name from path_key
            # Example: "node_modules/foo" -> name="foo", parent=None
            # Example: "node_modules/@scope/foo" -> name="@scope/foo", parent=None
            # Example: "node_modules/bar/node_modules/foo" -> name="foo", parent="bar"
            name, parent_name, is_nested = self._extract_package_names_from_path(path_key)
            if not name:
                continue

            is_direct = (name in effective_direct or name in effective_dev) and not is_nested
            is_dev = bool(info.get("dev", False)) or name in effective_dev
            is_optional = bool(info.get("optional", False)) or name in effective_opt
            is_peer = bool(info.get("peer", False))

            scope = (
                DependencyScope.DEV
                if is_dev
                else (
                    DependencyScope.OPTIONAL
                    if is_optional
                    else (DependencyScope.PEER if is_peer else DependencyScope.RUNTIME)
                )
            )

            metadata: dict[str, Any] = {}
            if "resolved" in info:
                metadata["resolved"] = info["resolved"]
            if "integrity" in info:
                metadata["integrity"] = info["integrity"]

            node = DependencyNode.create(
                name=name,
                version=str(version),
                ecosystem=Ecosystem.NPM,
                source_file=lock_path,
                is_direct=is_direct,
                scope=scope,
                manifest_source=pkg_path if is_direct else None,
                lockfile_source=lock_path,
                parent_name=parent_name,
                metadata=metadata,
            )
            graph.add_node(node)

            # Record subdependencies (edges)
            subdeps = info.get("dependencies", {})
            if isinstance(subdeps, dict):
                for child_name, constraint in subdeps.items():
                    edge = DependencyEdge(
                        parent_name=name,
                        parent_version=str(version),
                        child_name=child_name,
                        scope=scope,
                        requirement=str(constraint) if constraint else None,
                    )
                    graph.add_edge(edge)

            opt_deps = info.get("optionalDependencies", {})
            if isinstance(opt_deps, dict):
                for child_name, constraint in opt_deps.items():
                    edge = DependencyEdge(
                        parent_name=name,
                        parent_version=str(version),
                        child_name=child_name,
                        scope=DependencyScope.OPTIONAL,
                        requirement=str(constraint) if constraint else None,
                    )
                    graph.add_edge(edge)

            peer_deps = info.get("peerDependencies", {})
            if isinstance(peer_deps, dict):
                for child_name, constraint in peer_deps.items():
                    edge = DependencyEdge(
                        parent_name=name,
                        parent_version=str(version),
                        child_name=child_name,
                        scope=DependencyScope.PEER,
                        requirement=str(constraint) if constraint else None,
                    )
                    graph.add_edge(edge)

    def _parse_v1_dependencies(
        self,
        graph: DependencyGraph,
        deps: dict[str, Any],
        lock_path: str,
        pkg_path: str | None,
        direct_names: set[str],
        dev_names: set[str],
        opt_names: set[str],
        parent_name: str | None = None,
        parent_version: str | None = None,
    ) -> None:
        """Parse v1 package-lock.json nested dependencies dictionary."""
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if not version:
                continue

            is_direct = parent_name is None and (name in direct_names or not direct_names)
            is_dev = bool(info.get("dev", False)) or name in dev_names
            is_optional = bool(info.get("optional", False)) or name in opt_names

            scope = (
                DependencyScope.DEV
                if is_dev
                else (DependencyScope.OPTIONAL if is_optional else DependencyScope.RUNTIME)
            )

            node = DependencyNode.create(
                name=name,
                version=str(version),
                ecosystem=Ecosystem.NPM,
                source_file=lock_path,
                is_direct=is_direct,
                scope=scope,
                manifest_source=pkg_path if is_direct else None,
                lockfile_source=lock_path,
                parent_name=parent_name,
            )
            graph.add_node(node)

            if parent_name:
                edge = DependencyEdge(
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=name,
                    child_version=str(version),
                    scope=scope,
                )
                graph.add_edge(edge)

            # Recurse for nested dependencies
            sub_deps = info.get("dependencies", {})
            if isinstance(sub_deps, dict) and sub_deps:
                self._parse_v1_dependencies(
                    graph,
                    sub_deps,
                    lock_path,
                    pkg_path,
                    direct_names,
                    dev_names,
                    opt_names,
                    parent_name=name,
                    parent_version=str(version),
                )

    def _populate_manifest_only(
        self,
        graph: DependencyGraph,
        pkg_path: Path,
        direct: set[str],
        dev: set[str],
        peer: set[str],
        opt: set[str],
    ) -> None:
        """Create direct unpinned components from package.json when lockfile is absent."""
        try:
            content = pkg_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception:
            return

        all_specs: list[tuple[dict[str, str], DependencyScope]] = [
            (data.get("dependencies", {}), DependencyScope.RUNTIME),
            (data.get("devDependencies", {}), DependencyScope.DEV),
            (data.get("peerDependencies", {}), DependencyScope.PEER),
            (data.get("optionalDependencies", {}), DependencyScope.OPTIONAL),
        ]

        for dep_dict, scope in all_specs:
            if not isinstance(dep_dict, dict):
                continue
            for name, constraint in dep_dict.items():
                node = DependencyNode.create(
                    name=name,
                    version=None,
                    ecosystem=Ecosystem.NPM,
                    source_file=str(pkg_path),
                    is_direct=True,
                    scope=scope,
                    manifest_source=str(pkg_path),
                    version_constraint=str(constraint),
                )
                node.version_type = VersionType.RANGE
                graph.add_node(node)

    @staticmethod
    def _extract_package_names_from_path(path_key: str) -> tuple[str, str | None, bool]:
        """Extract component name and immediate parent package name from a node_modules path."""
        parts = path_key.split("node_modules/")
        if len(parts) <= 1:
            return "", None, False

        # Last part is the package name (could be scoped, e.g. @scope/pkg)
        name = parts[-1].strip("/")
        if not name:
            return "", None, False

        if len(parts) > 2:
            # Nested dependency
            parent_part = parts[-2].strip("/")
            parent_name = parent_part.split("/")[-1] if "/" in parent_part else parent_part
            return name, parent_name, True

        return name, None, False
