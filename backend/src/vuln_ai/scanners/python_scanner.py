"""Python project scanner.

Detects Python dependencies from:
- requirements.txt
- pyproject.toml (PEP 621 dependencies and optional-dependencies)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from vuln_ai.core.models import (
    ComponentType,
    DetectedComponent,
    Ecosystem,
    VersionType,
)

logger = logging.getLogger(__name__)

# Regex for parsing requirements.txt lines
# Matches: package_name[extras]==version, >=version, etc.
# Handles: name, name==1.0, name>=1.0,<2.0, name[extra]>=1.0
_REQ_LINE_RE = re.compile(
    r"""
    ^
    (?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)  # package name
    (?:\[.*?\])?                                           # optional extras
    \s*
    (?P<constraint>[=!<>~]=?.*)?\s*                        # version constraint
    $
    """,
    re.VERBOSE,
)

# Version specifier pattern for extracting exact version
_EXACT_VERSION_RE = re.compile(r"^==\s*([^\s,;]+)")


class PythonScanner:
    """Scanner for Python projects.

    Detects dependencies from requirements.txt and pyproject.toml.
    """

    @property
    def name(self) -> str:
        return "Python Scanner"

    @property
    def ecosystem(self) -> str:
        return "pypi"

    def can_scan(self, project_path: Path) -> bool:
        """Check if the project has Python dependency files."""
        return (project_path / "requirements.txt").is_file() or (
            project_path / "pyproject.toml"
        ).is_file()

    def scan(self, project_path: Path) -> list[DetectedComponent]:
        """Scan for Python dependencies."""
        components: list[DetectedComponent] = []

        # Scan requirements.txt
        req_file = project_path / "requirements.txt"
        if req_file.is_file():
            components.extend(self._parse_requirements(req_file))

        # Scan pyproject.toml
        pyproject_file = project_path / "pyproject.toml"
        if pyproject_file.is_file():
            components.extend(self._parse_pyproject(pyproject_file))

        return components

    def _parse_requirements(self, filepath: Path) -> list[DetectedComponent]:
        """Parse a requirements.txt file."""
        components: list[DetectedComponent] = []

        try:
            content = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("Failed to read %s: %s", filepath, exc)
            return components

        for _line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()

            # Skip empty lines, comments, options, and -r includes
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Skip URL-based dependencies (e.g., git+https://...)
            if "://" in line:
                continue

            component = self._parse_requirement_line(line, str(filepath))
            if component is not None:
                components.append(component)

        logger.debug("Parsed %d components from %s", len(components), filepath)
        return components

    def _parse_requirement_line(self, line: str, source_file: str) -> DetectedComponent | None:
        """Parse a single requirement line."""
        # Remove inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()

        # Remove environment markers (e.g., ; python_version >= "3.8")
        if ";" in line:
            line = line[: line.index(";")].strip()

        match = _REQ_LINE_RE.match(line)
        if match is None:
            return None

        name = match.group("name")
        constraint = match.group("constraint")

        version, version_type, version_constraint = self._parse_version_spec(constraint)

        return DetectedComponent(
            name=name,
            version=version,
            version_type=version_type,
            version_constraint=version_constraint,
            ecosystem=Ecosystem.PYPI,
            source_file=source_file,
            component_type=ComponentType.LIBRARY,
        )

    def _parse_pyproject(self, filepath: Path) -> list[DetectedComponent]:
        """Parse a pyproject.toml file for dependencies.

        Uses a simple TOML parser to avoid adding tomli/tomllib as dependency.
        Python 3.11+ has tomllib in stdlib.
        """
        components: list[DetectedComponent] = []

        try:
            content = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("Failed to read %s: %s", filepath, exc)
            return components

        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                logger.warning(
                    "Cannot parse pyproject.toml: tomllib (Python 3.11+) or tomli not available"
                )
                return components

        try:
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", filepath, exc)
            return components

        # PEP 621: [project.dependencies]
        project = data.get("project", {})
        deps = project.get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:
                component = self._parse_requirement_line(str(dep), str(filepath))
                if component is not None:
                    components.append(component)

        # PEP 621: [project.optional-dependencies]
        optional_deps = project.get("optional-dependencies", {})
        if isinstance(optional_deps, dict):
            for group_deps in optional_deps.values():
                if isinstance(group_deps, list):
                    for dep in group_deps:
                        component = self._parse_requirement_line(str(dep), str(filepath))
                        if component is not None:
                            components.append(component)

        logger.debug("Parsed %d components from %s", len(components), filepath)
        return components

    @staticmethod
    def _parse_version_spec(
        constraint: str | None,
    ) -> tuple[str | None, VersionType, str | None]:
        """Parse a version specifier string.

        Returns:
            Tuple of (exact_version_or_None, version_type, original_constraint)
        """
        if not constraint:
            return None, VersionType.UNKNOWN, None

        constraint = constraint.strip()
        if not constraint:
            return None, VersionType.UNKNOWN, None

        # Check for exact version: ==X.Y.Z
        exact_match = _EXACT_VERSION_RE.match(constraint)
        if exact_match:
            return exact_match.group(1), VersionType.EXACT, constraint

        # Check for minimum version: >=X.Y.Z (without upper bound comma)
        if constraint.startswith(">=") and "," not in constraint:
            return None, VersionType.MINIMUM, constraint

        # Everything else is a range
        return None, VersionType.RANGE, constraint
