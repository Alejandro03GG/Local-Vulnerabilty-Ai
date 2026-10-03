"""Version parsing, comparison, and range evaluation — per-ecosystem strategies.

This module is the core of the version-aware matcher.  It is 100 % deterministic:
no LLMs, no embeddings, no probabilistic inference.

Supported strategies:
- PEP 440  → PyPI  (delegated to ``packaging.version``)
- SemVer   → npm, Cargo, Go, NuGet  (delegated to ``semver``)
- Maven    → Maven  (custom comparator following Maven version ordering)
- OS pkgs  → deb, apk, rpm  (normalized upstream versions via ``packaging.version``)

Any ecosystem that does not have a registered strategy will yield
``Applicability.UNKNOWN`` so the system never over-claims.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import packaging.version
import semver

from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    DetectedComponent,
    Ecosystem,
    EvidenceType,
    MatchEvidence,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public result type
# ---------------------------------------------------------------------------


class RangeVerdict(StrEnum):
    """Outcome of evaluating a single affected range against an installed version."""

    WITHIN = "within"  # Version falls inside the affected range
    OUTSIDE = "outside"  # Version is outside the affected range
    UNKNOWN = "unknown"  # Cannot determine (e.g. unparseable version)


@dataclass(frozen=True, slots=True)
class VersionEvaluation:
    """Complete evaluation of one installed version against one affected range."""

    verdict: RangeVerdict
    range_ref: AffectedVersionRange
    installed_version: str
    details: str  # Human-readable explanation


# ---------------------------------------------------------------------------
# Abstract base strategy
# ---------------------------------------------------------------------------


class VersionStrategy(ABC):
    """Base class for ecosystem-specific version parsing & comparison."""

    @abstractmethod
    def parse(self, version_str: str) -> object | None:
        """Parse a version string.  Return ``None`` if unparseable."""

    @abstractmethod
    def compare(self, a: object, b: object) -> int:
        """Return -1, 0, or 1 comparing parsed versions *a* and *b*."""

    def is_valid(self, version_str: str) -> bool:
        """Return whether *version_str* can be parsed."""
        return self.parse(version_str) is not None

    # -- High-level evaluation --

    def evaluate_range(
        self,
        installed_str: str,
        affected: AffectedVersionRange,
    ) -> VersionEvaluation:
        """Evaluate whether *installed_str* falls inside *affected*.

        Range semantics:
        - ``introduced`` + ``fixed``         → [introduced, fixed)
        - ``introduced`` + ``limit``         → [introduced, limit)  (OSV exclusive bound)
        - ``introduced`` + ``last_affected`` → [introduced, last_affected]
        - ``introduced`` only (open range)   → [introduced, ∞)
        - ``introduced`` = "0" or None       → range starts at the beginning of time
        """
        installed = self.parse(installed_str)
        if installed is None:
            return VersionEvaluation(
                verdict=RangeVerdict.UNKNOWN,
                range_ref=affected,
                installed_version=installed_str,
                details=f"Cannot parse installed version '{installed_str}' for "
                f"{affected.ecosystem}/{affected.package_name}",
            )

        intro_str = affected.introduced
        fixed_str = affected.fixed
        limit_str = affected.limit
        last_aff_str = affected.last_affected

        # Parse range boundaries
        intro = self._parse_intro(intro_str)
        fixed = self.parse(fixed_str) if fixed_str else None
        limit_ver = self.parse(limit_str) if limit_str else None
        last_aff = self.parse(last_aff_str) if last_aff_str else None

        # --- Evaluation logic ---

        # Case 1: introduced + fixed → [introduced, fixed)
        if fixed is not None:
            after_intro = self._at_or_after_intro(installed, intro)
            before_fixed = self.compare(installed, fixed) < 0
            if after_intro and before_fixed:
                return self._within(installed_str, affected, intro_str, f"< {fixed_str}")
            return self._outside(installed_str, affected, intro_str, f"< {fixed_str}")

        # Case 2: introduced + limit → [introduced, limit)  (OSV exclusive upper bound)
        if limit_ver is not None:
            after_intro = self._at_or_after_intro(installed, intro)
            before_limit = self.compare(installed, limit_ver) < 0
            if after_intro and before_limit:
                return self._within(installed_str, affected, intro_str, f"< {limit_str} (limit)")
            return self._outside(installed_str, affected, intro_str, f"< {limit_str} (limit)")

        # Case 3: introduced + last_affected → [introduced, last_affected]
        if last_aff is not None:
            after_intro = self._at_or_after_intro(installed, intro)
            at_or_before_last = self.compare(installed, last_aff) <= 0
            if after_intro and at_or_before_last:
                return self._within(installed_str, affected, intro_str, f"<= {last_aff_str}")
            return self._outside(installed_str, affected, intro_str, f"<= {last_aff_str}")

        # Case 4: open range (introduced only, no upper bound)
        if intro is not None:
            after_intro = self._at_or_after_intro(installed, intro)
            if after_intro:
                return VersionEvaluation(
                    verdict=RangeVerdict.WITHIN,
                    range_ref=affected,
                    installed_version=installed_str,
                    details=(
                        f"Version {installed_str} >= introduced {intro_str} "
                        f"with NO upper bound (open range)"
                    ),
                )
            return self._outside(installed_str, affected, intro_str, "∞ (open)")

        # Case 5: no structured boundaries at all
        return VersionEvaluation(
            verdict=RangeVerdict.UNKNOWN,
            range_ref=affected,
            installed_version=installed_str,
            details=(
                f"No structured range boundaries for {affected.ecosystem}/{affected.package_name}"
            ),
        )

    # -- Helpers --

    def _parse_intro(self, intro_str: str | None) -> object | None:
        """Parse an 'introduced' value.  '0' means 'from the beginning'."""
        if intro_str is None or intro_str.strip() in ("", "0"):
            return None  # from the beginning of time
        return self.parse(intro_str)

    def _at_or_after_intro(self, installed: object, intro: object | None) -> bool:
        """Check if installed >= introduced (None means any version qualifies)."""
        if intro is None:
            return True
        return self.compare(installed, intro) >= 0

    def _within(
        self,
        installed_str: str,
        affected: AffectedVersionRange,
        intro: str | None,
        upper: str,
    ) -> VersionEvaluation:
        intro_desc = intro or "0"
        return VersionEvaluation(
            verdict=RangeVerdict.WITHIN,
            range_ref=affected,
            installed_version=installed_str,
            details=(
                f"Version {installed_str} is WITHIN affected range "
                f"[{intro_desc}, {upper}) for {affected.ecosystem}/{affected.package_name}"
            ),
        )

    def _outside(
        self,
        installed_str: str,
        affected: AffectedVersionRange,
        intro: str | None,
        upper: str,
    ) -> VersionEvaluation:
        intro_desc = intro or "0"
        return VersionEvaluation(
            verdict=RangeVerdict.OUTSIDE,
            range_ref=affected,
            installed_version=installed_str,
            details=(
                f"Version {installed_str} is OUTSIDE affected range "
                f"[{intro_desc}, {upper}) for {affected.ecosystem}/{affected.package_name}"
            ),
        )


# ---------------------------------------------------------------------------
# Concrete strategies
# ---------------------------------------------------------------------------


class PEP440Strategy(VersionStrategy):
    """PEP 440 version parsing for PyPI packages.

    Delegates to ``packaging.version.Version``.
    """

    def parse(self, version_str: str) -> packaging.version.Version | None:
        try:
            return packaging.version.Version(version_str)
        except packaging.version.InvalidVersion:
            return None

    def compare(self, a: object, b: object) -> int:
        assert isinstance(a, packaging.version.Version)
        assert isinstance(b, packaging.version.Version)
        if a < b:
            return -1
        if a > b:
            return 1
        return 0


class SemVerStrategy(VersionStrategy):
    """Semantic Versioning parsing for npm, Cargo, Go, NuGet.

    Delegates to ``semver.Version``.  Tolerant: strips leading 'v' prefix
    and attempts coercion for 2-part versions (e.g. ``1.0`` → ``1.0.0``).
    """

    def parse(self, version_str: str) -> semver.Version | None:
        cleaned = version_str.strip().lstrip("v").lstrip("V")
        # Try strict parse first
        try:
            return semver.Version.parse(cleaned)
        except ValueError:
            pass
        # Try coercion for partial versions
        parts = cleaned.split(".", 2)
        if len(parts) == 2:
            try:
                return semver.Version.parse(f"{parts[0]}.{parts[1]}.0")
            except ValueError:
                pass
        if len(parts) == 1:
            try:
                return semver.Version.parse(f"{parts[0]}.0.0")
            except ValueError:
                pass
        return None

    def compare(self, a: object, b: object) -> int:
        assert isinstance(a, semver.Version)
        assert isinstance(b, semver.Version)
        return a.compare(b)


class MavenStrategy(VersionStrategy):
    """Maven version comparison strategy.

    Implements a simplified Maven version ordering:
    - Split version string by ``-`` and ``.``
    - Compare segments numerically when possible, lexicographically otherwise
    - Qualifiers order: "alpha" < "beta" < "milestone" < "rc" < "snapshot" < "" (release) < "sp"
    """

    _QUALIFIER_ORDER: ClassVar[dict[str, int]] = {
        "alpha": 0,
        "a": 0,
        "beta": 1,
        "b": 1,
        "milestone": 2,
        "m": 2,
        "rc": 3,
        "cr": 3,
        "snapshot": 4,
        "": 5,  # release
        "sp": 6,
    }

    _SPLIT_RE = re.compile(r"[.\-]")

    def parse(self, version_str: str) -> tuple[list[int | str], ...] | None:
        cleaned = version_str.strip()
        if not cleaned:
            return None
        segments = self._SPLIT_RE.split(cleaned)
        parsed: list[int | str] = []
        for seg in segments:
            try:
                parsed.append(int(seg))
            except ValueError:
                parsed.append(seg.lower())
        return (parsed,)

    def compare(self, a: object, b: object) -> int:
        assert isinstance(a, tuple) and isinstance(b, tuple)
        segs_a = a[0]
        segs_b = b[0]
        max_len = max(len(segs_a), len(segs_b))

        for i in range(max_len):
            sa = segs_a[i] if i < len(segs_a) else None
            sb = segs_b[i] if i < len(segs_b) else None

            # Both missing → equal
            if sa is None and sb is None:
                continue

            # Normalize missing segments
            if sa is None:
                sa = self._default_pad(sb)
            if sb is None:
                sb = self._default_pad(sa)

            # Both numeric
            if isinstance(sa, int) and isinstance(sb, int):
                if sa < sb:
                    return -1
                if sa > sb:
                    return 1
                continue

            # Both string (qualifiers)
            if isinstance(sa, str) and isinstance(sb, str):
                oa = self._QUALIFIER_ORDER.get(sa, 99)
                ob = self._QUALIFIER_ORDER.get(sb, 99)
                if oa != ob:
                    return -1 if oa < ob else 1
                if sa < sb:
                    return -1
                if sa > sb:
                    return 1
                continue

            # Mixed: int vs string qualifier
            # In Maven, a numeric segment means 'release', a string segment
            # is a qualifier.  Qualifier ordering relative to release:
            # qualifiers with order < 5 come BEFORE release.
            if isinstance(sa, int) and isinstance(sb, str):
                ob = self._QUALIFIER_ORDER.get(sb, 99)
                release_order = self._QUALIFIER_ORDER[""]  # 5
                if ob < release_order:
                    return 1  # sa (numeric=release) > sb (pre-release qualifier)
                return -1  # sa (numeric=release) < sb (post-release qualifier)

            if isinstance(sa, str) and isinstance(sb, int):
                oa = self._QUALIFIER_ORDER.get(sa, 99)
                release_order = self._QUALIFIER_ORDER[""]  # 5
                if oa < release_order:
                    return -1  # sa (pre-release qualifier) < sb (numeric=release)
                return 1  # sa (post-release qualifier) > sb (numeric=release)

        return 0

    @staticmethod
    def _default_pad(other_seg: int | str) -> int | str:
        """Return the default padding value based on the type of the other segment."""
        if isinstance(other_seg, str):
            return ""  # Compare against release qualifier
        return 0  # Compare against numeric zero


class OSPackageVersionStrategy(VersionStrategy):
    """Loose version comparison for OS package ecosystems (deb, apk, rpm).

    Normalizes packaging revisions commonly found in Linux distributions:
    - Debian/Ubuntu: strip epoch (``1:``) and revision (``-1``, ``-1~deb12u1``)
    - Alpine: strip ``-rN`` revision suffixes
    - RPM: strip release segment after the final ``-`` when present

    Comparison then delegates to ``packaging.version.Version``.
    """

    _EPOCH_RE = re.compile(r"^\d+:")
    _ALPINE_REV_RE = re.compile(r"-r\d+$")

    def _normalize(self, version_str: str) -> str:
        cleaned = version_str.strip()
        cleaned = self._EPOCH_RE.sub("", cleaned)
        cleaned = self._ALPINE_REV_RE.sub("", cleaned)
        # Debian/RPM style revision: keep upstream before first '-' if left side parses
        if "-" in cleaned:
            upstream, _rev = cleaned.split("-", 1)
            try:
                packaging.version.Version(upstream)
                cleaned = upstream
            except packaging.version.InvalidVersion:
                pass
        return cleaned

    def parse(self, version_str: str) -> packaging.version.Version | None:
        cleaned = self._normalize(version_str)
        if not cleaned:
            return None
        try:
            return packaging.version.Version(cleaned)
        except packaging.version.InvalidVersion:
            # Last resort: keep only leading numeric dotted prefix
            match = re.match(r"^(\d+(?:\.\d+)*)", cleaned)
            if not match:
                return None
            try:
                return packaging.version.Version(match.group(1))
            except packaging.version.InvalidVersion:
                return None

    def compare(self, a: object, b: object) -> int:
        assert isinstance(a, packaging.version.Version)
        assert isinstance(b, packaging.version.Version)
        if a < b:
            return -1
        if a > b:
            return 1
        return 0


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------

_STRATEGY_REGISTRY: dict[str, VersionStrategy] = {
    Ecosystem.PYPI: PEP440Strategy(),
    Ecosystem.NPM: SemVerStrategy(),
    Ecosystem.CARGO: SemVerStrategy(),
    Ecosystem.GO: SemVerStrategy(),
    Ecosystem.NUGET: SemVerStrategy(),
    Ecosystem.MAVEN: MavenStrategy(),
    Ecosystem.DEB: OSPackageVersionStrategy(),
    Ecosystem.APK: OSPackageVersionStrategy(),
    Ecosystem.RPM: OSPackageVersionStrategy(),
}


def get_strategy(ecosystem: str | Ecosystem) -> VersionStrategy | None:
    """Return the version strategy for *ecosystem*, or ``None`` if unsupported."""
    key = ecosystem.value if isinstance(ecosystem, Ecosystem) else str(ecosystem).lower()
    return _STRATEGY_REGISTRY.get(key)


# ---------------------------------------------------------------------------
# Public API — evaluate a component against all matching ranges
# ---------------------------------------------------------------------------


def evaluate_component_ranges(
    component: DetectedComponent,
    ranges: list[AffectedVersionRange],
    vulnerability_id: str,
) -> tuple[Applicability, list[MatchEvidence]]:
    """Evaluate a detected component against all relevant affected ranges.

    Filtering rules:
    1. Match by ecosystem + normalized package name first
    2. Then evaluate version within matched ranges

    Returns:
        tuple[Applicability, list[MatchEvidence]]
    """
    from vuln_ai.core.models import normalize_component_name

    evidences: list[MatchEvidence] = []
    comp_ecosystem = (
        component.ecosystem.value
        if isinstance(component.ecosystem, Ecosystem)
        else str(component.ecosystem).lower()
    )
    comp_norm_name = normalize_component_name(component.name)

    # Filter ranges relevant to this component
    relevant: list[AffectedVersionRange] = []
    for r in ranges:
        r_eco = (
            r.ecosystem.value if isinstance(r.ecosystem, Ecosystem) else str(r.ecosystem).lower()
        )
        r_name = normalize_component_name(r.package_name)
        if r_eco == comp_ecosystem and r_name == comp_norm_name:
            relevant.append(r)

    if not relevant:
        # No ranges match this component's ecosystem+name → cannot evaluate
        return Applicability.UNKNOWN, []

    # No installed version → UNKNOWN
    if not component.version:
        for r in relevant:
            evidences.append(
                MatchEvidence(
                    source_name=r.source_name,
                    identifier=vulnerability_id,
                    package_name=component.name,
                    ecosystem=component.ecosystem,
                    installed_version=None,
                    affected_range=r.raw_range,
                    fixed_version=r.fixed,
                    status=Applicability.UNKNOWN,
                    evidence_type=EvidenceType.VERSION_UNKNOWN,
                    details=(
                        f"Affected range exists for {r.ecosystem}/{r.package_name} "
                        f"but installed version is not known"
                    ),
                )
            )
        return Applicability.UNKNOWN, evidences

    # Get strategy
    strategy = get_strategy(comp_ecosystem)
    if strategy is None:
        for r in relevant:
            evidences.append(
                MatchEvidence(
                    source_name=r.source_name,
                    identifier=vulnerability_id,
                    package_name=component.name,
                    ecosystem=component.ecosystem,
                    installed_version=component.version,
                    affected_range=r.raw_range,
                    fixed_version=r.fixed,
                    status=Applicability.UNKNOWN,
                    evidence_type=EvidenceType.VERSION_UNKNOWN,
                    details=(
                        f"No version strategy for ecosystem '{comp_ecosystem}'; "
                        f"cannot evaluate range"
                    ),
                )
            )
        return Applicability.UNKNOWN, evidences

    # Evaluate each range
    has_within = False
    has_unknown = False

    for r in relevant:
        evaluation = strategy.evaluate_range(component.version, r)

        if evaluation.verdict == RangeVerdict.WITHIN:
            has_within = True
            evidences.append(
                MatchEvidence(
                    source_name=r.source_name,
                    identifier=vulnerability_id,
                    package_name=component.name,
                    ecosystem=component.ecosystem,
                    installed_version=component.version,
                    affected_range=r.raw_range,
                    fixed_version=r.fixed,
                    status=Applicability.LIKELY_AFFECTED,
                    evidence_type=EvidenceType.RANGE_CONFIRMED,
                    details=evaluation.details,
                )
            )
        elif evaluation.verdict == RangeVerdict.OUTSIDE:
            evidences.append(
                MatchEvidence(
                    source_name=r.source_name,
                    identifier=vulnerability_id,
                    package_name=component.name,
                    ecosystem=component.ecosystem,
                    installed_version=component.version,
                    affected_range=r.raw_range,
                    fixed_version=r.fixed,
                    status=Applicability.LIKELY_NOT_AFFECTED,
                    evidence_type=EvidenceType.OUTSIDE_RANGE,
                    details=evaluation.details,
                )
            )
        else:
            has_unknown = True
            evidences.append(
                MatchEvidence(
                    source_name=r.source_name,
                    identifier=vulnerability_id,
                    package_name=component.name,
                    ecosystem=component.ecosystem,
                    installed_version=component.version,
                    affected_range=r.raw_range,
                    fixed_version=r.fixed,
                    status=Applicability.UNKNOWN,
                    evidence_type=EvidenceType.VERSION_UNKNOWN,
                    details=evaluation.details,
                )
            )

    # Determine aggregate applicability
    if has_within:
        return Applicability.LIKELY_AFFECTED, evidences
    if has_unknown:
        return Applicability.UNKNOWN, evidences
    return Applicability.LIKELY_NOT_AFFECTED, evidences
