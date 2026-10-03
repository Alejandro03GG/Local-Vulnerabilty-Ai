"""Deterministic vulnerability matcher.

Matches detected components against known vulnerabilities
using conservative, rule-based logic. No AI involved.

Pipeline:
1. Name matching (exact product, vendor, normalized)
2. Version-aware range evaluation (when affected_ranges exist)
3. Evidence generation (structured + legacy summary)
"""

from __future__ import annotations

import logging

from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    EvidenceType,
    MatchEvidence,
    MatchResult,
    MatchType,
    VulnerabilityRecord,
    normalize_component_name,
)
from vuln_ai.matching.version import evaluate_component_ranges

logger = logging.getLogger(__name__)


class VulnerabilityMatcher:
    """Matches project components against known vulnerabilities.

    The matcher uses conservative, deterministic rules:
    1. Exact normalized name match against product
    2. Exact normalized name match against affected_ranges package names
    3. Vendor + product match
    4. Normalized substring match (conservative)

    After name matching, version-aware range evaluation refines the
    applicability from DETECTED to LIKELY_AFFECTED / LIKELY_NOT_AFFECTED.

    Important: CISA KEV does NOT include version ranges.
    Therefore, a match only means the component NAME appears
    in the vulnerability catalog. The match is marked as
    DETECTED or UNKNOWN — never LIKELY_AFFECTED — until
    version information can be confirmed via other sources.
    """

    def match(
        self,
        components: list[DetectedComponent],
        vulnerabilities: list[VulnerabilityRecord],
    ) -> list[MatchResult]:
        """Match components against vulnerabilities.

        Args:
            components: Detected project components.
            vulnerabilities: Known vulnerability records.

        Returns:
            List of match results with evidence.
        """
        results: list[MatchResult] = []

        if not components or not vulnerabilities:
            return results

        # Build lookup indexes for efficient matching
        vuln_by_product: dict[str, list[VulnerabilityRecord]] = {}
        vuln_by_vendor: dict[str, list[VulnerabilityRecord]] = {}
        vuln_by_range_pkg: dict[str, list[VulnerabilityRecord]] = {}

        for vuln in vulnerabilities:
            norm_product = vuln.normalized_product()
            norm_vendor = vuln.normalized_vendor()

            vuln_by_product.setdefault(norm_product, []).append(vuln)
            vuln_by_vendor.setdefault(norm_vendor, []).append(vuln)

            # Index by normalized package names in affected_ranges
            for ar in vuln.affected_ranges:
                norm_pkg = normalize_component_name(ar.package_name)
                if norm_pkg:
                    vuln_by_range_pkg.setdefault(norm_pkg, []).append(vuln)

        # Match each component
        for component in components:
            component_matches = self._match_component(
                component, vuln_by_product, vuln_by_vendor, vuln_by_range_pkg
            )
            results.extend(component_matches)

        logger.info(
            "Matching complete: %d components, %d vulnerabilities, %d matches",
            len(components),
            len(vulnerabilities),
            len(results),
        )

        return results

    def _match_component(
        self,
        component: DetectedComponent,
        vuln_by_product: dict[str, list[VulnerabilityRecord]],
        vuln_by_vendor: dict[str, list[VulnerabilityRecord]],
        vuln_by_range_pkg: dict[str, list[VulnerabilityRecord]],
    ) -> list[MatchResult]:
        """Find vulnerabilities matching a single component."""
        results: list[MatchResult] = []
        norm_name = component.normalized_name()

        if not norm_name:
            return results

        # Track already-matched canonical IDs to avoid duplicates
        matched_ids: set[str] = set()

        # Strategy 1: Exact product name match
        if norm_name in vuln_by_product:
            for vuln in vuln_by_product[norm_name]:
                if vuln.canonical_id not in matched_ids:
                    matched_ids.add(vuln.canonical_id)
                    results.append(
                        self._create_match(
                            component,
                            vuln,
                            MatchType.EXACT_NAME,
                            confidence=0.7,
                            evidence=[
                                f"Component '{component.name}' matches product "
                                f"'{vuln.product}' (normalized: '{norm_name}')",
                                f"Found in {component.source_file}",
                                f"Source: {vuln.source_name}",
                            ],
                        )
                    )

        # Strategy 2: Affected range package name match
        if norm_name in vuln_by_range_pkg:
            for vuln in vuln_by_range_pkg[norm_name]:
                if vuln.canonical_id not in matched_ids:
                    matched_ids.add(vuln.canonical_id)
                    results.append(
                        self._create_match(
                            component,
                            vuln,
                            MatchType.NORMALIZED,
                            confidence=0.8,
                            evidence=[
                                f"Component '{component.name}' matches affected_range "
                                f"package name (normalized: '{norm_name}')",
                                f"Found in {component.source_file}",
                                f"Source: {vuln.source_name}",
                            ],
                        )
                    )

        # Strategy 3: Vendor name match (lower confidence)
        if norm_name in vuln_by_vendor:
            for vuln in vuln_by_vendor[norm_name]:
                if vuln.canonical_id not in matched_ids:
                    matched_ids.add(vuln.canonical_id)
                    results.append(
                        self._create_match(
                            component,
                            vuln,
                            MatchType.VENDOR_PRODUCT,
                            confidence=0.4,
                            evidence=[
                                f"Component '{component.name}' matches vendor "
                                f"'{vuln.vendor_project}' (normalized: '{norm_name}')",
                                f"Product: '{vuln.product}'",
                                f"Found in {component.source_file}",
                                f"Source: {vuln.source_name}",
                                "Note: Match is by vendor name, not product. "
                                "This may be a false positive.",
                            ],
                        )
                    )

        return results

    def _create_match(
        self,
        component: DetectedComponent,
        vulnerability: VulnerabilityRecord,
        match_type: MatchType,
        confidence: float,
        evidence: list[str],
    ) -> MatchResult:
        """Create a match result with version-aware applicability when possible."""
        # Add version evidence
        if component.version:
            evidence.append(
                f"Installed version: {component.version} (type: {component.version_type.value})"
            )
        else:
            evidence.append("Version: not determined")

        # --- Version-aware evaluation ---
        structured_evidences: list[MatchEvidence] = []

        if vulnerability.affected_ranges:
            applicability, structured_evidences = evaluate_component_ranges(
                component,
                vulnerability.affected_ranges,
                vulnerability.canonical_id,
            )

            # Generate human-readable evidence from structured evaluation
            for ev in structured_evidences:
                evidence.append(f"[{ev.source_name}] Range evaluation: {ev.details}")

            # Adjust confidence based on version evaluation
            if applicability == Applicability.LIKELY_AFFECTED:
                confidence = min(confidence + 0.2, 1.0)
            elif applicability == Applicability.LIKELY_NOT_AFFECTED:
                confidence = max(confidence - 0.2, 0.1)

        else:
            # No affected ranges → name-only match
            applicability = self._name_only_applicability(match_type)
            evidence.append(
                "Note: No version ranges available from any source. "
                "Cannot confirm version-level applicability."
            )
            structured_evidences.append(
                MatchEvidence(
                    source_name=vulnerability.source_name,
                    identifier=vulnerability.canonical_id,
                    package_name=component.name,
                    ecosystem=component.ecosystem,
                    installed_version=component.version,
                    affected_range=None,
                    fixed_version=None,
                    status=applicability,
                    evidence_type=EvidenceType.PRODUCT_NAME_ONLY,
                    details=(
                        f"Name match only ({match_type.value}). "
                        f"No affected version ranges available."
                    ),
                )
            )

        return MatchResult(
            component=component,
            vulnerability=vulnerability,
            match_type=match_type,
            match_confidence=confidence,
            applicability=applicability,
            evidence=evidence,
            structured_evidences=structured_evidences,
        )

    @staticmethod
    def _name_only_applicability(match_type: MatchType) -> Applicability:
        """Determine applicability when only name matching is available."""
        if match_type == MatchType.EXACT_NAME:
            return Applicability.DETECTED
        if match_type == MatchType.NORMALIZED:
            return Applicability.DETECTED
        return Applicability.UNKNOWN
