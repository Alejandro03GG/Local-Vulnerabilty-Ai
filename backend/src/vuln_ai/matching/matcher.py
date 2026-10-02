"""Deterministic vulnerability matcher.

Matches detected components against known vulnerabilities
using conservative, rule-based logic. No AI involved.
"""

from __future__ import annotations

import logging

from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    MatchResult,
    MatchType,
    VulnerabilityRecord,
)

logger = logging.getLogger(__name__)


class VulnerabilityMatcher:
    """Matches project components against known vulnerabilities.

    The matcher uses conservative, deterministic rules:
    1. Exact normalized name match against product
    2. Vendor + product match
    3. Normalized substring match (conservative)

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

        for vuln in vulnerabilities:
            norm_product = vuln.normalized_product()
            norm_vendor = vuln.normalized_vendor()

            vuln_by_product.setdefault(norm_product, []).append(vuln)
            vuln_by_vendor.setdefault(norm_vendor, []).append(vuln)

        # Match each component
        for component in components:
            component_matches = self._match_component(component, vuln_by_product, vuln_by_vendor)
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
    ) -> list[MatchResult]:
        """Find vulnerabilities matching a single component."""
        results: list[MatchResult] = []
        norm_name = component.normalized_name()

        if not norm_name:
            return results

        # Track already-matched CVEs to avoid duplicates
        matched_cves: set[str] = set()

        # Strategy 1: Exact product name match
        if norm_name in vuln_by_product:
            for vuln in vuln_by_product[norm_name]:
                if vuln.cve_id not in matched_cves:
                    matched_cves.add(vuln.cve_id)
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

        # Strategy 2: Vendor name match (lower confidence)
        if norm_name in vuln_by_vendor:
            for vuln in vuln_by_vendor[norm_name]:
                if vuln.cve_id not in matched_cves:
                    matched_cves.add(vuln.cve_id)
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
        """Create a match result with appropriate applicability."""
        # Add version evidence
        if component.version:
            evidence.append(
                f"Installed version: {component.version} (type: {component.version_type.value})"
            )
        else:
            evidence.append("Version: not determined")

        # KEV limitation evidence
        evidence.append(
            "Note: CISA KEV does not provide version ranges. "
            "Cannot confirm version-level applicability."
        )

        # Determine applicability
        # With KEV alone, we can only say DETECTED or UNKNOWN
        applicability = Applicability.UNKNOWN
        if match_type == MatchType.EXACT_NAME:
            applicability = Applicability.DETECTED

        return MatchResult(
            component=component,
            vulnerability=vulnerability,
            match_type=match_type,
            match_confidence=confidence,
            applicability=applicability,
            evidence=evidence,
        )
