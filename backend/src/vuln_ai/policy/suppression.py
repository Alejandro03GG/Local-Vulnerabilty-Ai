"""Suppression matching and filtering engine (Etapa 16 §8, §9, §10).

Provides deterministic in-memory matching of suppression records against
security findings.
"""

from __future__ import annotations

from vuln_ai.core.models import MatchResult, normalize_component_name
from vuln_ai.policy.clock import Clock, SystemClock
from vuln_ai.policy.models import Suppression


class SuppressionMatcher:
    """Matches suppressions against findings."""

    @staticmethod
    def matches_finding(
        suppression: Suppression,
        match: MatchResult,
        project_id: str | None = None,
        finding_id: str | None = None,
    ) -> bool:
        """Evaluate if suppression criteria match the given finding."""
        crit = suppression.match_criteria

        # If project_id is scoped on suppression and does not match, reject
        if (
            suppression.project_id is not None
            and project_id is not None
            and suppression.project_id.strip() != project_id.strip()
        ):
            return False

        has_criteria = False

        # If finding_id is specified
        if crit.finding_id:
            has_criteria = True
            if not finding_id or crit.finding_id.strip() != finding_id.strip():
                return False

        # 1. Vulnerability ID match (canonical_id, cve_id, or any identifier alias)
        if crit.vulnerability_id:
            has_criteria = True
            target_vid = crit.vulnerability_id.strip().upper()
            vuln = match.vulnerability

            all_ids: set[str] = set()
            if vuln.canonical_id:
                all_ids.add(vuln.canonical_id.strip().upper())
            if vuln.cve_id:
                all_ids.add(vuln.cve_id.strip().upper())
            for ident in vuln.identifiers:
                if ident.identifier:
                    all_ids.add(ident.identifier.strip().upper())

            if target_vid not in all_ids:
                return False

        # 2. Package Name match (normalized)
        if crit.package_name:
            has_criteria = True
            norm_target = normalize_component_name(crit.package_name)
            norm_actual = normalize_component_name(match.component.name)
            if norm_target != norm_actual:
                return False

        # 3. Ecosystem match
        if crit.ecosystem:
            has_criteria = True
            eco_target = str(crit.ecosystem).strip().lower()
            eco_actual = (
                str(
                    match.component.ecosystem.value
                    if hasattr(match.component.ecosystem, "value")
                    else match.component.ecosystem
                )
                .strip()
                .lower()
            )
            if eco_target != eco_actual:
                return False

        # 4. Package Version match
        if crit.package_version:
            has_criteria = True
            if (
                not match.component.version
                or crit.package_version.strip() != match.component.version.strip()
            ):
                return False

        # 5. Image Digest match
        if crit.image_digest:
            has_criteria = True
            comp_meta = match.component.metadata or {}
            actual_digest = (
                comp_meta.get("container_digest") or comp_meta.get("image_digest") or ""
            )
            if actual_digest.strip() != crit.image_digest.strip():
                return False

        # To prevent empty criteria from matching everything
        return has_criteria

    @classmethod
    def find_matching_suppressions(
        cls,
        suppressions: list[Suppression],
        match: MatchResult,
        clock: Clock | None = None,
        project_id: str | None = None,
        finding_id: str | None = None,
    ) -> tuple[Suppression | None, list[Suppression]]:
        """Find active suppression (if any) and all matched suppressions (including expired).

        Returns:
            (active_suppression, all_matched_suppressions)
        """
        active_clock = clock or SystemClock()
        matched: list[Suppression] = []
        active_match: Suppression | None = None

        for sup in suppressions:
            if cls.matches_finding(sup, match, project_id=project_id, finding_id=finding_id):
                matched.append(sup)
                if active_match is None and sup.is_active(active_clock):
                    active_match = sup

        return active_match, matched
