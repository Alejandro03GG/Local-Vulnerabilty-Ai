"""Multi-source conflict resolution and applicability consolidation.

This module provides deterministic, auditable reconciliation of multi-source
vulnerability intelligence (OSV, NVD, CISA KEV).

Pipeline position:
    Version-aware Matcher (produces individual MatchEvidence)
            ↓
    ConflictResolver (differentiates COMPLEMENTARY from CONFLICTING signals)
            ↓
    Consolidated Applicability (LIKELY_AFFECTED, LIKELY_NOT_AFFECTED, REQUIRES_REVIEW, etc.)
            ↓
    Deterministic Risk Engine

Design Principles:
1. Original evidence preservation: Individual MatchEvidence objects are NEVER mutated or discarded.
2. 100% Deterministic: No LLMs, no SystemOne, no heuristic voting, no probabilistic guesswork.
3. No arbitrary truth: OSV, NVD, and CISA are treated on their technical merits per field.
4. Distinction between Complementary vs Conflicting:
   - Complementary: Different dimensions (OSV range + NVD CVSS + CISA KEV exploitation).
   - Conflicting: Same dimension, incompatible verdicts (OSV says OUTSIDE, NVD says WITHIN).
5. KEV does not forge applicability: Presence in CISA KEV without matching range does not
   override a verified OUTSIDE range verdict.
"""

from __future__ import annotations

import enum
import logging
from typing import Any

from pydantic import BaseModel, Field

from vuln_ai.core.models import (
    Applicability,
    MatchEvidence,
    MatchResult,
    VulnerabilityRecord,
)

logger = logging.getLogger(__name__)


# --- Enums & Domain Models ---


class ConflictType(enum.StrEnum):
    """Categorization of discrepancies between vulnerability intelligence sources."""

    APPLICABILITY = "applicability"
    AFFECTED_RANGE = "affected_range"
    SEVERITY = "severity"
    CVSS = "cvss"
    IDENTIFIER = "identifier"
    METADATA = "metadata"


class ConflictSeverity(enum.StrEnum):
    """Impact severity of a detected conflict."""

    HIGH = "high"  # Direct contradiction affecting applicability or triage
    MEDIUM = "medium"  # Noticeable discrepancy in severity, CVSS, or range boundaries
    LOW = "low"  # Minor syntactic or non-blocking metadata divergence


class ConflictResolutionStatus(enum.StrEnum):
    """Status or outcome of conflict evaluation."""

    COMPLEMENTARY = "complementary"
    CONSENSUS = "consensus"
    REQUIRES_REVIEW = "requires_review"
    UNRESOLVED = "unresolved"


class SourceConflict(BaseModel):
    """Auditable record of a discrepancy between vulnerability sources."""

    conflict_type: ConflictType | str = Field(description="Category of conflict")
    severity: ConflictSeverity | str = Field(description="Severity impact of the conflict")
    field: str = Field(description="Domain attribute where divergence was observed")
    sources: list[str] = Field(
        default_factory=list,
        description="Names of sources exhibiting discrepancy",
    )
    identifiers: list[str] = Field(
        default_factory=list,
        description="Identifiers referenced by the conflicting sources",
    )
    values: dict[str, Any] = Field(
        default_factory=dict,
        description="Reported values mapped by source name",
    )
    resolution: str = Field(
        description="Consolidated resolution decision (e.g. REQUIRES_REVIEW, CONSENSUS_AFFECTED)"
    )
    rationale: str = Field(default="", description="Detailed auditable explanation of decision")


class ApplicabilityResolution(BaseModel):
    """Consolidated applicability outcome derived from evaluating all source evidences."""

    status: Applicability = Field(description="Consolidated applicability classification")
    source_count: int = Field(
        default=0, description="Total distinct sources contributing evidence"
    )
    affected_source_count: int = Field(
        default=0, description="Sources confirming installed version is affected"
    )
    not_affected_source_count: int = Field(
        default=0, description="Sources confirming installed version is not affected"
    )
    unknown_source_count: int = Field(
        default=0, description="Sources unable to determine version applicability"
    )
    detected_source_count: int = Field(
        default=0, description="Sources confirming catalog presence without range bounds"
    )
    conflict_detected: bool = Field(
        default=False,
        description="True if an unresolvable contradiction between sources requires human triage",
    )
    conflicts: list[SourceConflict] = Field(
        default_factory=list,
        description="Structured conflict records",
    )
    supporting_evidence: list[str] = Field(
        default_factory=list,
        description="Auditable evidence strings supporting the consolidated status",
    )
    contradicting_evidence: list[str] = Field(
        default_factory=list,
        description="Auditable evidence strings contradicting or creating tension",
    )
    rationale: str = Field(default="", description="Comprehensive audit summary of the resolution")
    requires_human_review: bool = Field(
        default=False,
        description="Whether a human security analyst must review the discrepancy",
    )


# --- Conflict Resolver ---


class ConflictResolver:
    """Deterministic, auditable resolver for multi-source vulnerability intelligence.

    Distinguishes COMPLEMENTARY evidence (e.g. OSV range + NVD CVSS + CISA KEV)
    from actual CONFLICTING evidence (e.g. OSV says OUTSIDE while NVD says WITHIN).
    """

    def resolve_applicability(
        self,
        evidences: list[MatchEvidence],
        vulnerability: VulnerabilityRecord | None = None,
        installed_version: str | None = None,
    ) -> ApplicabilityResolution:
        """Resolve multi-source applicability without mutating original evidence records.

        Args:
            evidences: Individual MatchEvidence records produced by the matcher/sources.
            vulnerability: Optional canonical VulnerabilityRecord providing additional context.
            installed_version: Installed component version evaluated.

        Returns:
            ApplicabilityResolution with consolidated status, audit trail, and any conflicts.
        """
        if not evidences:
            return ApplicabilityResolution(
                status=Applicability.UNKNOWN,
                source_count=0,
                rationale="No source evidence records provided for evaluation.",
                requires_human_review=True,
            )

        # 1. Group evidences by source name
        evidences_by_source: dict[str, list[MatchEvidence]] = {}
        for ev in evidences:
            evidences_by_source.setdefault(ev.source_name, []).append(ev)

        # Also incorporate any sources recorded in vulnerability.source_records if not in evidences
        if vulnerability:
            for sr in getattr(vulnerability, "source_records", []):
                if sr.source_name not in evidences_by_source:
                    # Source contributed metadata/KEV but had no version range evaluation
                    evidences_by_source.setdefault(sr.source_name, [])

        # 2. Determine per-source stance on version applicability
        source_stances: dict[str, Applicability] = {}
        for src, src_evs in evidences_by_source.items():
            if not src_evs:
                # Source exists in catalog without specific range evidence (e.g. CISA KEV)
                source_stances[src] = Applicability.DETECTED
                continue

            statuses = {ev.status for ev in src_evs}

            if Applicability.LIKELY_AFFECTED in statuses:
                # If any range from this source evaluates to WITHIN, the source considers it affected
                source_stances[src] = Applicability.LIKELY_AFFECTED
            elif Applicability.LIKELY_NOT_AFFECTED in statuses:
                # If source evaluated ranges and none matched WITHIN, but at least one was OUTSIDE
                source_stances[src] = Applicability.LIKELY_NOT_AFFECTED
            elif Applicability.DETECTED in statuses:
                source_stances[src] = Applicability.DETECTED
            else:
                source_stances[src] = Applicability.UNKNOWN

        affected_sources = sorted(
            [s for s, st in source_stances.items() if st == Applicability.LIKELY_AFFECTED]
        )
        not_affected_sources = sorted(
            [s for s, st in source_stances.items() if st == Applicability.LIKELY_NOT_AFFECTED]
        )
        detected_sources = sorted(
            [s for s, st in source_stances.items() if st == Applicability.DETECTED]
        )
        unknown_sources = sorted(
            [s for s, st in source_stances.items() if st == Applicability.UNKNOWN]
        )

        source_count = len(source_stances)
        conflicts: list[SourceConflict] = []
        supporting: list[str] = []
        contradicting: list[str] = []

        # Collect evidence summaries
        for src, src_evs in evidences_by_source.items():
            stance = source_stances[src]
            for ev in src_evs:
                summary_str = f"[{src}] {ev.status.value}: {ev.details or ev.evidence_type}"
                if stance in (Applicability.LIKELY_AFFECTED, Applicability.LIKELY_NOT_AFFECTED):
                    supporting.append(summary_str)

        # 3. Evaluate Applicability Discrepancies vs Consensus

        # --- Case A: REAL CONFLICT (AFFECTED vs NOT_AFFECTED) ---
        if affected_sources and not_affected_sources:
            conflict_val = {s: "LIKELY_AFFECTED" for s in affected_sources}
            conflict_val.update({s: "LIKELY_NOT_AFFECTED" for s in not_affected_sources})

            contradicting.extend(
                [
                    f"[{s}] reports LIKELY_NOT_AFFECTED for version '{installed_version}'"
                    for s in not_affected_sources
                ]
            )

            conflict = SourceConflict(
                conflict_type=ConflictType.APPLICABILITY,
                severity=ConflictSeverity.HIGH,
                field="applicability",
                sources=sorted(affected_sources + not_affected_sources),
                identifiers=(
                    [vulnerability.canonical_id]
                    if vulnerability and vulnerability.canonical_id
                    else []
                ),
                values=conflict_val,
                resolution="REQUIRES_REVIEW",
                rationale=(
                    f"Sources directly disagree on version '{installed_version}': "
                    f"{affected_sources} report affected, while {not_affected_sources} report not affected."
                ),
            )
            conflicts.append(conflict)

            return ApplicabilityResolution(
                status=Applicability.REQUIRES_REVIEW,
                source_count=source_count,
                affected_source_count=len(affected_sources),
                not_affected_source_count=len(not_affected_sources),
                unknown_source_count=len(unknown_sources),
                detected_source_count=len(detected_sources),
                conflict_detected=True,
                conflicts=conflicts,
                supporting_evidence=supporting,
                contradicting_evidence=contradicting,
                rationale=(
                    f"Applicability conflict detected for version '{installed_version}': "
                    f"{', '.join(affected_sources)} report LIKELY_AFFECTED, but "
                    f"{', '.join(not_affected_sources)} report LIKELY_NOT_AFFECTED. "
                    "Consolidated status set to REQUIRES_REVIEW."
                ),
                requires_human_review=True,
            )

        # --- Case B: CONSENSUS AFFECTED (1+ sources affected, 0 sources not affected) ---
        if affected_sources and not not_affected_sources:
            # Check if there are different range bounds among sources that both encompass the version
            range_values: dict[str, str] = {}
            for ev in evidences:
                if (
                    ev.source_name in affected_sources
                    and ev.affected_range
                    and ev.status == Applicability.LIKELY_AFFECTED
                ):
                    range_values[ev.source_name] = ev.affected_range

            if len(set(range_values.values())) > 1:
                # Sources report different ranges, but both include installed_version (Test 9)
                conflicts.append(
                    SourceConflict(
                        conflict_type=ConflictType.AFFECTED_RANGE,
                        severity=ConflictSeverity.LOW,
                        field="affected_range",
                        sources=sorted(list(range_values.keys())),
                        identifiers=(
                            [vulnerability.canonical_id]
                            if vulnerability and vulnerability.canonical_id
                            else []
                        ),
                        values=range_values,
                        resolution="CONSENSUS_AFFECTED",
                        rationale=(
                            f"Sources report different affected range boundaries {range_values}, "
                            f"but all encompass installed version '{installed_version}'. "
                            "Consensus applicability: LIKELY_AFFECTED."
                        ),
                    )
                )

            # Unknown or detected sources are complementary and do not contradict
            rationale_notes: list[str] = [
                f"{len(affected_sources)} source(s) ({', '.join(affected_sources)}) confirm version '{installed_version}' is within affected range."
            ]
            if detected_sources:
                rationale_notes.append(
                    f"Additional catalog presence confirmed by {', '.join(detected_sources)} (complementary)."
                )
            if unknown_sources:
                rationale_notes.append(
                    f"Inconclusive version data from {', '.join(unknown_sources)} does not contradict confirmed range."
                )

            return ApplicabilityResolution(
                status=Applicability.LIKELY_AFFECTED,
                source_count=source_count,
                affected_source_count=len(affected_sources),
                not_affected_source_count=0,
                unknown_source_count=len(unknown_sources),
                detected_source_count=len(detected_sources),
                conflict_detected=False,
                conflicts=conflicts,
                supporting_evidence=supporting,
                contradicting_evidence=[],
                rationale=" ".join(rationale_notes),
                requires_human_review=False,
            )

        # --- Case C: CONSENSUS NOT AFFECTED (1+ sources not affected, 0 sources affected) ---
        if not_affected_sources and not affected_sources:
            rationale_notes = [
                f"{len(not_affected_sources)} source(s) ({', '.join(not_affected_sources)}) confirm version '{installed_version}' is outside affected range."
            ]
            if detected_sources:
                rationale_notes.append(
                    f"Catalog presence in {', '.join(detected_sources)} (e.g. CISA KEV) confirmed without version contradiction."
                )
            if unknown_sources:
                rationale_notes.append(
                    f"Inconclusive version data from {', '.join(unknown_sources)} does not contradict verified bounds."
                )

            return ApplicabilityResolution(
                status=Applicability.LIKELY_NOT_AFFECTED,
                source_count=source_count,
                affected_source_count=0,
                not_affected_source_count=len(not_affected_sources),
                unknown_source_count=len(unknown_sources),
                detected_source_count=len(detected_sources),
                conflict_detected=False,
                conflicts=conflicts,
                supporting_evidence=supporting,
                contradicting_evidence=[],
                rationale=" ".join(rationale_notes),
                requires_human_review=False,
            )

        # --- Case D: ONLY DETECTED (No source provided version ranges) ---
        if detected_sources and not affected_sources and not not_affected_sources:
            return ApplicabilityResolution(
                status=Applicability.DETECTED,
                source_count=source_count,
                affected_source_count=0,
                not_affected_source_count=0,
                unknown_source_count=len(unknown_sources),
                detected_source_count=len(detected_sources),
                conflict_detected=False,
                conflicts=[],
                supporting_evidence=[
                    f"[{s}] Catalog/KEV presence confirmed without version ranges"
                    for s in detected_sources
                ],
                contradicting_evidence=[],
                rationale=(
                    f"Component matched vulnerability catalog in {', '.join(detected_sources)}, "
                    "but no sources provide version ranges to verify applicability."
                ),
                requires_human_review=True,
            )

        # --- Case E: ONLY UNKNOWN ---
        return ApplicabilityResolution(
            status=Applicability.UNKNOWN,
            source_count=source_count,
            affected_source_count=0,
            not_affected_source_count=0,
            unknown_source_count=len(unknown_sources),
            detected_source_count=0,
            conflict_detected=False,
            conflicts=[],
            supporting_evidence=[],
            contradicting_evidence=[],
            rationale=(
                f"Version applicability could not be evaluated by any source ({', '.join(unknown_sources)})."
            ),
            requires_human_review=True,
        )

    def resolve_match(self, match: MatchResult) -> MatchResult:
        """Resolve conflicts and consolidate applicability for a MatchResult in-place.

        Preserves original structured_evidences and attaches conflicts and conflict_resolution.
        """
        resolution = self.resolve_applicability(
            evidences=match.structured_evidences,
            vulnerability=match.vulnerability,
            installed_version=match.component.version,
        )

        match.applicability = resolution.status
        match.conflicts = resolution.conflicts
        match.conflict_resolution = resolution

        # Check for complementary metadata discrepancies (CVSS / Severity)
        self._check_metadata_discrepancies(match)

        return match

    def resolve_matches(self, matches: list[MatchResult]) -> list[MatchResult]:
        """Resolve conflicts across a batch of match results."""
        for m in matches:
            self.resolve_match(m)
        return matches

    def _check_metadata_discrepancies(self, match: MatchResult) -> None:
        """Inspect complementary metadata signals (CVSS score, severity) across sources.

        Does NOT alter version applicability. Documents differences for security audit.
        """
        if not match.vulnerability or not getattr(match.vulnerability, "source_records", None):
            return

        cvss_scores: dict[str, float] = {}
        severities: dict[str, str] = {}

        for sr in match.vulnerability.source_records:
            payload = sr.raw_payload if isinstance(sr.raw_payload, dict) else {}
            if sr.source_name == "NVD":
                if payload.get("cvss_score") is not None:
                    cvss_scores["NVD"] = float(payload["cvss_score"])
                if payload.get("severity"):
                    severities["NVD"] = str(payload["severity"]).upper()
            elif sr.source_name == "OSV":
                if payload.get("severity"):
                    severities["OSV"] = str(payload["severity"]).upper()

        if len(severities) > 1 and len(set(severities.values())) > 1:
            # Document severity difference as complementary signal, not blocking conflict
            match.conflicts.append(
                SourceConflict(
                    conflict_type=ConflictType.SEVERITY,
                    severity=ConflictSeverity.LOW,
                    field="severity",
                    sources=sorted(list(severities.keys())),
                    identifiers=(
                        [match.vulnerability.canonical_id]
                        if match.vulnerability and match.vulnerability.canonical_id
                        else []
                    ),
                    values=severities,
                    resolution="COMPLEMENTARY_SEVERITY",
                    rationale=(
                        f"Sources report different severity ratings {severities}; "
                        "retained as complementary context without altering version applicability."
                    ),
                )
            )
