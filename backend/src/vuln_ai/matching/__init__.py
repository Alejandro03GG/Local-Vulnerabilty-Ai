"""Matching and conflict resolution modules."""

from vuln_ai.matching.conflict import (
    ApplicabilityResolution,
    ConflictResolutionStatus,
    ConflictResolver,
    ConflictSeverity,
    ConflictType,
    SourceConflict,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.matching.version import evaluate_component_ranges

__all__ = [
    "ApplicabilityResolution",
    "ConflictResolutionStatus",
    "ConflictResolver",
    "ConflictSeverity",
    "ConflictType",
    "SourceConflict",
    "VulnerabilityMatcher",
    "evaluate_component_ranges",
]
