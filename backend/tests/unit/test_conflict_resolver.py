"""Comprehensive tests for Multi-Source Conflict Resolution (Stage 9).

Covers all 9 mandatory specification tests from Section 26, plus:
- End-to-end integration with Matcher, Conflict Resolver, and Risk Engine (Section 27)
- Database persistence and strict idempotency (Section 24)
- Non-interference of KEV with applicability math (Section 21)
- Non-interference of CVSS differences with applicability math (Section 20)
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    DetectedComponent,
    Ecosystem,
    EvidenceType,
    MatchEvidence,
    MatchResult,
    MatchType,
    VersionType,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.models import (
    MatchDB,
    ProjectComponentDB,
    ProjectDB,
    ScanDB,
    SourceConflictDB,
    VulnerabilityDB,
)
from vuln_ai.db.repositories import MatchRepository
from vuln_ai.matching.conflict import (
    ConflictResolver,
    ConflictSeverity,
    ConflictType,
    SourceConflict,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.risk.models import RiskLevel, RiskStatus


@pytest.fixture
def resolver() -> ConflictResolver:
    return ConflictResolver()


@pytest.fixture
def risk_engine() -> DeterministicRiskEngine:
    return DeterministicRiskEngine()


# ===========================================================================
# Section 26: Mandatory Unit Tests (1 through 9)
# ===========================================================================


class TestMandatoryConflictResolutionScenarios:
    """The 9 explicit scenarios required by Stage 9 specification."""

    def test_01_complementary_sources(self, resolver: ConflictResolver):
        """Test 1: Complementary sources — OSV range, NVD CVSS, CISA KEV.

        OSV: affected range >=1.0,<2.0
        NVD: CVSS 8.2 (no range)
        CISA: KEV true (no range)
        installed: 1.5

        Expected:
        - no applicability conflict
        - consolidated: LIKELY_AFFECTED
        """
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-1111",
                package_name="requests",
                ecosystem=Ecosystem.PYPI,
                installed_version="1.5.0",
                affected_range=">=1.0.0,<2.0.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="1.5.0 falls within [1.0.0, 2.0.0)",
            ),
            MatchEvidence(
                source_name="CISA KEV",
                identifier="CVE-2024-1111",
                package_name="requests",
                ecosystem=Ecosystem.PYPI,
                installed_version="1.5.0",
                status=Applicability.DETECTED,
                evidence_type="kev_exploited",
                details="Vulnerability cataloged in CISA KEV (active exploitation)",
            ),
        ]
        vuln = VulnerabilityRecord(
            canonical_id="CVE-2024-1111",
            source_name="OSV",
            vendor_project="psf",
            product="requests",
            cvss_score=8.2,
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="NVD",
                    source_identifier="CVE-2024-1111",
                    raw_payload={"cvss_score": 8.2, "severity": "HIGH"},
                ),
                VulnerabilitySourceRecord(
                    source_name="CISA KEV",
                    source_identifier="CVE-2024-1111",
                    has_kev_evidence=True,
                ),
            ],
        )

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            vulnerability=vuln,
            installed_version="1.5.0",
        )

        assert resolution.conflict_detected is False
        assert resolution.status == Applicability.LIKELY_AFFECTED
        assert resolution.affected_source_count == 1
        assert resolution.not_affected_source_count == 0
        assert resolution.requires_human_review is False

    def test_02_same_applicability(self, resolver: ConflictResolver):
        """Test 2: Same applicability — OSV and NVD both confirm range.

        OSV: >=1.0,<2.0
        NVD: >=1.0,<2.0
        installed: 1.5.0

        Expected:
        - LIKELY_AFFECTED
        - no conflict
        """
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-2222",
                package_name="urllib3",
                ecosystem=Ecosystem.PYPI,
                installed_version="1.5.0",
                affected_range=">=1.0,<2.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Within OSV range",
            ),
            MatchEvidence(
                source_name="NVD",
                identifier="CVE-2024-2222",
                package_name="urllib3",
                ecosystem=Ecosystem.PYPI,
                installed_version="1.5.0",
                affected_range=">=1.0,<2.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Within NVD range",
            ),
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version="1.5.0",
        )

        assert resolution.status == Applicability.LIKELY_AFFECTED
        assert resolution.conflict_detected is False
        assert resolution.affected_source_count == 2
        assert resolution.not_affected_source_count == 0
        assert resolution.requires_human_review is False

    def test_03_affected_vs_not_affected(self, resolver: ConflictResolver):
        """Test 3: Direct conflict — Affected vs Not Affected.

        OSV: >=1.0,<2.0 (installed 2.1 is OUTSIDE → LIKELY_NOT_AFFECTED)
        NVD: >=2.0,<3.0 (installed 2.1 is WITHIN → LIKELY_AFFECTED)
        installed: 2.1

        Expected:
        - OSV -> NOT_AFFECTED
        - NVD -> AFFECTED
        - Consolidated: REQUIRES_REVIEW
        - conflict_detected = True
        """
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-3333",
                package_name="flask",
                ecosystem=Ecosystem.PYPI,
                installed_version="2.1.0",
                affected_range=">=1.0,<2.0",
                status=Applicability.LIKELY_NOT_AFFECTED,
                evidence_type=EvidenceType.OUTSIDE_RANGE,
                details="Version 2.1.0 is outside [1.0, 2.0)",
            ),
            MatchEvidence(
                source_name="NVD",
                identifier="CVE-2024-3333",
                package_name="flask",
                ecosystem=Ecosystem.PYPI,
                installed_version="2.1.0",
                affected_range=">=2.0,<3.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Version 2.1.0 is within [2.0, 3.0)",
            ),
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version="2.1.0",
        )

        assert resolution.status == Applicability.REQUIRES_REVIEW
        assert resolution.conflict_detected is True
        assert resolution.requires_human_review is True
        assert resolution.affected_source_count == 1
        assert resolution.not_affected_source_count == 1
        assert len(resolution.conflicts) >= 1

        app_conflict = next(
            c for c in resolution.conflicts if c.conflict_type == ConflictType.APPLICABILITY
        )
        assert app_conflict.severity == ConflictSeverity.HIGH
        assert "OSV" in app_conflict.sources
        assert "NVD" in app_conflict.sources
        assert app_conflict.resolution == "REQUIRES_REVIEW"

    def test_04_unknown_does_not_conflict(self, resolver: ConflictResolver):
        """Test 4: UNKNOWN does not conflict with explicit range evidence.

        OSV -> LIKELY_AFFECTED
        NVD -> UNKNOWN

        Expected:
        - Consolidated: LIKELY_AFFECTED
        - conflict = False
        """
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-4444",
                package_name="cryptography",
                ecosystem=Ecosystem.PYPI,
                installed_version="3.4.0",
                affected_range="<4.0.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Version 3.4.0 is affected",
            ),
            MatchEvidence(
                source_name="NVD",
                identifier="CVE-2024-4444",
                package_name="cryptography",
                ecosystem=Ecosystem.PYPI,
                installed_version="3.4.0",
                status=Applicability.UNKNOWN,
                evidence_type=EvidenceType.VERSION_UNKNOWN,
                details="Unparseable version format in CPE",
            ),
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version="3.4.0",
        )

        assert resolution.status == Applicability.LIKELY_AFFECTED
        assert resolution.conflict_detected is False
        assert resolution.affected_source_count == 1
        assert resolution.unknown_source_count == 1
        assert resolution.requires_human_review is False

    def test_05_detected_plus_not_affected(self, resolver: ConflictResolver):
        """Test 5: DETECTED (CISA KEV) + NOT_AFFECTED (OSV).

        CISA -> DETECTED (name/KEV presence, no version bounds)
        OSV -> LIKELY_NOT_AFFECTED (installed version is outside affected range)

        Expected:
        - Consolidated: LIKELY_NOT_AFFECTED
        - Preserves KEV evidence
        - conflict = False
        """
        evidences = [
            MatchEvidence(
                source_name="CISA KEV",
                identifier="CVE-2024-5555",
                package_name="django",
                ecosystem=Ecosystem.PYPI,
                installed_version="5.0.0",
                status=Applicability.DETECTED,
                evidence_type="kev_exploited",
                details="Cataloged in CISA KEV",
            ),
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-5555",
                package_name="django",
                ecosystem=Ecosystem.PYPI,
                installed_version="5.0.0",
                affected_range="<4.2.0",
                status=Applicability.LIKELY_NOT_AFFECTED,
                evidence_type=EvidenceType.OUTSIDE_RANGE,
                details="Version 5.0.0 is fixed in 4.2.0",
            ),
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version="5.0.0",
        )

        # Range evidence takes precedence over name-only presence
        assert resolution.status == Applicability.LIKELY_NOT_AFFECTED
        assert resolution.conflict_detected is False
        assert resolution.not_affected_source_count == 1
        assert resolution.detected_source_count == 1
        assert resolution.requires_human_review is False

    def test_06_detected_only(self, resolver: ConflictResolver):
        """Test 6: DETECTED only — no affected ranges from any source.

        CISA -> DETECTED

        Expected:
        - DETECTED (never upgraded to LIKELY_AFFECTED)
        - conflict = False
        - requires_human_review = True
        """
        evidences = [
            MatchEvidence(
                source_name="CISA KEV",
                identifier="CVE-2024-6666",
                package_name="fortinet_vpn",
                ecosystem=Ecosystem.UNKNOWN,
                installed_version=None,
                status=Applicability.DETECTED,
                evidence_type=EvidenceType.PRODUCT_NAME_ONLY,
                details="Product name match only in CISA KEV",
            )
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version=None,
        )

        assert resolution.status == Applicability.DETECTED
        assert resolution.conflict_detected is False
        assert resolution.requires_human_review is True

    def test_07_three_sources_consensus(self, resolver: ConflictResolver):
        """Test 7: Three sources agreement.

        OSV -> AFFECTED
        NVD -> AFFECTED
        CISA -> DETECTED

        Expected:
        - LIKELY_AFFECTED
        - no conflict
        """
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-7777",
                package_name="werkzeug",
                ecosystem=Ecosystem.PYPI,
                installed_version="2.0.0",
                affected_range="<3.0.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Within OSV range",
            ),
            MatchEvidence(
                source_name="NVD",
                identifier="CVE-2024-7777",
                package_name="werkzeug",
                ecosystem=Ecosystem.PYPI,
                installed_version="2.0.0",
                affected_range="<3.0.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Within NVD range",
            ),
            MatchEvidence(
                source_name="CISA KEV",
                identifier="CVE-2024-7777",
                package_name="werkzeug",
                ecosystem=Ecosystem.PYPI,
                installed_version="2.0.0",
                status=Applicability.DETECTED,
                evidence_type="kev_exploited",
                details="Exploited in wild",
            ),
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version="2.0.0",
        )

        assert resolution.status == Applicability.LIKELY_AFFECTED
        assert resolution.conflict_detected is False
        assert resolution.affected_source_count == 2
        assert resolution.detected_source_count == 1
        assert resolution.not_affected_source_count == 0

    def test_08_three_sources_with_one_disagreement(self, resolver: ConflictResolver):
        """Test 8: Three sources with one disagreement.

        OSV -> AFFECTED
        NVD -> NOT_AFFECTED
        CISA -> DETECTED

        Expected:
        - REQUIRES_REVIEW
        - conflict_detected = True
        """
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-8888",
                package_name="jinja2",
                ecosystem=Ecosystem.PYPI,
                installed_version="3.1.2",
                affected_range="<=3.1.2",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="OSV says vulnerable",
            ),
            MatchEvidence(
                source_name="NVD",
                identifier="CVE-2024-8888",
                package_name="jinja2",
                ecosystem=Ecosystem.PYPI,
                installed_version="3.1.2",
                affected_range="<3.1.0",
                status=Applicability.LIKELY_NOT_AFFECTED,
                evidence_type=EvidenceType.OUTSIDE_RANGE,
                details="NVD says 3.1.2 is safe",
            ),
            MatchEvidence(
                source_name="CISA KEV",
                identifier="CVE-2024-8888",
                package_name="jinja2",
                ecosystem=Ecosystem.PYPI,
                installed_version="3.1.2",
                status=Applicability.DETECTED,
                evidence_type="kev_exploited",
                details="Listed in KEV",
            ),
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version="3.1.2",
        )

        assert resolution.status == Applicability.REQUIRES_REVIEW
        assert resolution.conflict_detected is True
        assert resolution.requires_human_review is True
        assert resolution.affected_source_count == 1
        assert resolution.not_affected_source_count == 1
        assert resolution.detected_source_count == 1

    def test_09_range_difference_without_disagreement(self, resolver: ConflictResolver):
        """Test 9: Range difference without actual disagreement.

        OSV: <2.0
        NVD: <2.1
        installed: 1.5

        Both sources report installed=1.5 is AFFECTED.

        Expected:
        - Consolidated: LIKELY_AFFECTED
        - No applicability conflict (conflict_detected = False)
        - Syntactic range difference recorded as informational conflict (severity=LOW)
        """
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-9999",
                package_name="aiohttp",
                ecosystem=Ecosystem.PYPI,
                installed_version="1.5.0",
                affected_range="<2.0.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Version 1.5.0 < 2.0.0",
            ),
            MatchEvidence(
                source_name="NVD",
                identifier="CVE-2024-9999",
                package_name="aiohttp",
                ecosystem=Ecosystem.PYPI,
                installed_version="1.5.0",
                affected_range="<2.1.0",
                status=Applicability.LIKELY_AFFECTED,
                evidence_type=EvidenceType.RANGE_CONFIRMED,
                details="Version 1.5.0 < 2.1.0",
            ),
        ]

        resolution = resolver.resolve_applicability(
            evidences=evidences,
            installed_version="1.5.0",
        )

        assert resolution.status == Applicability.LIKELY_AFFECTED
        assert resolution.conflict_detected is False  # No blocking conflict
        assert resolution.affected_source_count == 2

        # Verify informational range divergence was captured
        range_conflicts = [
            c for c in resolution.conflicts if c.conflict_type == ConflictType.AFFECTED_RANGE
        ]
        assert len(range_conflicts) == 1
        assert range_conflicts[0].severity == ConflictSeverity.LOW
        assert range_conflicts[0].resolution == "CONSENSUS_AFFECTED"


# ===========================================================================
# Section 27: End-to-End Pipeline Integration Test
# ===========================================================================


class TestPipelineIntegrationWithRiskEngine:
    """Test full pipeline: Source Evidence -> Matcher -> ConflictResolver -> RiskEngine."""

    def test_full_pipeline_conflict_triggers_risk_review(
        self,
        resolver: ConflictResolver,
        risk_engine: DeterministicRiskEngine,
    ):
        """Disagreement between OSV and NVD must produce REQUIRES_REVIEW and SOURCE_APPLICABILITY_CONFLICT."""
        comp = DetectedComponent(
            name="pydantic",
            version="2.5.0",
            version_type=VersionType.EXACT,
            ecosystem=Ecosystem.PYPI,
            source_file="pyproject.toml",
        )

        vuln = VulnerabilityRecord(
            canonical_id="CVE-2024-9001",
            source_name="OSV",
            vendor_project="pydantic",
            product="pydantic",
            cvss_score=7.5,
            affected_ranges=[
                AffectedVersionRange(
                    package_name="pydantic",
                    ecosystem="pypi",
                    introduced="2.0.0",
                    fixed="2.4.0",  # OSV says safe at 2.4.0 -> 2.5.0 is OUTSIDE
                    raw_range=">=2.0.0,<2.4.0",
                    source_name="OSV",
                ),
                AffectedVersionRange(
                    package_name="pydantic",
                    ecosystem="pypi",
                    introduced="2.0.0",
                    fixed="2.6.0",  # NVD says safe at 2.6.0 -> 2.5.0 is WITHIN
                    raw_range=">=2.0.0,<2.6.0",
                    source_name="NVD",
                ),
            ],
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="CISA KEV",
                    source_identifier="CVE-2024-9001",
                    has_kev_evidence=True,
                )
            ],
        )

        # 1. Matcher evaluates component against candidate vulnerability
        matcher = VulnerabilityMatcher()
        matches = matcher.match([comp], [vuln])
        assert len(matches) == 1
        match = matches[0]

        # 2. Match evidences are populated per source
        assert len(match.structured_evidences) >= 2
        sources_found = {ev.source_name for ev in match.structured_evidences}
        assert "OSV" in sources_found
        assert "NVD" in sources_found

        # 3. Conflict Resolver consolidates applicability
        resolver.resolve_match(match)

        assert match.applicability == Applicability.REQUIRES_REVIEW
        assert len(match.conflicts) >= 1
        assert any(c.conflict_type == ConflictType.APPLICABILITY for c in match.conflicts)

        # 4. Risk Engine evaluates consolidated match
        assessment = risk_engine.assess(match)

        assert assessment.status == RiskStatus.REQUIRES_REVIEW
        assert assessment.requires_human_review is True
        assert "SOURCE_APPLICABILITY_CONFLICT" in assessment.rule_ids
        assert assessment.risk_level == RiskLevel.HIGH  # Elevates due to KEV + CVSS 7.5

    def test_full_pipeline_consensus_affected_with_kev(
        self,
        resolver: ConflictResolver,
        risk_engine: DeterministicRiskEngine,
    ):
        """When OSV and NVD agree on affected range, status is LIKELY_AFFECTED and KEV elevates risk."""
        comp = DetectedComponent(
            name="cryptography",
            version="41.0.1",
            version_type=VersionType.EXACT,
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )

        vuln = VulnerabilityRecord(
            canonical_id="CVE-2024-9002",
            source_name="OSV",
            vendor_project="pyca",
            product="cryptography",
            cvss_score=8.5,
            affected_ranges=[
                AffectedVersionRange(
                    package_name="cryptography",
                    ecosystem="pypi",
                    introduced="41.0.0",
                    fixed="41.0.3",
                    raw_range=">=41.0.0,<41.0.3",
                    source_name="OSV",
                ),
                AffectedVersionRange(
                    package_name="cryptography",
                    ecosystem="pypi",
                    introduced="41.0.0",
                    fixed="41.0.3",
                    raw_range=">=41.0.0,<41.0.3",
                    source_name="NVD",
                ),
            ],
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="CISA KEV",
                    source_identifier="CVE-2024-9002",
                    has_kev_evidence=True,
                )
            ],
        )

        matcher = VulnerabilityMatcher()
        matches = matcher.match([comp], [vuln])
        match = matches[0]

        resolver.resolve_match(match)

        assert match.applicability == Applicability.LIKELY_AFFECTED
        assert not any(c.conflict_type == ConflictType.APPLICABILITY for c in match.conflicts)

        assessment = risk_engine.assess(match)

        assert assessment.status == RiskStatus.LIKELY_AFFECTED
        assert assessment.risk_level == RiskLevel.CRITICAL  # KEV + CVSS 8.5
        assert "APPLICABILITY_LIKELY_AFFECTED" in assessment.rule_ids
        assert "KEV_CONFIRMED" in assessment.rule_ids


# ===========================================================================
# Section 24: Database Persistence & Strict Idempotency Tests
# ===========================================================================


class TestConflictPersistenceAndIdempotency:
    """Validate DB persistence and idempotent upserting of source conflicts."""

    @pytest.mark.asyncio
    async def test_conflict_persistence_and_idempotency(self, db_session):
        """Saving the same conflict twice must NOT duplicate records."""
        # 1. Setup sample project, scan, component, vulnerability, match
        proj = ProjectDB(name="test_proj", path="/tmp/test_proj")
        db_session.add(proj)
        await db_session.flush()

        scan = ScanDB(project_id=proj.id)
        db_session.add(scan)
        await db_session.flush()

        comp = ProjectComponentDB(
            project_id=proj.id,
            name="demo_pkg",
            version="1.0.0",
            source_file="requirements.txt",
            ecosystem="pypi",
        )
        db_session.add(comp)
        await db_session.flush()

        vuln = VulnerabilityDB(
            canonical_id="CVE-2024-9999",
            vendor_project="demo",
            product="demo_pkg",
        )
        db_session.add(vuln)
        await db_session.flush()

        match_db = MatchDB(
            scan_id=scan.id,
            component_id=comp.id,
            vulnerability_id=vuln.id,
            match_type="exact_name",
            applicability="requires_review",
        )
        db_session.add(match_db)
        await db_session.flush()

        repo = MatchRepository(db_session)

        # 2. Define domain conflict
        conflict = SourceConflict(
            conflict_type=ConflictType.APPLICABILITY,
            severity=ConflictSeverity.HIGH,
            field="applicability",
            sources=["OSV", "NVD"],
            identifiers=["CVE-2024-9999"],
            values={"OSV": "LIKELY_AFFECTED", "NVD": "LIKELY_NOT_AFFECTED"},
            resolution="REQUIRES_REVIEW",
            rationale="Disagreement on range",
        )

        # 3. Save conflict first time
        saved_1 = await repo.save_match_conflicts(
            match_id=match_db.id,
            conflicts=[conflict],
            vulnerability_id=vuln.id,
        )
        assert len(saved_1) == 1

        # Query DB directly
        result_1 = await db_session.execute(
            select(SourceConflictDB).where(SourceConflictDB.match_id == match_db.id)
        )
        conflicts_in_db = list(result_1.scalars().all())
        assert len(conflicts_in_db) == 1
        assert conflicts_in_db[0].conflict_type == "applicability"

        # 4. Save conflict SECOND time (Idempotency check)
        saved_2 = await repo.save_match_conflicts(
            match_id=match_db.id,
            conflicts=[conflict],
            vulnerability_id=vuln.id,
        )
        assert len(saved_2) == 1

        # Query DB directly to verify NO duplicate was created
        result_2 = await db_session.execute(
            select(SourceConflictDB).where(SourceConflictDB.match_id == match_db.id)
        )
        conflicts_in_db_after = list(result_2.scalars().all())
        assert len(conflicts_in_db_after) == 1, (
            "Idempotency violated: duplicate conflict record created!"
        )

        # 5. Fetch match through get_by_id and verify conflicts joined
        retrieved_match = await repo.get_by_id(match_db.id)
        assert retrieved_match is not None
        assert len(retrieved_match.conflicts) == 1
        assert retrieved_match.conflicts[0].conflict_type == "applicability"
        assert retrieved_match.conflicts[0].severity == "high"


class TestConflictResolverEdgeCasesAndMetadata:
    """Validate edge cases, metadata checks, and helper functions."""

    def test_empty_evidences_yields_unknown(self, resolver: ConflictResolver):
        """No evidences provided should produce UNKNOWN with review required."""
        res = resolver.resolve_applicability([], installed_version="1.0.0")
        assert res.status == Applicability.UNKNOWN
        assert res.requires_human_review is True
        assert res.source_count == 0

    def test_only_unknown_evidences(self, resolver: ConflictResolver):
        """All sources unable to evaluate version produces UNKNOWN."""
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-0001",
                package_name="test-pkg",
                ecosystem=Ecosystem.PYPI,
                installed_version="1.0.0",
                status=Applicability.UNKNOWN,
                evidence_type=EvidenceType.VERSION_UNKNOWN,
                details="Unparseable",
            )
        ]
        res = resolver.resolve_applicability(evidences, installed_version="1.0.0")
        assert res.status == Applicability.UNKNOWN
        assert res.unknown_source_count == 1
        assert res.conflict_detected is False

    def test_not_affected_with_unknown_source(self, resolver: ConflictResolver):
        """NOT_AFFECTED from one source + UNKNOWN from another results in NOT_AFFECTED."""
        evidences = [
            MatchEvidence(
                source_name="OSV",
                identifier="CVE-2024-0002",
                package_name="test-pkg",
                ecosystem=Ecosystem.PYPI,
                installed_version="3.0.0",
                affected_range="<2.0.0",
                status=Applicability.LIKELY_NOT_AFFECTED,
                evidence_type=EvidenceType.OUTSIDE_RANGE,
            ),
            MatchEvidence(
                source_name="NVD",
                identifier="CVE-2024-0002",
                package_name="test-pkg",
                ecosystem=Ecosystem.PYPI,
                installed_version="3.0.0",
                status=Applicability.UNKNOWN,
                evidence_type=EvidenceType.VERSION_UNKNOWN,
            ),
        ]
        res = resolver.resolve_applicability(evidences, installed_version="3.0.0")
        assert res.status == Applicability.LIKELY_NOT_AFFECTED
        assert res.conflict_detected is False
        assert res.not_affected_source_count == 1
        assert res.unknown_source_count == 1

    def test_complementary_metadata_severity_check(self, resolver: ConflictResolver):
        """Different severity ratings between NVD and OSV should be recorded as complementary."""
        comp = DetectedComponent(
            name="demo_lib",
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
        vuln = VulnerabilityRecord(
            canonical_id="CVE-2024-0003",
            source_name="OSV",
            vendor_project="demo",
            product="demo_lib",
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="NVD",
                    source_identifier="CVE-2024-0003",
                    raw_payload={"cvss_score": 9.8, "severity": "CRITICAL"},
                ),
                VulnerabilitySourceRecord(
                    source_name="OSV",
                    source_identifier="CVE-2024-0003",
                    raw_payload={"severity": "MEDIUM"},
                ),
            ],
        )
        match = MatchResult(
            component=comp,
            vulnerability=vuln,
            match_type=MatchType.EXACT_NAME,
            match_confidence=0.8,
            applicability=Applicability.DETECTED,
            structured_evidences=[
                MatchEvidence(
                    source_name="OSV",
                    identifier="CVE-2024-0003",
                    package_name="demo_lib",
                    ecosystem=Ecosystem.PYPI,
                    status=Applicability.DETECTED,
                )
            ],
        )

        resolver.resolve_match(match)

        # Applicability remains DETECTED
        assert match.applicability == Applicability.DETECTED
        # Severity difference is recorded as complementary conflict
        sev_conflicts = [c for c in match.conflicts if c.conflict_type == ConflictType.SEVERITY]
        assert len(sev_conflicts) == 1
        assert sev_conflicts[0].resolution == "COMPLEMENTARY_SEVERITY"
