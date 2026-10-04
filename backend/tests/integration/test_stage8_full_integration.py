"""Comprehensive end-to-end integration tests for Stage 8.

Verifies:
1. Version-aware matching within affected range -> LIKELY_AFFECTED
2. Version-aware matching outside affected range -> LIKELY_NOT_AFFECTED
3. Unknown version -> UNKNOWN / REQUIRES_REVIEW
4. CISA only without ranges -> DETECTED (product_name_only)
5. Multi-source correlation: OSV + NVD + CISA on same canonical vulnerability
6. AI unavailable -> deterministic fallback, no crash
7. SystemOne unavailable -> deterministic fallback, no crash
8. AI malformed response -> graceful fallback, risk calculation continues
9. SystemOne malformed response -> graceful fallback, risk calculation continues
10. KEV + outside range -> applicability preserved as LIKELY_NOT_AFFECTED, KEV preserved
11. Deterministic Risk Engine without AI -> auditable rule trace
12. Full end-to-end pipeline + persistence + idempotency
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.base import AIProvider, DecisionProvider
from vuln_ai.ai.models import (
    AIAnalysis,
    AnalysisContext,
    DecisionQuestion,
    DecisionResult,
)
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    DetectedComponent,
    Ecosystem,
    EvidenceType,
    IdentifierType,
    ScanStatus,
    VersionType,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.models import (
    AIAnalysisDB,
    DecisionResultDB,
    MatchDB,
    MatchEvidenceDB,
    RiskAssessmentDB,
    ScanDB,
)
from vuln_ai.db.repositories import (
    MatchRepository,
    SourceRepository,
    VulnerabilityRepository,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.risk.models import RiskLevel, RiskStatus
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.cisa_kev import CISAKEVSource
from vuln_ai.sources.registry import SourceRegistry


class WorkingAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "WorkingAIProvider"

    @property
    def provider_type(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        return True

    async def analyze(self, context: AnalysisContext) -> AIAnalysis:
        return AIAnalysis(
            provider=self.name,
            model="llama3.2-mock",
            explanation=f"Contextual analysis for {context.component_name} {context.cve_id}",
            evidence=[f"Evaluated package {context.component_name}"],
            requires_human_review=False,
        )


class MalformedAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "MalformedAIProvider"

    @property
    def provider_type(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        return True

    async def analyze(self, context: AnalysisContext) -> AIAnalysis:
        raise ValueError("Malformed LLM response: missing required JSON delimiters")


class WorkingDecisionProvider(DecisionProvider):
    @property
    def name(self) -> str:
        return "WorkingDecisionProvider"

    @property
    def provider_type(self) -> str:
        return "ollama_systemone"

    async def is_available(self) -> bool:
        return True

    async def decide(
        self, context: AnalysisContext, questions: list[DecisionQuestion]
    ) -> DecisionResult:
        return DecisionResult(
            provider=self.name,
            model="tev1:4b-mock",
            responses={"applicability": "yes", "exposure": "direct", "urgency": 8.0},
            decision_probabilities={"applicability": {"yes": 0.90, "no": 0.10}},
            applicability_probability=0.90,
            urgency_score=8.0,
        )


class MalformedDecisionProvider(DecisionProvider):
    @property
    def name(self) -> str:
        return "MalformedDecisionProvider"

    @property
    def provider_type(self) -> str:
        return "ollama_systemone"

    async def is_available(self) -> bool:
        return True

    async def decide(
        self, context: AnalysisContext, questions: list[DecisionQuestion]
    ) -> DecisionResult:
        raise RuntimeError("SystemOne internal server error 500: bad request")


# ===========================================================================
# Unit / Component Level Cases
# ===========================================================================


def test_caso1_affected_range():
    """Caso 1: Component requests 2.31.0 in [2.0, 2.32) -> LIKELY_AFFECTED."""
    matcher = VulnerabilityMatcher()
    components = [
        DetectedComponent(
            name="requests",
            version="2.31.0",
            version_type=VersionType.EXACT,
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
    ]
    vulns = [
        VulnerabilityRecord(
            canonical_id="GHSA-j8r2-6x86-q33q",
            cve_id="CVE-2023-32681",
            source_name="OSV",
            vendor_project="",
            product="requests",
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="requests",
                    range_type="ecosystem",
                    introduced="2.0",
                    fixed="2.32.0",
                    source_name="OSV",
                    raw_range=">= 2.0, < 2.32.0",
                )
            ],
        )
    ]
    matches = matcher.match(components, vulns)
    assert len(matches) == 1
    assert matches[0].applicability == Applicability.LIKELY_AFFECTED
    assert any(
        ev.evidence_type == EvidenceType.RANGE_CONFIRMED for ev in matches[0].structured_evidences
    )


def test_caso2_outside_range():
    """Caso 2: Component requests 2.32.0 in [2.0, 2.32) -> LIKELY_NOT_AFFECTED."""
    matcher = VulnerabilityMatcher()
    components = [
        DetectedComponent(
            name="requests",
            version="2.32.0",
            version_type=VersionType.EXACT,
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
    ]
    vulns = [
        VulnerabilityRecord(
            canonical_id="GHSA-j8r2-6x86-q33q",
            cve_id="CVE-2023-32681",
            source_name="OSV",
            vendor_project="",
            product="requests",
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="requests",
                    range_type="ecosystem",
                    introduced="2.0",
                    fixed="2.32.0",
                    source_name="OSV",
                    raw_range=">= 2.0, < 2.32.0",
                )
            ],
        )
    ]
    matches = matcher.match(components, vulns)
    assert len(matches) == 1
    assert matches[0].applicability == Applicability.LIKELY_NOT_AFFECTED
    assert any(
        ev.evidence_type == EvidenceType.OUTSIDE_RANGE for ev in matches[0].structured_evidences
    )


def test_caso3_unknown_version():
    """Caso 3: Component requests without version -> UNKNOWN."""
    matcher = VulnerabilityMatcher()
    components = [
        DetectedComponent(
            name="requests",
            version=None,
            version_type=VersionType.UNKNOWN,
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
    ]
    vulns = [
        VulnerabilityRecord(
            canonical_id="GHSA-j8r2-6x86-q33q",
            cve_id="CVE-2023-32681",
            source_name="OSV",
            vendor_project="",
            product="requests",
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="requests",
                    range_type="ecosystem",
                    introduced="2.0",
                    fixed="2.32.0",
                    source_name="OSV",
                )
            ],
        )
    ]
    matches = matcher.match(components, vulns)
    assert len(matches) == 1
    assert matches[0].applicability == Applicability.UNKNOWN

    risk_engine = DeterministicRiskEngine()
    assessment = risk_engine.assess(matches[0])
    assert assessment.status == RiskStatus.REQUIRES_REVIEW
    assert "NO_VERSION_EVIDENCE" in assessment.rule_ids


def test_caso4_cisa_only_product_name_only():
    """Caso 4: CISA only (no affected ranges) -> DETECTED, evidence_type = product_name_only."""
    matcher = VulnerabilityMatcher()
    components = [
        DetectedComponent(
            name="django",
            version="4.2.0",
            version_type=VersionType.EXACT,
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
    ]
    vulns = [
        VulnerabilityRecord(
            canonical_id="CVE-2024-9999",
            cve_id="CVE-2024-9999",
            source_name="CISA KEV",
            vendor_project="Django",
            product="Django",
            affected_ranges=[],
        )
    ]
    matches = matcher.match(components, vulns)
    assert len(matches) == 1
    assert matches[0].applicability == Applicability.DETECTED
    assert any(
        ev.evidence_type == EvidenceType.PRODUCT_NAME_ONLY
        for ev in matches[0].structured_evidences
    )

    risk_engine = DeterministicRiskEngine()
    assessment = risk_engine.assess(matches[0])
    assert assessment.status == RiskStatus.DETECTED
    assert "APPLICABILITY_DETECTED" in assessment.rule_ids
    assert "KEV_CONFIRMED" in assessment.rule_ids


def test_caso10_kev_plus_outside_range():
    """Caso 10: CISA KEV + Outside Range -> applicability = LIKELY_NOT_AFFECTED, KEV preserved."""
    matcher = VulnerabilityMatcher()
    components = [
        DetectedComponent(
            name="requests",
            version="2.1",
            version_type=VersionType.EXACT,
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
    ]
    vulns = [
        VulnerabilityRecord(
            canonical_id="CVE-2026-9999",
            cve_id="CVE-2026-9999",
            source_name="Multi",
            vendor_project="",
            product="requests",
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="CISA KEV",
                    source_identifier="CVE-2026-9999",
                    has_kev_evidence=True,
                ),
                VulnerabilitySourceRecord(
                    source_name="OSV",
                    source_identifier="GHSA-test-test",
                    has_affected_range=True,
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="requests",
                    range_type="ecosystem",
                    introduced="1.0",
                    fixed="2.0",
                    source_name="OSV",
                    raw_range=">= 1.0, < 2.0",
                )
            ],
        )
    ]
    matches = matcher.match(components, vulns)
    assert len(matches) == 1
    assert matches[0].applicability == Applicability.LIKELY_NOT_AFFECTED

    risk_engine = DeterministicRiskEngine()
    assessment = risk_engine.assess(matches[0])
    # Must preserve LIKELY_NOT_AFFECTED despite KEV confirmation
    assert assessment.status == RiskStatus.LIKELY_NOT_AFFECTED
    assert assessment.risk_level == RiskLevel.UNKNOWN
    assert assessment.requires_human_review is False
    assert "KEV_CONFIRMED" in assessment.rule_ids
    assert "APPLICABILITY_LIKELY_NOT_AFFECTED" in assessment.rule_ids


def test_caso11_risk_engine_deterministic_without_ai():
    """Caso 11: Deterministic Risk Engine evaluation with AI offline."""
    comp = DetectedComponent(
        name="log4j",
        version="2.14.0",
        version_type=VersionType.EXACT,
        ecosystem=Ecosystem.MAVEN,
        source_file="pom.xml",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2021-44228",
        cve_id="CVE-2021-44228",
        source_name="NVD",
        vendor_project="apache",
        product="log4j",
        severity="CRITICAL",
        cvss_score=10.0,
        known_ransomware_use="Known",
        source_records=[
            VulnerabilitySourceRecord(
                source_name="CISA KEV",
                source_identifier="CVE-2021-44228",
                has_kev_evidence=True,
            )
        ],
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="maven",
                package_name="log4j",
                range_type="maven",
                introduced="2.0",
                fixed="2.15.0",
                source_name="OSV",
            )
        ],
    )
    matcher = VulnerabilityMatcher()
    matches = matcher.match([comp], [vuln])
    assert len(matches) == 1
    assert matches[0].applicability == Applicability.LIKELY_AFFECTED

    risk_engine = DeterministicRiskEngine()
    assessment = risk_engine.assess(matches[0], ai_analysis=None, decision=None)

    assert assessment.status == RiskStatus.LIKELY_AFFECTED
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert "AI_UNAVAILABLE_FALLBACK" in assessment.rule_ids
    assert "SYSTEMONE_UNAVAILABLE_FALLBACK" in assessment.rule_ids
    assert "APPLICABILITY_LIKELY_AFFECTED" in assessment.rule_ids
    assert "CVSS_CRITICAL" in assessment.rule_ids
    assert "KEV_CONFIRMED" in assessment.rule_ids
    assert "RANSOMWARE_CAMPAIGN_ASSOCIATED" in assessment.rule_ids
    assert assessment.requires_human_review is True


# ===========================================================================
# End-to-End Pipeline Integration Tests with Async Database
# ===========================================================================


@pytest.mark.asyncio
async def test_full_pipeline_multi_source_and_ai_success(
    db_session: AsyncSession,
    tmp_path: Path,
):
    """Caso 5 & Caso 12: Full pipeline with OSV + NVD + CISA correlation and AI success."""
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n")

    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    src_osv, _ = await source_repo.get_or_create("OSV", "osv", "https://osv.dev")
    src_nvd, _ = await source_repo.get_or_create("NVD", "nvd", "https://nvd.nist.gov")
    src_cisa, _ = await source_repo.get_or_create("CISA KEV", "kev", "https://cisa.gov")

    # 1. Upsert OSV record (range + GHSA + CVE)
    osv_record = VulnerabilityRecord(
        canonical_id="GHSA-q2x7-8rv8-9754",
        cve_id="CVE-2021-33503",
        source_name="OSV",
        vendor_project="",
        product="urllib3",
        vulnerability_name="Catastrophic ReDoS in urllib3",
        short_description="ReDoS in urllib3 URL parser",
        identifiers=[
            VulnerabilityIdentifier(
                identifier="GHSA-q2x7-8rv8-9754",
                identifier_type=IdentifierType.GHSA,
                source="OSV",
            ),
            VulnerabilityIdentifier(
                identifier="CVE-2021-33503",
                identifier_type=IdentifierType.CVE,
                source="OSV",
            ),
        ],
        source_records=[
            VulnerabilitySourceRecord(
                source_id=src_osv.id,
                source_name="OSV",
                source_identifier="GHSA-q2x7-8rv8-9754",
                has_affected_range=True,
            )
        ],
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="pypi",
                package_name="urllib3",
                range_type="ecosystem",
                introduced="1.0",
                fixed="1.26.5",
                source_name="OSV",
                raw_range=">= 1.0, < 1.26.5",
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(src_osv.id, [osv_record])
    await db_session.commit()

    # 2. Enrich via NVD (CVSS score + severity)
    nvd_record = VulnerabilityRecord(
        canonical_id="CVE-2021-33503",
        cve_id="CVE-2021-33503",
        source_name="NVD",
        vendor_project="urllib3",
        product="urllib3",
        severity="HIGH",
        cvss_score=7.5,
        identifiers=[
            VulnerabilityIdentifier(
                identifier="CVE-2021-33503",
                identifier_type=IdentifierType.CVE,
                source="NVD",
            )
        ],
        source_records=[
            VulnerabilitySourceRecord(
                source_id=src_nvd.id,
                source_name="NVD",
                source_identifier="CVE-2021-33503",
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(src_nvd.id, [nvd_record])
    await db_session.commit()

    # 3. Enrich via CISA KEV (KEV evidence)
    cisa_record = VulnerabilityRecord(
        canonical_id="CVE-2021-33503",
        cve_id="CVE-2021-33503",
        source_name="CISA KEV",
        vendor_project="urllib3",
        product="urllib3",
        known_ransomware_use="Known",
        identifiers=[
            VulnerabilityIdentifier(
                identifier="CVE-2021-33503",
                identifier_type=IdentifierType.CVE,
                source="CISA KEV",
            )
        ],
        source_records=[
            VulnerabilitySourceRecord(
                source_id=src_cisa.id,
                source_name="CISA KEV",
                source_identifier="CVE-2021-33503",
                has_kev_evidence=True,
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(src_cisa.id, [cisa_record])
    await db_session.commit()

    # Verify multi-source correlation: single vulnerability in DB
    all_vulns = await vuln_repo.get_all()
    assert len(all_vulns) == 1
    db_vuln = all_vulns[0]
    assert len(db_vuln.identifiers) >= 2
    assert len(db_vuln.source_records) == 3
    assert len(db_vuln.affected_ranges) == 1

    # Setup scan engine with active providers
    scanner_reg = ScannerRegistry()
    scanner_reg.register(PythonScanner())

    source_reg = SourceRegistry()
    source_reg.register(CISAKEVSource())

    ai_reg = AIRegistry()
    ai_reg.register_ai_provider(WorkingAIProvider())
    ai_reg.register_decision_provider(WorkingDecisionProvider())

    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
        ai_registry=ai_reg,
        risk_engine=DeterministicRiskEngine(),
        ai_enabled=True,
        decision_enabled=True,
    )

    result = await engine.scan(tmp_path)

    assert result.scan_status == ScanStatus.COMPLETED
    assert result.components_found == 1
    assert result.matches_found == 1

    match = result.matches[0]
    assert match.component.name == "urllib3"
    assert match.component.version == "1.26.4"
    assert match.applicability == Applicability.LIKELY_AFFECTED

    # Check AI and decision integration
    assert match.ai_analysis is not None
    assert match.decision is not None
    assert match.risk_assessment is not None
    assert match.risk_assessment.status == RiskStatus.LIKELY_AFFECTED
    assert match.risk_assessment.risk_level == RiskLevel.CRITICAL
    assert "APPLICABILITY_LIKELY_AFFECTED" in match.risk_assessment.rule_ids
    assert "KEV_CONFIRMED" in match.risk_assessment.rule_ids
    assert "CVSS_HIGH" in match.risk_assessment.rule_ids
    assert "RANSOMWARE_CAMPAIGN_ASSOCIATED" in match.risk_assessment.rule_ids

    # 4. Verify database persistence
    scans = (await db_session.execute(select(ScanDB))).scalars().all()
    assert len(scans) == 1

    matches_db = (await db_session.execute(select(MatchDB))).scalars().all()
    assert len(matches_db) == 1

    evidence_db = (await db_session.execute(select(MatchEvidenceDB))).scalars().all()
    assert len(evidence_db) >= 1
    assert evidence_db[0].package_name == "urllib3"
    assert evidence_db[0].installed_version == "1.26.4"

    ai_db = (await db_session.execute(select(AIAnalysisDB))).scalars().all()
    assert len(ai_db) == 1

    dec_db = (await db_session.execute(select(DecisionResultDB))).scalars().all()
    assert len(dec_db) == 1

    risk_db = (await db_session.execute(select(RiskAssessmentDB))).scalars().all()
    assert len(risk_db) == 1
    assert risk_db[0].status == "likely_affected"
    assert risk_db[0].risk_level == "critical"

    # 5. Idempotency test: run scan again on the same path
    result_2 = await engine.scan(tmp_path)
    assert result_2.scan_status == ScanStatus.COMPLETED
    # Vulns in database should still be 1 (not duplicated)
    all_vulns_after = await vuln_repo.get_all()
    assert len(all_vulns_after) == 1


@pytest.mark.asyncio
async def test_full_pipeline_ai_and_systemone_malformed_fallback(
    db_session: AsyncSession,
    tmp_path: Path,
):
    """Caso 8 & Caso 9: Malformed AI and SystemOne responses fallback gracefully."""
    (tmp_path / "requirements.txt").write_text("django==4.2.11\n")

    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    src, _ = await source_repo.get_or_create("OSV", "osv", "https://osv.dev")
    record = VulnerabilityRecord(
        canonical_id="GHSA-w4rh-hpgg-vjjv",
        cve_id="CVE-2024-42005",
        source_name="OSV",
        vendor_project="Django",
        product="django",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="pypi",
                package_name="django",
                range_type="ecosystem",
                introduced="4.2",
                fixed="4.2.16",
                source_name="OSV",
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(src.id, [record])
    await db_session.commit()

    scanner_reg = ScannerRegistry()
    scanner_reg.register(PythonScanner())

    source_reg = SourceRegistry()
    source_reg.register(CISAKEVSource())

    # Register providers that throw errors
    ai_reg = AIRegistry()
    ai_reg.register_ai_provider(MalformedAIProvider())
    ai_reg.register_decision_provider(MalformedDecisionProvider())

    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
        ai_registry=ai_reg,
        risk_engine=DeterministicRiskEngine(),
        ai_enabled=True,
        decision_enabled=True,
    )

    result = await engine.scan(tmp_path)

    # Must succeed without throwing unhandled exceptions
    assert result.scan_status == ScanStatus.COMPLETED
    assert result.matches_found == 1

    match = result.matches[0]
    # AI and decision failed, so they should be None
    assert match.ai_analysis is None
    assert match.decision is None

    # Deterministic risk assessment should still be generated
    assert match.risk_assessment is not None
    assert match.risk_assessment.status == RiskStatus.LIKELY_AFFECTED
    assert "AI_UNAVAILABLE_FALLBACK" in match.risk_assessment.rule_ids
    assert "SYSTEMONE_UNAVAILABLE_FALLBACK" in match.risk_assessment.rule_ids
    assert "APPLICABILITY_LIKELY_AFFECTED" in match.risk_assessment.rule_ids


class OfflineAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "OfflineAIProvider"

    @property
    def provider_type(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        return False

    async def analyze(self, context: AnalysisContext) -> AIAnalysis:
        raise RuntimeError("Unreachable")


class OfflineDecisionProvider(DecisionProvider):
    @property
    def name(self) -> str:
        return "OfflineDecisionProvider"

    @property
    def provider_type(self) -> str:
        return "ollama_systemone"

    async def is_available(self) -> bool:
        return False

    async def decide(
        self, context: AnalysisContext, questions: list[DecisionQuestion]
    ) -> DecisionResult:
        raise RuntimeError("Unreachable")


@pytest.mark.asyncio
async def test_full_pipeline_ai_and_systemone_offline(
    db_session: AsyncSession,
    tmp_path: Path,
):
    """Caso 6 & Caso 7: AI and SystemOne offline -> scan succeeds with deterministic fallback."""
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")

    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    src, _ = await source_repo.get_or_create("OSV", "osv", "https://osv.dev")
    record = VulnerabilityRecord(
        canonical_id="GHSA-9wx4-h78v-vm56",
        cve_id="CVE-2023-32681",
        source_name="OSV",
        vendor_project="",
        product="requests",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="pypi",
                package_name="requests",
                range_type="ecosystem",
                introduced="2.0",
                fixed="2.31.0",
                source_name="OSV",
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(src.id, [record])
    await db_session.commit()

    scanner_reg = ScannerRegistry()
    scanner_reg.register(PythonScanner())

    source_reg = SourceRegistry()
    source_reg.register(CISAKEVSource())

    ai_reg = AIRegistry()
    ai_reg.register_ai_provider(OfflineAIProvider())
    ai_reg.register_decision_provider(OfflineDecisionProvider())

    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
        ai_registry=ai_reg,
        risk_engine=DeterministicRiskEngine(),
        ai_enabled=True,
        decision_enabled=True,
    )

    result = await engine.scan(tmp_path)
    assert result.scan_status == ScanStatus.COMPLETED
    assert result.matches_found == 1

    match = result.matches[0]
    assert match.ai_analysis is None
    assert match.decision is None
    assert match.risk_assessment is not None
    assert match.risk_assessment.status == RiskStatus.LIKELY_AFFECTED
    assert "AI_UNAVAILABLE_FALLBACK" in match.risk_assessment.rule_ids
    assert "SYSTEMONE_UNAVAILABLE_FALLBACK" in match.risk_assessment.rule_ids


@pytest.mark.asyncio
async def test_persistence_retrieval_and_relationships(
    db_session: AsyncSession,
    tmp_path: Path,
):
    """Caso 30: Verify retrieval of Match and all related entities via MatchRepository."""
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n")

    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    match_repo = MatchRepository(db_session)

    src, _ = await source_repo.get_or_create("OSV", "osv", "https://osv.dev")
    record = VulnerabilityRecord(
        canonical_id="GHSA-xxxx-yyyy-zzzz",
        cve_id="CVE-2022-1234",
        source_name="OSV",
        vendor_project="pallets",
        product="flask",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="pypi",
                package_name="flask",
                range_type="ecosystem",
                introduced="2.0.0",
                fixed="2.1.0",
                source_name="OSV",
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(src.id, [record])
    await db_session.commit()

    scanner_reg = ScannerRegistry()
    scanner_reg.register(PythonScanner())

    source_reg = SourceRegistry()
    source_reg.register(CISAKEVSource())

    ai_reg = AIRegistry()
    ai_reg.register_ai_provider(WorkingAIProvider())
    ai_reg.register_decision_provider(WorkingDecisionProvider())

    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
        ai_registry=ai_reg,
        risk_engine=DeterministicRiskEngine(),
        ai_enabled=True,
        decision_enabled=True,
    )

    result = await engine.scan(tmp_path)
    assert result.scan_status == ScanStatus.COMPLETED

    matches_in_db = await match_repo.get_by_scan(
        (await db_session.execute(select(ScanDB))).scalars().first().id
    )
    assert len(matches_in_db) == 1

    loaded_match = await match_repo.get_by_id(matches_in_db[0].id)
    assert loaded_match is not None
    assert loaded_match.component is not None
    assert loaded_match.component.name == "flask"
    assert loaded_match.vulnerability is not None
    assert loaded_match.vulnerability.canonical_id == "GHSA-xxxx-yyyy-zzzz"
    assert loaded_match.ai_analysis is not None
    assert loaded_match.decision_result is not None
    assert loaded_match.risk_assessment is not None
    assert len(loaded_match.structured_evidences) >= 1
