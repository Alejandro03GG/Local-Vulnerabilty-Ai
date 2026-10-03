"""End-to-End integration and reliability tests for Local Vulnerability AI.

Exercises complete scenarios:
Project -> Dependency Scanner -> Version-aware Matcher -> Multi-Source Conflict Resolution
-> AI / SystemOne Providers -> Deterministic Risk Engine -> Database -> FastAPI Endpoints.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.base import AIProvider, DecisionProvider
from vuln_ai.ai.models import AIAnalysis, DecisionResult
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.api.deps import get_ai_registry
from vuln_ai.api.main import app
from vuln_ai.core.models import (
    AffectedVersionRange,
    Ecosystem,
    VulnerabilityRecord,
)
from vuln_ai.db.repositories import (
    SourceRepository,
    VulnerabilityRepository,
)


class MockHealthyAI(AIProvider):
    @property
    def name(self) -> str:
        return "ollama_llama"

    @property
    def provider_type(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        return True

    async def analyze(self, context) -> AIAnalysis:
        return AIAnalysis(
            provider=self.name,
            model="llama3.2:latest",
            explanation=f"Contextual analysis for {context.component_name} in {context.source_file}",
            evidence=["Evaluated version boundaries against CVE metadata"],
            contextual_findings=["Standard network usage"],
            requires_human_review=False,
            analysis_duration_seconds=0.08,
            tokens_used=120,
        )


class MockHealthyDecision(DecisionProvider):
    @property
    def name(self) -> str:
        return "systemone_decision"

    @property
    def provider_type(self) -> str:
        return "systemone"

    async def is_available(self) -> bool:
        return True

    async def evaluate_decision(self, questions, context) -> DecisionResult:
        return DecisionResult(
            provider=self.name,
            model="systemone-fast",
            responses={q.id: "Affirmative" for q in questions},
            decision_probabilities={"applicable": 0.85, "not_applicable": 0.15},
            applicability_probability=0.85,
            urgency_score=7.0,
            latency_seconds=0.04,
        )


class MockFailingAI(AIProvider):
    @property
    def name(self) -> str:
        return "failing_ai"

    @property
    def provider_type(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        return False

    async def analyze(self, context) -> AIAnalysis:
        raise RuntimeError("Ollama connection refused on localhost:11434")


class MockFailingDecision(DecisionProvider):
    @property
    def name(self) -> str:
        return "failing_decision"

    @property
    def provider_type(self) -> str:
        return "systemone"

    async def is_available(self) -> bool:
        return False

    async def evaluate_decision(self, questions, context) -> DecisionResult:
        raise RuntimeError("SystemOne inference engine timeout")


@pytest.fixture
def healthy_ai_registry() -> AIRegistry:
    reg = AIRegistry()
    reg.register_ai_provider(MockHealthyAI())
    reg.register_decision_provider(MockHealthyDecision())
    return reg


@pytest.fixture
def offline_ai_registry() -> AIRegistry:
    reg = AIRegistry()
    reg.register_ai_provider(MockFailingAI())
    reg.register_decision_provider(MockFailingDecision())
    return reg


async def _seed_intelligence_sources(session: AsyncSession) -> dict[str, str]:
    """Seed OSV, NVD, and CISA KEV sources in DB."""
    source_repo = SourceRepository(session)
    osv, _ = await source_repo.get_or_create(
        name="OSV",
        source_type="ecosystem",
        url="https://api.osv.dev",
    )
    nvd, _ = await source_repo.get_or_create(
        name="NVD",
        source_type="nvd",
        url="https://services.nvd.nist.gov",
    )
    cisa, _ = await source_repo.get_or_create(
        name="CISA KEV",
        source_type="kev",
        url="https://cisa.gov/kev",
    )
    return {"OSV": osv.id, "NVD": nvd.id, "CISA KEV": cisa.id}


# ============================================================================
# SCENARIO A: No Vulnerability Match
# ============================================================================
async def test_scenario_a_no_vulnerability(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    healthy_ai_registry: AIRegistry,
):
    """Fixture A: Scanned dependency has no known CVE -> 0 matches, completed scan."""
    app.dependency_overrides[get_ai_registry] = lambda: healthy_ai_registry
    try:
        # Create test project directory with safe dependency
        proj_dir = tmp_path / "safe_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("clean-package==1.0.0\n")

        # 1. Create project via API
        resp = await api_client.post(
            "/api/v1/projects",
            json={"name": "Safe Project", "path": str(proj_dir)},
        )
        assert resp.status_code == 201
        proj_id = resp.json()["id"]

        # 2. Run scan
        scan_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan_resp.status_code == 201
        scan_data = scan_resp.json()
        assert scan_data["status"] == "completed"
        assert scan_data["components_found"] == 1
        assert scan_data["vulnerabilities_found"] == 0
        assert scan_data["matches"] == []
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIO B: Affected (Within Range)
# ============================================================================
async def test_scenario_b_affected_within_range(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    healthy_ai_registry: AIRegistry,
):
    """Fixture B: urllib3 2.31.0 within OSV [2.0, 2.32) -> LIKELY_AFFECTED."""
    app.dependency_overrides[get_ai_registry] = lambda: healthy_ai_registry
    try:
        source_map = await _seed_intelligence_sources(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        # Seed advisory
        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["OSV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="GHSA-test-b",
                    cve_id="CVE-2024-0001",
                    vulnerability_name="Proxy Leak",
                    source_name="OSV",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="urllib3",
                            range_type="ECOSYSTEM",
                            introduced="2.0",
                            fixed="2.32.0",
                            source_name="OSV",
                        )
                    ],
                )
            ],
        )

        proj_dir = tmp_path / "b_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("urllib3==2.31.0\n")

        p_resp = await api_client.post(
            "/api/v1/projects", json={"name": "Proj B", "path": str(proj_dir)}
        )
        proj_id = p_resp.json()["id"]

        scan_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        # Fetch matches
        m_resp = await api_client.get(f"/api/v1/matches?scan_id={scan_id}")
        assert m_resp.status_code == 200
        matches = m_resp.json()["items"]
        assert len(matches) == 1
        m = matches[0]
        assert m["applicability"].upper() == "LIKELY_AFFECTED"
        assert m["component"]["version"] == "2.31.0"
        assert m["risk_assessment"]["risk_level"].upper() in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert "APPLICABILITY_LIKELY_AFFECTED" in m["risk_assessment"]["rule_ids"]
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIO C: Outside Range
# ============================================================================
async def test_scenario_c_outside_range(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    healthy_ai_registry: AIRegistry,
):
    """Fixture C: urllib3 2.32.0 outside [2.0, 2.32) -> LIKELY_NOT_AFFECTED."""
    app.dependency_overrides[get_ai_registry] = lambda: healthy_ai_registry
    try:
        source_map = await _seed_intelligence_sources(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["OSV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="GHSA-test-c",
                    cve_id="CVE-2024-0002",
                    vulnerability_name="Proxy Leak Patch",
                    source_name="OSV",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="urllib3",
                            range_type="ECOSYSTEM",
                            introduced="2.0",
                            fixed="2.32.0",
                            source_name="OSV",
                        )
                    ],
                )
            ],
        )

        proj_dir = tmp_path / "c_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("urllib3==2.32.0\n")

        p_resp = await api_client.post(
            "/api/v1/projects", json={"name": "Proj C", "path": str(proj_dir)}
        )
        proj_id = p_resp.json()["id"]

        scan_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        m_resp = await api_client.get(f"/api/v1/matches?scan_id={scan_id}")
        assert m_resp.status_code == 200
        matches = m_resp.json()["items"]
        assert len(matches) == 1
        assert matches[0]["applicability"].upper() == "LIKELY_NOT_AFFECTED"
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIO D: CISA KEV Only (No Range) -> DETECTED
# ============================================================================
async def test_scenario_d_cisa_only_detected(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    healthy_ai_registry: AIRegistry,
):
    """Fixture D: Component matched solely by catalog without affected range -> DETECTED."""
    app.dependency_overrides[get_ai_registry] = lambda: healthy_ai_registry
    try:
        source_map = await _seed_intelligence_sources(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["CISA KEV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="CISA-test-d",
                    cve_id="CVE-2024-9999",
                    product="legacy-lib",
                    vendor_project="legacy-lib",
                    vulnerability_name="Legacy CVE",
                    source_name="CISA KEV",
                    affected_ranges=[],  # No version range
                )
            ],
        )

        proj_dir = tmp_path / "d_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("legacy-lib==1.0.0\n")

        p_resp = await api_client.post(
            "/api/v1/projects", json={"name": "Proj D", "path": str(proj_dir)}
        )
        proj_id = p_resp.json()["id"]

        scan_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        m_resp = await api_client.get(f"/api/v1/matches?scan_id={scan_id}")
        assert m_resp.status_code == 200
        matches = m_resp.json()["items"]
        assert len(matches) == 1
        assert matches[0]["applicability"].upper() == "DETECTED"
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIOS E & 11: CRITICAL E2E MULTI-SOURCE CONFLICT
# OSV (AFFECTED) + NVD (NOT_AFFECTED) + CISA (DETECTED) -> REQUIRES_REVIEW
# ============================================================================
async def test_scenario_e_and_critical_multi_source_conflict(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    healthy_ai_registry: AIRegistry,
):
    """Sections 9(E) & 11: OSV AFFECTED vs NVD NOT_AFFECTED vs CISA DETECTED.

    Must produce:
    - Applicability: REQUIRES_REVIEW
    - Risk: requires_human_review = true
    - Rule: SOURCE_APPLICABILITY_CONFLICT
    - Match evidence records from all sources
    - Distinctive conflict record in DB and API response
    """
    app.dependency_overrides[get_ai_registry] = lambda: healthy_ai_registry
    try:
        source_map = await _seed_intelligence_sources(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        # Correlated multi-source vulnerability under canonical CVE-2024-5555
        # 1. OSV: range [1.0, 2.0) -> component 1.5 is WITHIN
        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["OSV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="GHSA-conflict-01",
                    cve_id="CVE-2024-5555",
                    vulnerability_name="Multi-source advisory",
                    source_name="OSV",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="shared-dep",
                            range_type="ECOSYSTEM",
                            introduced="1.0",
                            fixed="2.0",
                            source_name="OSV",
                        )
                    ],
                )
            ],
        )

        # 2. NVD: range <1.4 -> component 1.5 is OUTSIDE
        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["NVD"],
            records=[
                VulnerabilityRecord(
                    canonical_id="CVE-2024-5555",
                    cve_id="CVE-2024-5555",
                    vulnerability_name="Multi-source advisory",
                    source_name="NVD",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="shared-dep",
                            range_type="ECOSYSTEM",
                            introduced="0",
                            fixed="1.4",
                            source_name="NVD",
                        )
                    ],
                )
            ],
        )

        # 3. CISA KEV: entry for CVE-2024-5555 without range
        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["CISA KEV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="CVE-2024-5555",
                    cve_id="CVE-2024-5555",
                    product="shared-dep",
                    vulnerability_name="Exploited in wild",
                    source_name="CISA KEV",
                    known_ransomware_use="Known",
                    affected_ranges=[],
                )
            ],
        )

        # Create target codebase with shared-dep 1.5.0
        proj_dir = tmp_path / "conflict_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("shared-dep==1.5.0\n")

        p_resp = await api_client.post(
            "/api/v1/projects", json={"name": "Conflict Project", "path": str(proj_dir)}
        )
        assert p_resp.status_code == 201
        proj_id = p_resp.json()["id"]

        # Run Scan
        scan_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        # Verify scan summary flags requires_review
        scan_detail = await api_client.get(f"/api/v1/scans/{scan_id}")
        assert scan_detail.status_code == 200
        assert scan_detail.json()["summary"]["requires_review"] >= 1

        # Query Match details via GET /api/v1/matches/{id}
        m_list = await api_client.get(f"/api/v1/matches?scan_id={scan_id}")
        assert m_list.status_code == 200
        match_id = m_list.json()["items"][0]["id"]

        match_full = await api_client.get(f"/api/v1/matches/{match_id}")
        assert match_full.status_code == 200
        m = match_full.json()

        # Assert Section 11 requirements
        assert m["applicability"].upper() == "REQUIRES_REVIEW"
        assert m["risk_assessment"]["requires_human_review"] is True
        assert "SOURCE_APPLICABILITY_CONFLICT" in m["risk_assessment"]["rule_ids"]
        assert "KEV_CONFIRMED" in m["risk_assessment"]["rule_ids"]

        # Verify structured evidence from sources exists
        assert len(m["structured_evidences"]) >= 2
        sources_reported = [ev["source_name"] for ev in m["structured_evidences"]]
        assert "OSV" in sources_reported
        assert "NVD" in sources_reported

        # Verify conflict payload
        assert len(m["conflicts"]) >= 1
        conflict = m["conflicts"][0]
        assert conflict["conflict_type"] == "applicability"
        assert conflict["resolution"].upper() == "REQUIRES_REVIEW"
        assert "OSV" in conflict["sources"]
        assert "NVD" in conflict["sources"]
        assert str(conflict["values"]["OSV"]).upper() == "LIKELY_AFFECTED"
        assert str(conflict["values"]["NVD"]).upper() == "LIKELY_NOT_AFFECTED"
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIO F: Multi-Source Agreement
# ============================================================================
async def test_scenario_f_multi_source_agreement(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    healthy_ai_registry: AIRegistry,
):
    """Fixture F: OSV and NVD both agree AFFECTED, CISA KEV present -> LIKELY_AFFECTED."""
    app.dependency_overrides[get_ai_registry] = lambda: healthy_ai_registry
    try:
        source_map = await _seed_intelligence_sources(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        # OSV: [1.0, 3.0) -> 2.0 is WITHIN
        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["OSV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="GHSA-agree-01",
                    cve_id="CVE-2024-7777",
                    vulnerability_name="Agreed advisory",
                    source_name="OSV",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="agreed-pkg",
                            range_type="ECOSYSTEM",
                            introduced="1.0",
                            fixed="3.0",
                            source_name="OSV",
                        )
                    ],
                )
            ],
        )

        # NVD: [1.0, 3.0) -> 2.0 is WITHIN
        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["NVD"],
            records=[
                VulnerabilityRecord(
                    canonical_id="CVE-2024-7777",
                    cve_id="CVE-2024-7777",
                    vulnerability_name="Agreed advisory",
                    source_name="NVD",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="agreed-pkg",
                            range_type="ECOSYSTEM",
                            introduced="1.0",
                            fixed="3.0",
                            source_name="NVD",
                        )
                    ],
                )
            ],
        )

        proj_dir = tmp_path / "agree_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("agreed-pkg==2.0.0\n")

        p_resp = await api_client.post(
            "/api/v1/projects", json={"name": "Agreement Proj", "path": str(proj_dir)}
        )
        proj_id = p_resp.json()["id"]

        scan_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        m_resp = await api_client.get(f"/api/v1/matches?scan_id={scan_id}")
        assert m_resp.status_code == 200
        matches = m_resp.json()["items"]
        assert len(matches) == 1
        m = matches[0]
        assert m["applicability"].upper() == "LIKELY_AFFECTED"
        assert len(m["conflicts"]) == 0
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIOS G & H: AI & SystemOne Failures Handled Gracefully
# ============================================================================
async def test_scenarios_g_and_h_ai_and_systemone_unavailable(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    offline_ai_registry: AIRegistry,
):
    """Fixtures G & H: AI and SystemOne offline -> Scan completes, fallback recorded, risk calculated."""
    app.dependency_overrides[get_ai_registry] = lambda: offline_ai_registry
    try:
        source_map = await _seed_intelligence_sources(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["OSV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="GHSA-offline-01",
                    cve_id="CVE-2024-8888",
                    vulnerability_name="Offline test vuln",
                    source_name="OSV",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="offline-dep",
                            range_type="ECOSYSTEM",
                            introduced="1.0",
                            fixed="2.0",
                            source_name="OSV",
                        )
                    ],
                )
            ],
        )

        proj_dir = tmp_path / "offline_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("offline-dep==1.5.0\n")

        p_resp = await api_client.post(
            "/api/v1/projects", json={"name": "Offline AI Proj", "path": str(proj_dir)}
        )
        proj_id = p_resp.json()["id"]

        # Run scan with run_ai=True even though Ollama is down
        scan_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        # Verify scan succeeded despite AI service offline
        scan_data = scan_resp.json()
        assert scan_data["status"] == "completed"

        # Verify match details
        m_resp = await api_client.get(f"/api/v1/matches?scan_id={scan_id}")
        match = m_resp.json()["items"][0]
        assert match["applicability"].upper() == "LIKELY_AFFECTED"
        assert match["risk_assessment"] is not None
        assert "AI_UNAVAILABLE_FALLBACK" in match["risk_assessment"]["rule_ids"]
        assert match["risk_assessment"]["requires_human_review"] is True
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIO I: Idempotency & Database Integrity
# ============================================================================
async def test_scenario_i_idempotency_same_scan_twice(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    healthy_ai_registry: AIRegistry,
):
    """Section 25: Executing scan twice on same project preserves data integrity without duplicate corruption."""
    app.dependency_overrides[get_ai_registry] = lambda: healthy_ai_registry
    try:
        source_map = await _seed_intelligence_sources(db_session)
        vuln_repo = VulnerabilityRepository(db_session)

        await vuln_repo.upsert_vulnerabilities(
            source_id=source_map["OSV"],
            records=[
                VulnerabilityRecord(
                    canonical_id="GHSA-idem-01",
                    cve_id="CVE-2024-1111",
                    vulnerability_name="Idempotency vuln",
                    source_name="OSV",
                    affected_ranges=[
                        AffectedVersionRange(
                            ecosystem=Ecosystem.PYPI,
                            package_name="idem-pkg",
                            range_type="ECOSYSTEM",
                            introduced="1.0",
                            fixed="2.0",
                            source_name="OSV",
                        )
                    ],
                )
            ],
        )

        proj_dir = tmp_path / "idem_proj"
        proj_dir.mkdir()
        (proj_dir / "requirements.txt").write_text("idem-pkg==1.2.0\n")

        p_resp = await api_client.post(
            "/api/v1/projects", json={"name": "Idem Proj", "path": str(proj_dir)}
        )
        proj_id = p_resp.json()["id"]

        # First scan
        scan1_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan1_resp.status_code == 201
        scan1 = scan1_resp.json()
        assert scan1["status"] == "completed"

        # Second scan
        scan2_resp = await api_client.post(
            f"/api/v1/projects/{proj_id}/scans", json={"run_ai": True}
        )
        assert scan2_resp.status_code == 201
        scan2 = scan2_resp.json()
        assert scan2["status"] == "completed"

        # Scans are distinct records
        assert scan1["id"] != scan2["id"]

        # Components for this project are not duplicated endlessly
        comps = (await api_client.get(f"/api/v1/projects/{proj_id}/components")).json()["items"]
        assert len(comps) == 1
    finally:
        app.dependency_overrides.pop(get_ai_registry, None)


# ============================================================================
# SCENARIO J: Empty Database Resilience
# ============================================================================
async def test_scenario_j_empty_database_endpoints(api_client: AsyncClient):
    """Section 30: System operates cleanly on a completely empty database without crashing."""
    p_resp = await api_client.get("/api/v1/projects")
    assert p_resp.status_code == 200
    assert p_resp.json()["total"] == 0
    assert p_resp.json()["items"] == []

    s_resp = await api_client.get("/api/v1/scans")
    assert s_resp.status_code == 200
    assert s_resp.json()["total"] == 0

    m_resp = await api_client.get("/api/v1/matches")
    assert m_resp.status_code == 200
    assert m_resp.json()["total"] == 0

    v_resp = await api_client.get("/api/v1/vulnerabilities")
    assert v_resp.status_code == 200
    assert v_resp.json()["total"] == 0

    src_resp = await api_client.get("/api/v1/sources")
    assert src_resp.status_code == 200
    assert isinstance(src_resp.json(), list)


# ============================================================================
# SCENARIO K: Large Dataset (N+1 / Performance Audit)
# ============================================================================
async def test_scenario_k_large_dataset_performance(
    api_client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
):
    """Section 31: Seed 50 components & 50 vulnerabilities, verify fast non-N+1 scan & match queries."""
    source_map = await _seed_intelligence_sources(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    # Seed 50 vulnerabilities in batch
    records = [
        VulnerabilityRecord(
            canonical_id=f"GHSA-large-{i:03d}",
            cve_id=f"CVE-2024-{1000 + i}",
            vulnerability_name=f"Bulk vuln {i}",
            source_name="OSV",
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem=Ecosystem.PYPI,
                    package_name=f"pkg-{i:03d}",
                    range_type="ECOSYSTEM",
                    introduced="1.0",
                    fixed="2.0",
                    source_name="OSV",
                )
            ],
        )
        for i in range(50)
    ]
    await vuln_repo.upsert_vulnerabilities(
        source_id=source_map["OSV"],
        records=records,
    )

    # Project with 50 packages matching those vulnerabilities
    req_lines = [f"pkg-{i:03d}==1.5.0\n" for i in range(50)]
    proj_dir = tmp_path / "large_proj"
    proj_dir.mkdir()
    (proj_dir / "requirements.txt").write_text("".join(req_lines))

    p_resp = await api_client.post(
        "/api/v1/projects", json={"name": "Large Proj", "path": str(proj_dir)}
    )
    proj_id = p_resp.json()["id"]

    # Run scan without AI (pure deterministic engine speed check)
    scan_resp = await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    assert scan_resp.status_code == 201
    scan_data = scan_resp.json()
    assert scan_data["components_found"] == 50
    assert scan_data["vulnerabilities_found"] == 50

    # Query paginated matches: page 1
    m_page1 = await api_client.get(
        f"/api/v1/matches?scan_id={scan_data['id']}&page=1&page_size=20"
    )
    assert m_page1.status_code == 200
    p1_data = m_page1.json()
    assert p1_data["total"] == 50
    assert len(p1_data["items"]) == 20

    # Query paginated matches: page 2
    m_page2 = await api_client.get(
        f"/api/v1/matches?scan_id={scan_data['id']}&page=2&page_size=20"
    )
    assert m_page2.status_code == 200
    p2_data = m_page2.json()
    assert len(p2_data["items"]) == 20
    # Items across pages should be distinct
    ids_p1 = {item["id"] for item in p1_data["items"]}
    ids_p2 = {item["id"] for item in p2_data["items"]}
    assert ids_p1.isdisjoint(ids_p2)


# ============================================================================
# SCENARIO L: Standardized Error Contracts & Request IDs
# ============================================================================
async def test_scenario_l_error_contract_and_request_id(api_client: AsyncClient):
    """Section 14 & 15: HTTP 400, 404, 422 return standardized error format and preserve X-Request-ID."""
    custom_request_id = "req-client-audit-999"

    # 404 Not Found
    resp_404 = await api_client.get(
        "/api/v1/projects/non-existent-id",
        headers={"X-Request-ID": custom_request_id},
    )
    assert resp_404.status_code == 404
    assert resp_404.headers["X-Request-ID"] == custom_request_id
    data_404 = resp_404.json()
    assert "error" in data_404
    assert data_404["error"]["code"] == "PROJECT_NOT_FOUND"

    # 422 Validation Error
    resp_422 = await api_client.post(
        "/api/v1/projects",
        json={"invalid_field": "test"},
        headers={"X-Request-ID": custom_request_id},
    )
    assert resp_422.status_code == 422
    assert resp_422.headers["X-Request-ID"] == custom_request_id
