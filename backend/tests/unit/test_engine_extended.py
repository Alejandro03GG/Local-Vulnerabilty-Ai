"""Extended tests for ScanEngine: update_sources and failure modes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import ScanStatus, SyncResult, VulnerabilityRecord
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.registry import SourceRegistry


class MockSuccessfulSource:
    """Mock source that succeeds when syncing."""

    def __init__(self, records: list[VulnerabilityRecord]):
        self._records = records

    @property
    def name(self) -> str:
        return "MockSuccess"

    @property
    def source_type(self) -> str:
        return "MOCK"

    @property
    def url(self) -> str:
        return "https://example.com/mock.json"

    @property
    def records(self) -> list[VulnerabilityRecord]:
        return self._records

    async def sync(self) -> SyncResult:
        return SyncResult(
            source_name=self.name,
            success=True,
            records_synced=len(self._records),
            records_total=len(self._records),
            duration_seconds=0.05,
        )

    async def search(self, query):
        return []


class MockFailingSource:
    """Mock source that fails when syncing."""

    @property
    def name(self) -> str:
        return "MockFailure"

    @property
    def source_type(self) -> str:
        return "MOCK"

    @property
    def url(self) -> str:
        return "https://example.com/mock_fail.json"

    @property
    def records(self) -> list[VulnerabilityRecord]:
        return []

    async def sync(self) -> SyncResult:
        return SyncResult(
            source_name=self.name,
            success=False,
            error="Connection timeout to upstream server",
            duration_seconds=0.1,
        )

    async def search(self, query):
        return []


@pytest.mark.asyncio
async def test_update_sources_success(
    db_session: AsyncSession,
    sample_vulnerabilities: list[VulnerabilityRecord],
):
    """update_sources updates database records and returns success reports."""
    source_reg = SourceRegistry()
    mock_src = MockSuccessfulSource(sample_vulnerabilities)
    source_reg.register(mock_src)

    scanner_reg = ScannerRegistry()
    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
    )

    results = await engine.update_sources()

    assert len(results) == 1
    assert results[0]["source"] == "MockSuccess"
    assert results[0]["success"] is True
    assert results[0]["records"] == len(sample_vulnerabilities)


@pytest.mark.asyncio
async def test_update_sources_failure(db_session: AsyncSession):
    """update_sources gracefully reports source failure without crashing."""
    source_reg = SourceRegistry()
    failing_src = MockFailingSource()
    source_reg.register(failing_src)

    scanner_reg = ScannerRegistry()
    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
    )

    results = await engine.update_sources()

    assert len(results) == 1
    assert results[0]["source"] == "MockFailure"
    assert results[0]["success"] is False
    assert "timeout" in results[0]["error"].lower()


@pytest.mark.asyncio
async def test_scan_exception_handling(
    db_session: AsyncSession,
    tmp_path: Path,
):
    """ScanEngine.scan handles unexpected exceptions during scan gracefully."""
    scanner_reg = ScannerRegistry()
    mock_scanner = PythonScanner()
    # Force scanner to throw an unexpected exception
    mock_scanner.scan = MagicMock(side_effect=RuntimeError("Simulated scanner crash"))
    scanner_reg.register(mock_scanner)

    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=SourceRegistry(),
        matcher=VulnerabilityMatcher(),
    )

    result = await engine.scan(tmp_path)

    assert result.scan_status == ScanStatus.FAILED
    assert "Simulated scanner crash" in result.error


@pytest.mark.asyncio
async def test_scan_ai_and_decision_provider_exceptions(
    db_session: AsyncSession,
    tmp_path: Path,
    sample_vulnerabilities: list[VulnerabilityRecord],
):
    """ScanEngine handles exceptions inside AI and Decision providers gracefully."""
    from vuln_ai.ai.registry import AIRegistry
    from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository

    # Populate dummy source and vuln in db
    src_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    db_src, _ = await src_repo.get_or_create(
        name="CISA KEV",
        source_type="kev",
        url="https://example.com/kev.json",
    )
    await vuln_repo.upsert_vulnerabilities(db_src.id, sample_vulnerabilities)
    await db_session.commit()

    (tmp_path / "requirements.txt").write_text("django==4.2.11\n")

    scanner_reg = ScannerRegistry()
    scanner_reg.register(PythonScanner())

    # Create AI and Decision providers that raise errors during analysis/decision
    mock_ai = MagicMock()
    mock_ai.name = "FailingAI"
    mock_ai.is_available = AsyncMock(return_value=True)
    mock_ai.analyze = AsyncMock(side_effect=RuntimeError("AI runtime boom"))

    mock_dec = MagicMock()
    mock_dec.name = "FailingDec"
    mock_dec.is_available = AsyncMock(return_value=True)
    mock_dec.decide = AsyncMock(side_effect=RuntimeError("Decision runtime boom"))

    ai_reg = AIRegistry()
    ai_reg.register_ai_provider(mock_ai)
    ai_reg.register_decision_provider(mock_dec)

    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanner_reg,
        source_registry=SourceRegistry(),
        matcher=VulnerabilityMatcher(),
        ai_registry=ai_reg,
        ai_enabled=True,
        decision_enabled=True,
    )

    result = await engine.scan(tmp_path)

    # Scan succeeds despite provider crashes
    assert result.scan_status == ScanStatus.COMPLETED
    assert result.matches_found >= 1
    match = result.matches[0]
    assert match.ai_analysis is None
    assert match.decision is None
    assert match.risk_assessment is not None
    assert "AI_UNAVAILABLE_FALLBACK" in match.risk_assessment.rule_ids
