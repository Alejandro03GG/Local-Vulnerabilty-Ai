"""Integration test for the full scan pipeline.

Tests the complete flow:
    Scanner → Matcher → Repository → ScanResult

Uses only local fixtures, no internet required.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import (
    Applicability,
    ScanStatus,
)
from vuln_ai.db.repositories import (
    SourceRepository,
    VulnerabilityRepository,
)
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.cisa_kev import CISAKEVSource
from vuln_ai.sources.registry import SourceRegistry


async def _seed_vulnerabilities(session: AsyncSession, fixtures_dir: Path) -> None:
    """Seed the database with test vulnerability data."""
    kev_data = json.loads((fixtures_dir / "sample_kev_data.json").read_text())
    kev_source = CISAKEVSource()
    records = kev_source._parse(kev_data)

    source_repo = SourceRepository(session)
    db_source, _ = await source_repo.get_or_create(
        name="CISA KEV",
        source_type="kev",
        url="https://test.example.com",
    )

    vuln_repo = VulnerabilityRepository(session)
    await vuln_repo.upsert_vulnerabilities(db_source.id, records)
    await session.commit()


class TestScanPipeline:
    """Integration tests for the full scan pipeline."""

    async def test_full_scan(
        self,
        db_session: AsyncSession,
        sample_project_dir: Path,
        fixtures_dir: Path,
    ):
        """Test complete scan pipeline with local fixtures."""
        # Seed vulnerability data
        await _seed_vulnerabilities(db_session, fixtures_dir)

        # Set up registries
        scanner_registry = ScannerRegistry()
        scanner_registry.register(PythonScanner())

        source_registry = SourceRegistry()

        # Create engine and scan
        engine = ScanEngine(
            session=db_session,
            scanner_registry=scanner_registry,
            source_registry=source_registry,
        )

        result = await engine.scan(sample_project_dir)

        # Verify scan completed
        assert result.scan_status == ScanStatus.COMPLETED
        assert result.components_found > 0
        assert result.error is None

    async def test_scan_finds_matches(
        self,
        db_session: AsyncSession,
        sample_project_dir: Path,
        fixtures_dir: Path,
    ):
        """Scan should find matches between project deps and KEV data."""
        await _seed_vulnerabilities(db_session, fixtures_dir)

        scanner_registry = ScannerRegistry()
        scanner_registry.register(PythonScanner())

        engine = ScanEngine(
            session=db_session,
            scanner_registry=scanner_registry,
            source_registry=SourceRegistry(),
        )

        result = await engine.scan(sample_project_dir)

        # Our fixture has Django, Flask, Requests in both requirements.txt
        # and the KEV data
        assert result.matches_found > 0

        # Check specific matches
        matched_components = {m.component.name for m in result.matches}
        # django should match (exact product name match)
        assert "django" in matched_components

    async def test_scan_never_claims_likely_affected(
        self,
        db_session: AsyncSession,
        sample_project_dir: Path,
        fixtures_dir: Path,
    ):
        """Scan should never claim LIKELY_AFFECTED with KEV alone."""
        await _seed_vulnerabilities(db_session, fixtures_dir)

        scanner_registry = ScannerRegistry()
        scanner_registry.register(PythonScanner())

        engine = ScanEngine(
            session=db_session,
            scanner_registry=scanner_registry,
            source_registry=SourceRegistry(),
        )

        result = await engine.scan(sample_project_dir)

        for match in result.matches:
            assert match.applicability != Applicability.LIKELY_AFFECTED, (
                f"Match for {match.vulnerability.cve_id} should not be "
                f"LIKELY_AFFECTED without version evidence"
            )

    async def test_scan_all_matches_have_evidence(
        self,
        db_session: AsyncSession,
        sample_project_dir: Path,
        fixtures_dir: Path,
    ):
        """Every match should have an evidence trail."""
        await _seed_vulnerabilities(db_session, fixtures_dir)

        scanner_registry = ScannerRegistry()
        scanner_registry.register(PythonScanner())

        engine = ScanEngine(
            session=db_session,
            scanner_registry=scanner_registry,
            source_registry=SourceRegistry(),
        )

        result = await engine.scan(sample_project_dir)

        for match in result.matches:
            assert len(match.evidence) > 0, (
                f"Match for {match.vulnerability.cve_id} has no evidence"
            )

    async def test_scan_nonexistent_path(self, db_session: AsyncSession):
        """Scanning a nonexistent path should return a failed result."""
        engine = ScanEngine(
            session=db_session,
            scanner_registry=ScannerRegistry(),
            source_registry=SourceRegistry(),
        )

        result = await engine.scan("/nonexistent/path")
        assert result.scan_status == ScanStatus.FAILED
        assert result.error is not None

    async def test_scan_empty_project(self, db_session: AsyncSession, tmp_path: Path):
        """Scanning an empty directory should complete with 0 components."""
        engine = ScanEngine(
            session=db_session,
            scanner_registry=ScannerRegistry(),
            source_registry=SourceRegistry(),
        )

        result = await engine.scan(tmp_path)
        assert result.scan_status == ScanStatus.COMPLETED
        assert result.components_found == 0
        assert result.matches_found == 0

    async def test_scan_records_duration(
        self,
        db_session: AsyncSession,
        sample_project_dir: Path,
        fixtures_dir: Path,
    ):
        """Scan should record execution time."""
        await _seed_vulnerabilities(db_session, fixtures_dir)

        scanner_registry = ScannerRegistry()
        scanner_registry.register(PythonScanner())

        engine = ScanEngine(
            session=db_session,
            scanner_registry=scanner_registry,
            source_registry=SourceRegistry(),
        )

        result = await engine.scan(sample_project_dir)
        assert result.duration_seconds > 0
