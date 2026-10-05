"""H11: clean false-positive fixture must not use currently affected request pins."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import (
    AffectedVersionRange,
    Ecosystem,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.registry import SourceRegistry

ROOT = Path(__file__).resolve().parents[1]
CLEAN = ROOT / "fixtures" / "clean_false_positives"


def test_h11_clean_fixture_pins_are_outside_known_requests_ranges() -> None:
    pins = [
        line.strip()
        for line in (CLEAN / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "requests==2.32.3" not in pins
    assert "requests==2.33.0" in pins


@pytest.mark.asyncio
async def test_h11_clean_fixture_zero_likely_affected_with_stub_catalog(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """Offline catalog stubs the historical OSV ranges; clean pins must not match."""
    sources = SourceRepository(db_session)
    vulns = VulnerabilityRepository(db_session)
    osv, _ = await sources.get_or_create(name="OSV", source_type="osv")

    # Historical OSV ranges that made requests==2.32.3 fail the clean-FP criterion.
    await vulns.upsert_vulnerabilities(
        osv.id,
        [
            VulnerabilityRecord(
                canonical_id="CVE-2024-47081",
                cve_id="CVE-2024-47081",
                source_name="OSV",
                product="requests",
                vulnerability_name="CVE-2024-47081",
                identifiers=[
                    VulnerabilityIdentifier(identifier_type="CVE", identifier="CVE-2024-47081")
                ],
                source_records=[
                    VulnerabilitySourceRecord(
                        source_name="OSV",
                        source_identifier="CVE-2024-47081",
                        raw_payload={},
                    )
                ],
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem=Ecosystem.PYPI,
                        package_name="requests",
                        introduced="0",
                        fixed="2.32.4",
                    )
                ],
            ),
            VulnerabilityRecord(
                canonical_id="CVE-2026-25645",
                cve_id="CVE-2026-25645",
                source_name="OSV",
                product="requests",
                vulnerability_name="CVE-2026-25645",
                identifiers=[
                    VulnerabilityIdentifier(identifier_type="CVE", identifier="CVE-2026-25645")
                ],
                source_records=[
                    VulnerabilitySourceRecord(
                        source_name="OSV",
                        source_identifier="CVE-2026-25645",
                        raw_payload={},
                    )
                ],
                affected_ranges=[
                    AffectedVersionRange(
                        ecosystem=Ecosystem.PYPI,
                        package_name="requests",
                        introduced="0",
                        fixed="2.33.0",
                    )
                ],
            ),
        ],
    )

    project = tmp_path / "clean"
    project.mkdir()
    (project / "requirements.txt").write_text((CLEAN / "requirements.txt").read_text())

    scanners = ScannerRegistry()
    scanners.register(PythonScanner())
    engine = ScanEngine(
        session=db_session,
        scanner_registry=scanners,
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )
    summary = await engine.scan(project)
    likely = [
        m
        for m in summary.matches
        if str(getattr(m.applicability, "value", m.applicability)).lower() == "likely_affected"
    ]
    assert likely == []
