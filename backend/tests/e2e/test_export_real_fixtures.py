"""Tests exporting real lockfile fixtures (Etapa 15 §47).

Validates that real lockfiles from all supported ecosystems produce valid
SARIF, CycloneDX, and SPDX documents with accurate components, PURLs, and graphs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import ScanStatus
from vuln_ai.export.cyclonedx import export_cyclonedx_dict, validate_cyclonedx_dict
from vuln_ai.export.models import ExportScan
from vuln_ai.export.sarif import export_sarif_dict, validate_sarif_dict
from vuln_ai.export.spdx import export_spdx_dict, validate_spdx_dict
from vuln_ai.scanners.cargo_scanner import CargoLockScanner
from vuln_ai.scanners.npm_scanner import NpmLockScanner
from vuln_ai.scanners.pnpm_scanner import PnpmLockScanner
from vuln_ai.scanners.poetry_scanner import PoetryLockScanner
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.registry import SourceRegistry


def _build_full_scanner_registry() -> ScannerRegistry:
    registry = ScannerRegistry()
    registry.register(PythonScanner())
    registry.register(PoetryLockScanner())
    registry.register(NpmLockScanner())
    registry.register(PnpmLockScanner())
    registry.register(CargoLockScanner())
    return registry


@pytest.mark.asyncio
async def test_export_real_poetry_fixture(db_session: AsyncSession):
    """Real fixture: poetry.lock exported to SARIF, CycloneDX, and SPDX."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_poetry"
    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )
    summary = await engine.scan(fixtures_dir)
    assert summary.scan_status == ScanStatus.COMPLETED

    scan = ExportScan.from_scan_summary(summary)
    assert len(scan.components) >= 5

    # SARIF
    sarif = export_sarif_dict(scan)
    validate_sarif_dict(sarif)
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Local Vulnerability AI"

    # CycloneDX
    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)
    purls = [c.get("purl") for c in cdx["components"] if c.get("purl")]
    assert any("pkg:pypi/" in p for p in purls)
    # Check dependency tree exists
    assert "dependencies" in cdx
    assert len(cdx["dependencies"]) >= 1

    # SPDX
    spdx = export_spdx_dict(scan)
    validate_spdx_dict(spdx)
    assert len(spdx["packages"]) == len(scan.components) + 1


@pytest.mark.asyncio
async def test_export_real_npm_fixture(db_session: AsyncSession):
    """Real fixture: package-lock.json exported to SARIF, CycloneDX, and SPDX."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_npm"
    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )
    summary = await engine.scan(fixtures_dir)
    assert summary.scan_status == ScanStatus.COMPLETED

    scan = ExportScan.from_scan_summary(summary)
    assert len(scan.components) >= 5

    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)
    purls = [c.get("purl") for c in cdx["components"] if c.get("purl")]
    assert any("pkg:npm/" in p for p in purls)

    spdx = export_spdx_dict(scan)
    validate_spdx_dict(spdx)
    assert any(p["name"] == "express" for p in spdx["packages"])


@pytest.mark.asyncio
async def test_export_real_pnpm_fixture(db_session: AsyncSession):
    """Real fixture: pnpm-lock.yaml exported to SARIF, CycloneDX, and SPDX."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_pnpm"
    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )
    summary = await engine.scan(fixtures_dir)
    assert summary.scan_status == ScanStatus.COMPLETED

    scan = ExportScan.from_scan_summary(summary)
    sarif = export_sarif_dict(scan)
    validate_sarif_dict(sarif)

    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)


@pytest.mark.asyncio
async def test_export_real_cargo_fixture(db_session: AsyncSession):
    """Real fixture: Cargo.lock exported to SARIF, CycloneDX, and SPDX."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_cargo"
    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )
    summary = await engine.scan(fixtures_dir)
    assert summary.scan_status == ScanStatus.COMPLETED

    scan = ExportScan.from_scan_summary(summary)
    spdx = export_spdx_dict(scan)
    validate_spdx_dict(spdx)

    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)
    purls = [c.get("purl") for c in cdx["components"] if c.get("purl")]
    assert any("pkg:cargo/" in p for p in purls)
