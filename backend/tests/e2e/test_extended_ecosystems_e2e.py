"""Comprehensive E2E scenarios for Extended Ecosystems & Lockfile Resolution (Etapa 14).

Validates Cases A through L from the specification:
- Case A: requirements.txt (preserves previous behavior)
- Case B: poetry.lock (detects transitives)
- Case C: package-lock.json (detects transitives)
- Case D: pnpm-lock.yaml (detects transitives)
- Case E: Cargo.lock (detects transitives)
- Case F: Multiple lockfiles in the same project
- Case G: Multiple versions of same package
- Case H: Vulnerability only in transitive dependency
- Case I: Corrupt lockfile
- Case J: Clean lockfile without vulnerabilities
- Case K: Large dependency graph (1000+ nodes)
- Case L: Artificial cycle in dependency graph
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    ScanStatus,
    VulnerabilityRecord,
)
from vuln_ai.db.repositories import (
    SourceRepository,
    VulnerabilityRepository,
)
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
async def test_case_a_requirements_txt_regression(db_session: AsyncSession, tmp_path: Path):
    """Case A: requirements.txt retains classic direct dependency behavior."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("fastapi==0.115.6\nrequests>=2.0.0\n", encoding="utf-8")

    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )

    summary = await engine.scan(tmp_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.components_found == 2
    assert summary.direct_components_count == 2
    assert summary.transitive_components_count == 0


@pytest.mark.asyncio
async def test_case_b_poetry_lock_transitives(db_session: AsyncSession):
    """Case B: poetry.lock detects direct and transitive dependencies with parents."""
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
    assert summary.components_found >= 5
    assert summary.direct_components_count >= 1
    assert summary.transitive_components_count >= 4
    assert "poetry.lock" in summary.lockfiles_detected


@pytest.mark.asyncio
async def test_case_c_npm_package_lock_transitives(db_session: AsyncSession):
    """Case C: package-lock.json detects express and nested dependencies."""
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
    assert summary.components_found >= 5
    assert "package-lock.json" in summary.lockfiles_detected


@pytest.mark.asyncio
async def test_case_d_pnpm_lock_transitives(db_session: AsyncSession):
    """Case D: pnpm-lock.yaml detects axios and follow-redirects."""
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
    assert summary.components_found >= 5
    assert "pnpm-lock.yaml" in summary.lockfiles_detected


@pytest.mark.asyncio
async def test_case_e_cargo_lock_transitives(db_session: AsyncSession):
    """Case E: Cargo.lock detects crates and transitive dependencies."""
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
    assert summary.components_found >= 5
    assert "Cargo.lock" in summary.lockfiles_detected


@pytest.mark.asyncio
async def test_case_f_multiple_lockfiles(db_session: AsyncSession, tmp_path: Path):
    """Case F: Project with multiple lockfiles (e.g. polyglot repository)."""
    # Copy poetry files
    poetry_dir = Path(__file__).parent.parent / "fixtures" / "sample_poetry"
    (tmp_path / "poetry.lock").write_text((poetry_dir / "poetry.lock").read_text())
    (tmp_path / "pyproject.toml").write_text((poetry_dir / "pyproject.toml").read_text())

    # Copy npm files
    npm_dir = Path(__file__).parent.parent / "fixtures" / "sample_npm"
    (tmp_path / "package-lock.json").write_text((npm_dir / "package-lock.json").read_text())
    (tmp_path / "package.json").write_text((npm_dir / "package.json").read_text())

    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )

    summary = await engine.scan(tmp_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert "poetry.lock" in summary.lockfiles_detected
    assert "package-lock.json" in summary.lockfiles_detected
    assert summary.components_found >= 10


@pytest.mark.asyncio
async def test_case_g_multiple_versions_same_package(db_session: AsyncSession):
    """Case G: Project has multiple versions of the same package (lodash 3.x and 4.x)."""
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

    # Verify both versions exist in the resolved components
    resolved_comps = summary.dependency_graph.resolve_components()
    lodash_comps = [c for c in resolved_comps if c.name == "lodash"]
    assert len(lodash_comps) == 2
    versions = {c.version for c in lodash_comps}
    assert versions == {"3.10.1", "4.17.21"}


@pytest.mark.asyncio
async def test_case_h_vulnerability_only_in_transitive_dependency(
    db_session: AsyncSession, tmp_path: Path
):
    """Case H: Vulnerability present solely in a transitive dependency (anyio)."""
    poetry_dir = Path(__file__).parent.parent / "fixtures" / "sample_poetry"
    (tmp_path / "poetry.lock").write_text((poetry_dir / "poetry.lock").read_text())
    (tmp_path / "pyproject.toml").write_text((poetry_dir / "pyproject.toml").read_text())

    # Add a vulnerability affecting anyio 4.4.0 (introduced 4.0.0, fixed 4.5.0)
    vuln_repo = VulnerabilityRepository(db_session)
    source_repo = SourceRepository(db_session)
    src, _ = await source_repo.get_or_create(name="OSV", source_type="osv")

    record = VulnerabilityRecord(
        canonical_id="GHSA-anyio-vuln-test",
        cve_id="CVE-2024-8888",
        source_name="OSV",
        product="anyio",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="pypi",
                package_name="anyio",
                introduced="4.0.0",
                fixed="4.5.0",
                source_name="OSV",
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(src.id, [record])
    await db_session.commit()

    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )

    summary = await engine.scan(tmp_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.matches_found >= 1

    anyio_match = next(m for m in summary.matches if m.component.name == "anyio")
    assert anyio_match.component.is_direct is False
    assert anyio_match.component.dependency_path == ["fastapi", "starlette", "anyio"]
    assert anyio_match.applicability == Applicability.LIKELY_AFFECTED


@pytest.mark.asyncio
async def test_case_i_corrupt_lockfile_graceful(db_session: AsyncSession, tmp_path: Path):
    """Case I: Corrupt lockfile does not crash the scan engine."""
    (tmp_path / "poetry.lock").write_text("CORRUPTED NOT TOML [[]", encoding="utf-8")

    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )

    summary = await engine.scan(tmp_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.components_found == 0


@pytest.mark.asyncio
async def test_case_j_clean_lockfile_no_vulnerabilities(db_session: AsyncSession, tmp_path: Path):
    """Case J: Clean lockfile produces 0 matches cleanly."""
    lock_content = """
[[package]]
name = "safe-pkg"
version = "1.0.0"
"""
    (tmp_path / "poetry.lock").write_text(lock_content, encoding="utf-8")

    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )

    summary = await engine.scan(tmp_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.components_found == 1
    assert summary.matches_found == 0


@pytest.mark.asyncio
async def test_case_k_large_dependency_graph(db_session: AsyncSession, tmp_path: Path):
    """Case K: Project with a large lockfile (1000+ nodes) scans cleanly."""
    packages = []
    # 1 root
    packages.append(
        '[[package]]\nname = "large-root"\nversion = "1.0.0"\n[package.dependencies]\n'
    )
    for i in range(100):
        packages.append(f'dep-{i} = "1.0.0"\n')

    for i in range(100):
        packages.append(
            f'\n[[package]]\nname = "dep-{i}"\nversion = "1.0.0"\n[package.dependencies]\n'
        )
        for j in range(9):
            packages.append(f'subdep-{i}-{j} = "1.0.0"\n')

    for i in range(100):
        for j in range(9):
            packages.append(f'\n[[package]]\nname = "subdep-{i}-{j}"\nversion = "1.0.0"\n')

    (tmp_path / "poetry.lock").write_text("".join(packages), encoding="utf-8")

    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )

    summary = await engine.scan(tmp_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.components_found == 1001


@pytest.mark.asyncio
async def test_case_l_artificial_cycle(db_session: AsyncSession, tmp_path: Path):
    """Case L: Artificial cycle does not loop indefinitely."""
    lock_content = """
[[package]]
name = "cycle-a"
version = "1.0.0"
[package.dependencies]
cycle-b = "1.0.0"

[[package]]
name = "cycle-b"
version = "1.0.0"
[package.dependencies]
cycle-c = "1.0.0"

[[package]]
name = "cycle-c"
version = "1.0.0"
[package.dependencies]
cycle-a = "1.0.0"
"""
    (tmp_path / "poetry.lock").write_text(lock_content, encoding="utf-8")

    engine = ScanEngine(
        session=db_session,
        scanner_registry=_build_full_scanner_registry(),
        source_registry=SourceRegistry(),
        ai_enabled=False,
        decision_enabled=False,
    )

    summary = await engine.scan(tmp_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.components_found == 3
    assert len(summary.dependency_graph.cycles) > 0
