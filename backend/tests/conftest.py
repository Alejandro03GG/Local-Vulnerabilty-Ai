"""Shared test fixtures and configuration."""

from __future__ import annotations

import json
import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from vuln_ai.config import Settings
from vuln_ai.core.models import (
    ComponentType,
    DetectedComponent,
    Ecosystem,
    VersionType,
    VulnerabilityRecord,
)
from vuln_ai.db.models import Base

FIXTURES_DIR = Path(__file__) / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_kev_data(fixtures_dir: Path) -> dict:
    """Load the sample KEV data fixture."""
    kev_file = fixtures_dir / "sample_kev_data.json"
    return json.loads(kev_file.read_text())


@pytest.fixture
def ollama_analysis_success_data(fixtures_dir: Path) -> dict:
    """Load the sample Ollama analysis success fixture."""
    file = fixtures_dir / "ollama" / "analysis_success.json"
    return json.loads(file.read_text())


@pytest.fixture
def ollama_analysis_invalid_data(fixtures_dir: Path) -> dict:
    """Load the sample Ollama analysis invalid fixture."""
    file = fixtures_dir / "ollama" / "analysis_invalid.json"
    return json.loads(file.read_text())


@pytest.fixture
def ollama_systemone_success_data(fixtures_dir: Path) -> dict:
    """Load the sample Ollama SystemOne success fixture."""
    file = fixtures_dir / "ollama" / "systemone_success.json"
    return json.loads(file.read_text())


@pytest.fixture
def sample_components() -> list[DetectedComponent]:
    """Sample detected components for testing."""
    return [
        DetectedComponent(
            name="django",
            version="4.2.11",
            version_type=VersionType.EXACT,
            version_constraint="==4.2.11",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
            component_type=ComponentType.FRAMEWORK,
        ),
        DetectedComponent(
            name="requests",
            version="2.31.0",
            version_type=VersionType.EXACT,
            version_constraint="==2.31.0",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
            component_type=ComponentType.LIBRARY,
        ),
        DetectedComponent(
            name="flask",
            version="3.0.0",
            version_type=VersionType.EXACT,
            version_constraint="==3.0.0",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
            component_type=ComponentType.FRAMEWORK,
        ),
        DetectedComponent(
            name="numpy",
            version=None,
            version_type=VersionType.UNKNOWN,
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
            component_type=ComponentType.LIBRARY,
        ),
        DetectedComponent(
            name="pydantic",
            version=None,
            version_type=VersionType.RANGE,
            version_constraint=">=2.0,<3.0",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
            component_type=ComponentType.LIBRARY,
        ),
    ]


@pytest.fixture
def sample_vulnerabilities() -> list[VulnerabilityRecord]:
    """Sample vulnerability records for testing."""
    return [
        VulnerabilityRecord(
            cve_id="CVE-2024-1000",
            source_name="CISA KEV",
            vendor_project="Django",
            product="Django",
            vulnerability_name="Django SQL Injection",
            short_description="SQL injection in admin interface.",
        ),
        VulnerabilityRecord(
            cve_id="CVE-2024-4000",
            source_name="CISA KEV",
            vendor_project="Python",
            product="Requests",
            vulnerability_name="Requests SSRF",
            short_description="SSRF vulnerability.",
        ),
        VulnerabilityRecord(
            cve_id="CVE-2024-5000",
            source_name="CISA KEV",
            vendor_project="Pallets",
            product="Flask",
            vulnerability_name="Flask Debug Mode",
            short_description="Information disclosure.",
        ),
        VulnerabilityRecord(
            cve_id="CVE-2024-9999",
            source_name="CISA KEV",
            vendor_project="Cisco",
            product="IOS XE",
            vulnerability_name="Cisco IOS XE Vulnerability",
            short_description="Remote code execution.",
        ),
    ]


@pytest.fixture
def sample_project_dir(tmp_path: Path, fixtures_dir: Path) -> Path:
    """Create a temporary project directory with sample files."""
    # Copy requirements.txt
    req_src = fixtures_dir / "sample_requirements.txt"
    req_dst = tmp_path / "requirements.txt"
    req_dst.write_text(req_src.read_text())

    # Copy pyproject.toml
    pyproject_src = fixtures_dir / "sample_pyproject.toml"
    pyproject_dst = tmp_path / "pyproject.toml"
    pyproject_dst.write_text(pyproject_src.read_text())

    return tmp_path


@pytest.fixture
async def db_session() -> AsyncSession:
    """Create an in-memory SQLite session for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def settings() -> Settings:
    """Test settings with in-memory database."""
    return Settings(
        data_dir=Path(tempfile.mkdtemp()),
    )


@pytest.fixture
async def api_client(db_session: AsyncSession) -> AsyncGenerator:
    """Test client for FastAPI with isolated in-memory DB session."""
    from httpx import ASGITransport, AsyncClient

    from vuln_ai.api.deps import get_db
    from vuln_ai.api.main import app

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()
