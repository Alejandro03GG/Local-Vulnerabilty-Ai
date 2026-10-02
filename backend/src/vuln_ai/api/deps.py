"""FastAPI dependency injection providers."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.ollama_provider import OllamaProvider
from vuln_ai.ai.ollama_systemone_provider import OllamaSystemOneProvider
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.api.services import (
    ComponentService,
    MatchService,
    ProjectService,
    ScanService,
    SourceService,
    VulnerabilityService,
)
from vuln_ai.config import Settings, get_settings
from vuln_ai.db.database import get_session
from vuln_ai.db.repositories import (
    AIAnalysisRepository,
    ComponentRepository,
    DecisionRepository,
    MatchRepository,
    ProjectRepository,
    RiskAssessmentRepository,
    ScanRepository,
    SourceRepository,
    VulnerabilityRepository,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.scanners.python_scanner import PythonScanner
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.cisa_kev import CISAKEVSource
from vuln_ai.sources.registry import SourceRegistry


def get_app_settings() -> Settings:
    """Return application settings."""
    return get_settings()


async def get_db(
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session."""
    async for session in get_session(settings):
        yield session


# Repositories
def get_project_repo(session: Annotated[AsyncSession, Depends(get_db)]) -> ProjectRepository:
    return ProjectRepository(session)


def get_component_repo(session: Annotated[AsyncSession, Depends(get_db)]) -> ComponentRepository:
    return ComponentRepository(session)


def get_source_repo(session: Annotated[AsyncSession, Depends(get_db)]) -> SourceRepository:
    return SourceRepository(session)


def get_vulnerability_repo(
    session: Annotated[AsyncSession, Depends(get_db)],
) -> VulnerabilityRepository:
    return VulnerabilityRepository(session)


def get_scan_repo(session: Annotated[AsyncSession, Depends(get_db)]) -> ScanRepository:
    return ScanRepository(session)


def get_match_repo(session: Annotated[AsyncSession, Depends(get_db)]) -> MatchRepository:
    return MatchRepository(session)


def get_ai_analyses_repo(
    session: Annotated[AsyncSession, Depends(get_db)],
) -> AIAnalysisRepository:
    return AIAnalysisRepository(session)


def get_decisions_repo(session: Annotated[AsyncSession, Depends(get_db)]) -> DecisionRepository:
    return DecisionRepository(session)


def get_risk_assessments_repo(
    session: Annotated[AsyncSession, Depends(get_db)],
) -> RiskAssessmentRepository:
    return RiskAssessmentRepository(session)


# Registries & Engines
def get_scanner_registry() -> ScannerRegistry:
    registry = ScannerRegistry()
    registry.register(PythonScanner())
    return registry


def get_source_registry(
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SourceRegistry:
    registry = SourceRegistry()
    registry.register(CISAKEVSource(settings=settings.kev))
    return registry


def get_ai_registry(settings: Annotated[Settings, Depends(get_app_settings)]) -> AIRegistry:
    registry = AIRegistry()
    if settings.ai.enabled:
        if settings.ai.ollama.enabled:
            registry.register_ai_provider(OllamaProvider(settings=settings.ai.ollama))
        if settings.ai.decision.enabled:
            registry.register_decision_provider(
                OllamaSystemOneProvider(settings=settings.ai.decision)
            )
    return registry


def get_risk_engine() -> DeterministicRiskEngine:
    return DeterministicRiskEngine()


def get_matcher() -> VulnerabilityMatcher:
    return VulnerabilityMatcher()


# Services
def get_project_service(
    project_repo: Annotated[ProjectRepository, Depends(get_project_repo)],
) -> ProjectService:
    return ProjectService(project_repo)


def get_component_service(
    component_repo: Annotated[ComponentRepository, Depends(get_component_repo)],
    project_repo: Annotated[ProjectRepository, Depends(get_project_repo)],
) -> ComponentService:
    return ComponentService(component_repo, project_repo)


def get_vulnerability_service(
    vuln_repo: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repo)],
) -> VulnerabilityService:
    return VulnerabilityService(vuln_repo)


def get_source_service(
    source_repo: Annotated[SourceRepository, Depends(get_source_repo)],
    vuln_repo: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repo)],
    source_registry: Annotated[SourceRegistry, Depends(get_source_registry)],
) -> SourceService:
    return SourceService(source_repo, vuln_repo, source_registry)


def get_match_service(
    match_repo: Annotated[MatchRepository, Depends(get_match_repo)],
    vuln_repo: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repo)],
    ai_analyses_repo: Annotated[AIAnalysisRepository, Depends(get_ai_analyses_repo)],
    decisions_repo: Annotated[DecisionRepository, Depends(get_decisions_repo)],
    risk_assessments_repo: Annotated[RiskAssessmentRepository, Depends(get_risk_assessments_repo)],
    ai_registry: Annotated[AIRegistry, Depends(get_ai_registry)],
    risk_engine: Annotated[DeterministicRiskEngine, Depends(get_risk_engine)],
) -> MatchService:
    return MatchService(
        match_repo=match_repo,
        vuln_repo=vuln_repo,
        ai_analyses_repo=ai_analyses_repo,
        decisions_repo=decisions_repo,
        risk_assessments_repo=risk_assessments_repo,
        ai_registry=ai_registry,
        risk_engine=risk_engine,
    )


def get_scan_service(
    session: Annotated[AsyncSession, Depends(get_db)],
    scan_repo: Annotated[ScanRepository, Depends(get_scan_repo)],
    project_repo: Annotated[ProjectRepository, Depends(get_project_repo)],
    match_repo: Annotated[MatchRepository, Depends(get_match_repo)],
    risk_assessments_repo: Annotated[RiskAssessmentRepository, Depends(get_risk_assessments_repo)],
    scanner_registry: Annotated[ScannerRegistry, Depends(get_scanner_registry)],
    source_registry: Annotated[SourceRegistry, Depends(get_source_registry)],
    matcher: Annotated[VulnerabilityMatcher, Depends(get_matcher)],
    ai_registry: Annotated[AIRegistry, Depends(get_ai_registry)],
    risk_engine: Annotated[DeterministicRiskEngine, Depends(get_risk_engine)],
    match_service: Annotated[MatchService, Depends(get_match_service)],
) -> ScanService:
    return ScanService(
        session=session,
        scan_repo=scan_repo,
        project_repo=project_repo,
        match_repo=match_repo,
        risk_assessments_repo=risk_assessments_repo,
        scanner_registry=scanner_registry,
        source_registry=source_registry,
        matcher=matcher,
        ai_registry=ai_registry,
        risk_engine=risk_engine,
        match_service=match_service,
    )
