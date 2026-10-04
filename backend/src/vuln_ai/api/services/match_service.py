"""Service for vulnerability matches and AI re-analysis."""

from __future__ import annotations

import contextlib
import json
import logging

from vuln_ai.ai.models import AnalysisContext
from vuln_ai.ai.questions import get_default_decision_questions
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.api.errors import NotFoundError
from vuln_ai.api.schemas.ai import AIAnalysisResponse, DecisionResultResponse
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.components import ComponentResponse
from vuln_ai.api.schemas.matches import (
    MatchEvidenceResponse,
    MatchResponse,
    SourceConflictResponse,
)
from vuln_ai.api.schemas.risk import RiskAssessmentResponse
from vuln_ai.api.schemas.vulnerabilities import VulnerabilityResponse
from vuln_ai.core.models import (
    Applicability,
    ComponentType,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    VersionType,
)
from vuln_ai.db.models import MatchDB
from vuln_ai.db.repositories import (
    AIAnalysisRepository,
    DecisionRepository,
    MatchRepository,
    RiskAssessmentRepository,
    VulnerabilityRepository,
)
from vuln_ai.risk.engine import DeterministicRiskEngine

logger = logging.getLogger(__name__)


class MatchService:
    """Business logic for querying and re-evaluating matches."""

    def __init__(
        self,
        match_repo: MatchRepository,
        vuln_repo: VulnerabilityRepository,
        ai_analyses_repo: AIAnalysisRepository,
        decisions_repo: DecisionRepository,
        risk_assessments_repo: RiskAssessmentRepository,
        ai_registry: AIRegistry | None = None,
        risk_engine: DeterministicRiskEngine | None = None,
    ) -> None:
        self._match_repo = match_repo
        self._vuln_repo = vuln_repo
        self._ai_analyses = ai_analyses_repo
        self._decisions = decisions_repo
        self._risk_assessments = risk_assessments_repo
        self._ai_registry = ai_registry
        self._risk_engine = risk_engine or DeterministicRiskEngine()

    @staticmethod
    def _to_match_response(db_match: MatchDB) -> MatchResponse:
        evidence = []
        if db_match.evidence:
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                evidence = json.loads(db_match.evidence)

        comp_resp = None
        if db_match.component:
            path_list: list[str] = []
            if getattr(db_match.component, "dependency_path", None):
                with contextlib.suppress(Exception):
                    path_list = json.loads(db_match.component.dependency_path)

            comp_resp = ComponentResponse(
                id=db_match.component.id,
                project_id=db_match.component.project_id,
                name=db_match.component.name,
                version=db_match.component.version,
                version_type=db_match.component.version_type,
                version_constraint=db_match.component.version_constraint,
                source_file=db_match.component.source_file,
                ecosystem=db_match.component.ecosystem,
                component_type=db_match.component.component_type,
                is_direct=getattr(db_match.component, "is_direct", True),
                dependency_type=getattr(db_match.component, "dependency_type", "direct"),
                scope=getattr(db_match.component, "scope", "runtime"),
                manifest_source=getattr(db_match.component, "manifest_source", None),
                lockfile_source=getattr(db_match.component, "lockfile_source", None),
                parent_name=getattr(db_match.component, "parent_name", None),
                dependency_path=path_list,
                detected_at=db_match.component.detected_at,
            )

        vuln_resp = None
        if db_match.vulnerability:
            cwes = []
            if db_match.vulnerability.cwes:
                with contextlib.suppress(json.JSONDecodeError, TypeError):
                    cwes = json.loads(db_match.vulnerability.cwes)
            canonical = (db_match.vulnerability.canonical_id or "").strip()
            if not canonical:
                canonical = (db_match.vulnerability.cve_id or "").strip() or db_match.vulnerability.id
            vuln_resp = VulnerabilityResponse(
                id=db_match.vulnerability.id,
                canonical_id=canonical,
                cve_id=db_match.vulnerability.cve_id,
                source_id=db_match.vulnerability.source_id,
                vendor_project=db_match.vulnerability.vendor_project,
                product=db_match.vulnerability.product,
                vulnerability_name=db_match.vulnerability.vulnerability_name,
                short_description=db_match.vulnerability.short_description,
                required_action=db_match.vulnerability.required_action,
                date_added=db_match.vulnerability.date_added,
                due_date=db_match.vulnerability.due_date,
                known_ransomware_use=db_match.vulnerability.known_ransomware_use,
                cwes=cwes,
                notes=db_match.vulnerability.notes,
                synced_at=db_match.vulnerability.synced_at,
            )

        ai_resp = None
        if db_match.ai_analysis:
            ai_domain = AIAnalysisRepository.to_domain(db_match.ai_analysis)
            ai_resp = AIAnalysisResponse(
                provider=ai_domain.provider,
                model=ai_domain.model,
                explanation=ai_domain.explanation,
                evidence=ai_domain.evidence,
                contextual_findings=ai_domain.contextual_findings,
                requires_human_review=ai_domain.requires_human_review,
                duration_seconds=ai_domain.analysis_duration_seconds,
                tokens_used=ai_domain.tokens_used,
                analyzed_at=ai_domain.analyzed_at,
            )

        dec_resp = None
        if db_match.decision_result:
            dec_domain = DecisionRepository.to_domain(db_match.decision_result)
            dec_resp = DecisionResultResponse(
                provider=dec_domain.provider,
                model=dec_domain.model,
                responses=dec_domain.responses,
                decision_probabilities=dec_domain.decision_probabilities,
                applicability_probability=dec_domain.applicability_probability,
                urgency_score=dec_domain.urgency_score,
                latency_seconds=dec_domain.latency_seconds,
                timestamp=dec_domain.timestamp,
            )

        risk_resp = None
        if db_match.risk_assessment:
            risk_domain = RiskAssessmentRepository.to_domain(db_match.risk_assessment)
            risk_resp = RiskAssessmentResponse(
                status=risk_domain.status.value,
                risk_level=risk_domain.risk_level.value,
                certainty=risk_domain.certainty,
                rationale=risk_domain.rationale,
                recommended_action=risk_domain.recommended_action,
                requires_human_review=risk_domain.requires_human_review,
                rule_ids=risk_domain.rule_ids,
                assessed_at=risk_domain.assessed_at,
            )

        structured_evidences = []
        if getattr(db_match, "structured_evidences", None):
            for ev in db_match.structured_evidences:
                structured_evidences.append(
                    MatchEvidenceResponse(
                        source_name=ev.source_name,
                        identifier=ev.identifier,
                        package_name=ev.package_name,
                        ecosystem=ev.ecosystem,
                        installed_version=ev.installed_version,
                        affected_range=ev.affected_range,
                        fixed_version=ev.fixed_version,
                        status=ev.status,
                        evidence_type=ev.evidence_type,
                        details=ev.details,
                    )
                )

        conflicts = []
        if getattr(db_match, "conflicts", None):
            for c in db_match.conflicts:
                sources = []
                identifiers = []
                values = {}
                if c.sources:
                    with contextlib.suppress(json.JSONDecodeError, TypeError):
                        sources = (
                            json.loads(c.sources) if isinstance(c.sources, str) else c.sources
                        )
                if c.identifiers:
                    with contextlib.suppress(json.JSONDecodeError, TypeError):
                        identifiers = (
                            json.loads(c.identifiers)
                            if isinstance(c.identifiers, str)
                            else c.identifiers
                        )
                if c.values:
                    with contextlib.suppress(json.JSONDecodeError, TypeError):
                        values = json.loads(c.values) if isinstance(c.values, str) else c.values
                conflicts.append(
                    SourceConflictResponse(
                        conflict_type=c.conflict_type,
                        severity=c.severity,
                        field=c.field,
                        sources=sources,
                        identifiers=identifiers,
                        values=values,
                        resolution=c.resolution,
                        rationale=c.rationale,
                    )
                )

        return MatchResponse(
            id=db_match.id,
            scan_id=db_match.scan_id,
            component_id=db_match.component_id,
            vulnerability_id=db_match.vulnerability_id,
            match_type=db_match.match_type,
            match_confidence=db_match.match_confidence,
            applicability=db_match.applicability,
            evidence=evidence,
            matched_at=db_match.matched_at,
            component=comp_resp,
            vulnerability=vuln_resp,
            ai_analysis=ai_resp,
            decision_result=dec_resp,
            risk_assessment=risk_resp,
            structured_evidences=structured_evidences,
            conflicts=conflicts,
        )

    async def list_matches(
        self,
        page: int = 1,
        page_size: int = 20,
        scan_id: str | None = None,
        applicability: str | None = None,
    ) -> PaginatedResponse[MatchResponse]:
        """List matches paginated with optional filtering."""
        items, total = await self._match_repo.list_paginated(
            page=page,
            page_size=page_size,
            scan_id=scan_id,
            applicability=applicability,
        )
        return PaginatedResponse(
            items=[self._to_match_response(m) for m in items],
            page=page,
            page_size=page_size,
            total=total,
        )

    async def get_match(self, match_id: str) -> MatchResponse:
        """Get full details of a match."""
        db_match = await self._match_repo.get_by_id(match_id)
        if db_match is None:
            raise NotFoundError(
                message=f"Match with ID '{match_id}' not found",
                code="MATCH_NOT_FOUND",
            )
        return self._to_match_response(db_match)

    async def get_match_analysis(self, match_id: str) -> AIAnalysisResponse:
        """Get the persisted AI analysis for a match."""
        # Ensure match exists
        db_match = await self._match_repo.get_by_id(match_id)
        if db_match is None:
            raise NotFoundError(
                message=f"Match with ID '{match_id}' not found",
                code="MATCH_NOT_FOUND",
            )

        analysis = await self._ai_analyses.get_by_match_id(match_id)
        if analysis is None:
            raise NotFoundError(
                message=f"No AI analysis found for match '{match_id}'",
                code="ANALYSIS_NOT_FOUND",
            )
        domain = AIAnalysisRepository.to_domain(analysis)
        return AIAnalysisResponse(
            provider=domain.provider,
            model=domain.model,
            explanation=domain.explanation,
            evidence=domain.evidence,
            contextual_findings=domain.contextual_findings,
            requires_human_review=domain.requires_human_review,
            duration_seconds=domain.analysis_duration_seconds,
            tokens_used=domain.tokens_used,
            analyzed_at=domain.analyzed_at,
        )

    async def get_match_decision(self, match_id: str) -> DecisionResultResponse:
        """Get the persisted SystemOne decision for a match."""
        db_match = await self._match_repo.get_by_id(match_id)
        if db_match is None:
            raise NotFoundError(
                message=f"Match with ID '{match_id}' not found",
                code="MATCH_NOT_FOUND",
            )

        decision = await self._decisions.get_by_match_id(match_id)
        if decision is None:
            raise NotFoundError(
                message=f"No decision result found for match '{match_id}'",
                code="DECISION_NOT_FOUND",
            )
        domain = DecisionRepository.to_domain(decision)
        return DecisionResultResponse(
            provider=domain.provider,
            model=domain.model,
            responses=domain.responses,
            decision_probabilities=domain.decision_probabilities,
            applicability_probability=domain.applicability_probability,
            urgency_score=domain.urgency_score,
            latency_seconds=domain.latency_seconds,
            timestamp=domain.timestamp,
        )

    async def get_match_risk(self, match_id: str) -> RiskAssessmentResponse:
        """Get the deterministic risk assessment for a match."""
        db_match = await self._match_repo.get_by_id(match_id)
        if db_match is None:
            raise NotFoundError(
                message=f"Match with ID '{match_id}' not found",
                code="MATCH_NOT_FOUND",
            )

        assessment = await self._risk_assessments.get_by_match_id(match_id)
        if assessment is None:
            raise NotFoundError(
                message=f"No risk assessment found for match '{match_id}'",
                code="RISK_ASSESSMENT_NOT_FOUND",
            )
        domain = RiskAssessmentRepository.to_domain(assessment)
        return RiskAssessmentResponse(
            status=domain.status.value,
            risk_level=domain.risk_level.value,
            certainty=domain.certainty,
            rationale=domain.rationale,
            recommended_action=domain.recommended_action,
            requires_human_review=domain.requires_human_review,
            rule_ids=domain.rule_ids,
            assessed_at=domain.assessed_at,
        )

    async def reanalyze_match(self, match_id: str) -> MatchResponse:
        """Re-run AI analysis, SystemOne decision, and Risk Engine for an existing match."""
        db_match = await self._match_repo.get_by_id(match_id)
        if db_match is None:
            raise NotFoundError(
                message=f"Match with ID '{match_id}' not found",
                code="MATCH_NOT_FOUND",
            )

        db_comp = db_match.component
        db_vuln = db_match.vulnerability

        evidence = []
        if db_match.evidence:
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                evidence = json.loads(db_match.evidence)

        comp_domain = DetectedComponent(
            name=db_comp.name,
            version=db_comp.version,
            version_type=VersionType(db_comp.version_type),
            version_constraint=db_comp.version_constraint,
            source_file=db_comp.source_file,
            ecosystem=Ecosystem(db_comp.ecosystem),
            component_type=ComponentType(db_comp.component_type),
        )

        vuln_domain = self._vuln_repo.to_domain(db_vuln)
        match_result = MatchResult(
            component=comp_domain,
            vulnerability=vuln_domain,
            match_type=MatchType(db_match.match_type),
            match_confidence=db_match.match_confidence,
            applicability=Applicability(db_match.applicability),
            evidence=evidence,
        )

        context = AnalysisContext.from_match(match_result)
        questions = get_default_decision_questions()

        ai_provider = self._ai_registry.get_ai_provider() if self._ai_registry else None
        decision_provider = (
            self._ai_registry.get_decision_provider() if self._ai_registry else None
        )

        ai_available = await ai_provider.is_available() if ai_provider else False
        decision_available = await decision_provider.is_available() if decision_provider else False

        ai_analysis = None
        if ai_available and ai_provider:
            try:
                ai_analysis = await ai_provider.analyze(context)
            except Exception as exc:
                logger.warning("Re-analysis AI analysis failed for match %s: %s", match_id, exc)

        decision = None
        if decision_available and decision_provider:
            try:
                decision = await decision_provider.decide(context, questions)
            except Exception as exc:
                logger.warning("Re-analysis decision failed for match %s: %s", match_id, exc)

        assessment = self._risk_engine.assess(match_result, ai_analysis, decision)

        # Persist results
        if ai_analysis:
            await self._ai_analyses.save_analysis(match_id, ai_analysis)
        if decision:
            await self._decisions.save_decision(match_id, decision)
        await self._risk_assessments.save_assessment(match_id, assessment)

        # Reload updated match with eager loaded relations
        self._match_repo._session.expire_all()
        reloaded = await self._match_repo.get_by_id(match_id)
        assert reloaded is not None
        return self._to_match_response(reloaded)
