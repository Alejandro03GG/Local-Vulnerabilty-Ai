"""High-level service coordinating policy evaluation, suppressions, and persistence."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import MatchResult
from vuln_ai.db.repositories import (
    MatchRepository,
    PolicyRepository,
    ProjectRepository,
    ScanRepository,
    SuppressionRepository,
)
from vuln_ai.policy.clock import Clock, SystemClock
from vuln_ai.policy.engine import PolicyEngine
from vuln_ai.policy.errors import PolicyError, PolicyValidationError
from vuln_ai.policy.models import (
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyThresholds,
)
from vuln_ai.policy.parser import load_policy_file, parse_policy_yaml


def get_default_policy() -> Policy:
    """Return default baseline policy for scans without custom configuration."""
    return Policy(
        name="default-baseline-policy",
        description="Standard baseline policy blocking critical findings and requiring review for conflicts",
        thresholds=PolicyThresholds(
            fail_on=["HIGH", "CRITICAL"],
            fail_on_review=False,
        ),
        rules=[
            PolicyRule(
                id="block-cisa-kev",
                description="Block any vulnerability confirmed in CISA KEV",
                when=PolicyCondition(has_kev_evidence=True),
                action=PolicyAction.BLOCK,
                reason="Vulnerability is actively exploited in the wild (CISA KEV)",
                priority=10,
            ),
            PolicyRule(
                id="require-review-on-conflict",
                description="Require human review when advisory sources disagree",
                when=PolicyCondition(conflict_detected=True),
                action=PolicyAction.REQUIRE_REVIEW,
                reason="Advisory sources present unresolved discrepancies",
                priority=20,
            ),
        ],
        default_action=PolicyAction.ALLOW,
    )


class PolicyService:
    """Orchestrates policy lifecycle, evaluation against scans, and persistence."""

    def __init__(self, session: AsyncSession, clock: Clock | None = None) -> None:
        self._session = session
        self._clock = clock or SystemClock()
        self.policy_repo = PolicyRepository(session)
        self.suppression_repo = SuppressionRepository(session)
        self.scan_repo = ScanRepository(session)
        self.project_repo = ProjectRepository(session)
        self.match_repo = MatchRepository(session)

    async def resolve_policy(
        self,
        project_path: str | Path | None = None,
        policy_id: str | None = None,
        policy_content: str | None = None,
    ) -> Policy:
        """Resolve policy to apply: direct content > policy_id > project .vuln-ai.yaml > default."""
        # 1. Direct YAML content
        if policy_content and policy_content.strip():
            return parse_policy_yaml(policy_content)

        # 2. Database policy ID
        if policy_id:
            db_policy = await self.policy_repo.get_by_id(policy_id)
            if db_policy:
                return self.policy_repo.to_domain(db_policy)
            raise PolicyValidationError(f"Policy with ID '{policy_id}' not found")

        # 3. Project root .vuln-ai.yaml / .vuln-ai.yml
        if project_path:
            p_dir = Path(project_path)
            for fname in (".vuln-ai.yaml", ".vuln-ai.yml"):
                p_file = p_dir / fname
                if p_file.exists() and p_file.is_file():
                    return load_policy_file(p_file)

        # 4. Default baseline policy
        return get_default_policy()

    async def evaluate_scan(
        self,
        scan_id: str,
        policy_id: str | None = None,
        policy_content: str | None = None,
    ) -> PolicyEvaluationResult:
        """Evaluate all findings in a scan against the chosen or discovered policy."""
        scan = await self.scan_repo.get_by_id(scan_id)
        if not scan:
            raise PolicyError(f"Scan '{scan_id}' not found")

        project = await self.project_repo.get_by_id(scan.project_id)
        project_path = project.path if project else None

        policy = await self.resolve_policy(
            project_path=project_path,
            policy_id=policy_id,
            policy_content=policy_content,
        )

        # Fetch suppressions
        db_sups = await self.suppression_repo.list_all(project_id=scan.project_id)
        suppressions = [self.suppression_repo.to_domain(s) for s in db_sups]

        # Fetch matches
        db_matches = await self.match_repo.get_by_scan(scan_id)
        domain_matches: list[MatchResult] = [self.match_repo.to_domain(m) for m in db_matches]

        engine = PolicyEngine(
            policy=policy,
            suppressions=suppressions,
            clock=self._clock,
        )
        result = engine.evaluate(domain_matches, project_id=scan.project_id)

        # Persist snapshot
        await self.policy_repo.save_evaluation(result, scan_id=scan_id)

        return result
