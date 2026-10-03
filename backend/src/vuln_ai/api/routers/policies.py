"""Policies REST API router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from vuln_ai.api.deps import get_policy_repo
from vuln_ai.api.schemas.policy import (
    PolicyConditionSchema,
    PolicyCreateRequest,
    PolicyResponse,
    PolicyRuleSchema,
    PolicyThresholdsSchema,
    PolicyUpdateRequest,
    PolicyValidateRequest,
    PolicyValidateResponse,
)
from vuln_ai.db.repositories import PolicyRepository
from vuln_ai.policy.errors import PolicyError, PolicyParseError, PolicyValidationError
from vuln_ai.policy.models import (
    Policy,
    PolicyCondition,
    PolicyRule,
    PolicyThresholds,
)
from vuln_ai.policy.parser import parse_policy_dict, parse_policy_yaml

router = APIRouter(prefix="/policies", tags=["Policies"])


def _to_policy_response(p: Policy) -> PolicyResponse:
    rules = [
        PolicyRuleSchema(
            id=r.id,
            description=r.description,
            when=PolicyConditionSchema(**r.when.model_dump(exclude_unset=True)),
            action=r.action,
            reason=r.reason,
            enabled=r.enabled,
            priority=r.priority,
        )
        for r in p.rules
    ]
    return PolicyResponse(
        id=p.id,
        name=p.name,
        version=p.version,
        description=p.description,
        enabled=p.enabled,
        thresholds=PolicyThresholdsSchema(
            fail_on=p.thresholds.fail_on,
            fail_on_review=p.thresholds.fail_on_review,
        ),
        rules=rules,
        default_action=p.default_action.value
        if hasattr(p.default_action, "value")
        else str(p.default_action),
        metadata=p.metadata,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


@router.get("", summary="List policies", response_model=list[PolicyResponse])
async def list_policies(
    repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
) -> list[PolicyResponse]:
    """List all configured organizational security policies."""
    db_policies = await repo.list_all()
    return [_to_policy_response(repo.to_domain(p)) for p in db_policies]


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create policy",
    response_model=PolicyResponse,
)
async def create_policy(
    body: PolicyCreateRequest,
    repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
) -> PolicyResponse:
    """Create a new declarative security policy."""
    existing = await repo.get_by_name(body.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy with name '{body.name}' already exists",
        )

    rules = [
        PolicyRule(
            id=r.id,
            description=r.description,
            when=PolicyCondition(**r.when.model_dump(exclude_unset=True)),
            action=r.action,
            reason=r.reason,
            enabled=r.enabled,
            priority=r.priority,
        )
        for r in body.rules
    ]
    policy_domain = Policy(
        name=body.name,
        version=body.version,
        description=body.description,
        enabled=body.enabled,
        thresholds=PolicyThresholds(
            fail_on=body.thresholds.fail_on,
            fail_on_review=body.thresholds.fail_on_review,
        ),
        rules=rules,
        default_action=body.default_action,
        metadata=body.metadata,
    )

    db_policy = await repo.create(policy_domain)
    return _to_policy_response(repo.to_domain(db_policy))


@router.get("/{policy_id}", summary="Get policy by ID", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
) -> PolicyResponse:
    """Retrieve details of a specific policy by its ID."""
    db_policy = await repo.get_by_id(policy_id)
    if not db_policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found"
        )
    return _to_policy_response(repo.to_domain(db_policy))


@router.put("/{policy_id}", summary="Update policy", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    body: PolicyUpdateRequest,
    repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
) -> PolicyResponse:
    """Update attributes or rules of an existing policy."""
    db_policy = await repo.get_by_id(policy_id)
    if not db_policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found"
        )

    current = repo.to_domain(db_policy)

    if body.name is not None:
        current.name = body.name
    if body.description is not None:
        current.description = body.description
    if body.enabled is not None:
        current.enabled = body.enabled
    if body.default_action is not None:
        current.default_action = body.default_action
    if body.metadata is not None:
        current.metadata = body.metadata
    if body.thresholds is not None:
        current.thresholds = PolicyThresholds(
            fail_on=body.thresholds.fail_on,
            fail_on_review=body.thresholds.fail_on_review,
        )
    if body.rules is not None:
        current.rules = [
            PolicyRule(
                id=r.id,
                description=r.description,
                when=PolicyCondition(**r.when.model_dump(exclude_unset=True)),
                action=r.action,
                reason=r.reason,
                enabled=r.enabled,
                priority=r.priority,
            )
            for r in body.rules
        ]

    updated = await repo.update(policy_id, current)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found",
        )
    return _to_policy_response(repo.to_domain(updated))


@router.delete("/{policy_id}", summary="Delete policy")
async def delete_policy(
    policy_id: str,
    repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
) -> dict[str, bool]:
    """Delete a security policy by ID."""
    deleted = await repo.delete(policy_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found"
        )
    return {"deleted": True}


@router.post(
    "/validate", summary="Validate policy document", response_model=PolicyValidateResponse
)
async def validate_policy_document(
    body: PolicyValidateRequest,
) -> PolicyValidateResponse:
    """Validate a policy YAML text or JSON schema without persisting it."""
    errors: list[str] = []
    parsed_policy: Policy | None = None

    if body.yaml_content:
        try:
            parsed_policy = parse_policy_yaml(body.yaml_content)
        except (PolicyParseError, PolicyValidationError, PolicyError) as exc:
            errors.append(str(exc))
        except Exception as exc:
            errors.append(f"Parsing error: {exc}")
    elif body.policy:
        try:
            raw_dict = body.policy.model_dump()
            parsed_policy = parse_policy_dict(raw_dict)
        except Exception as exc:
            errors.append(str(exc))
    else:
        errors.append("Must provide either 'yaml_content' or 'policy' JSON payload")

    if errors or parsed_policy is None:
        return PolicyValidateResponse(valid=False, errors=errors, policy=None)

    return PolicyValidateResponse(
        valid=True,
        errors=[],
        policy=_to_policy_response(parsed_policy),
    )
