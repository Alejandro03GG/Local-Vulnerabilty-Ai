"""Suppressions REST API router."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from vuln_ai.api.deps import get_suppression_repo
from vuln_ai.api.schemas.policy import (
    SuppressionCreateRequest,
    SuppressionMatchCriteriaSchema,
    SuppressionResponse,
    SuppressionUpdateRequest,
)
from vuln_ai.db.repositories import SuppressionRepository
from vuln_ai.policy.clock import SystemClock
from vuln_ai.policy.models import Suppression, SuppressionMatchCriteria

router = APIRouter(prefix="/suppressions", tags=["Suppressions"])


def _to_suppression_response(s: Suppression) -> SuppressionResponse:
    clock = SystemClock()
    st = s.status(clock)
    return SuppressionResponse(
        id=s.id,
        project_id=s.project_id,
        match_criteria=SuppressionMatchCriteriaSchema(
            vulnerability_id=s.match_criteria.vulnerability_id,
            package_name=s.match_criteria.package_name,
            ecosystem=s.match_criteria.ecosystem,
            package_version=s.match_criteria.package_version,
            finding_id=s.match_criteria.finding_id,
            project_id=s.match_criteria.project_id,
        ),
        reason=s.reason,
        owner=s.owner,
        reference=s.reference,
        expires_at=s.expires_at,
        enabled=s.enabled,
        status=st.value,
        created_by=s.created_by,
        created_at=s.created_at,
        updated_at=s.updated_at,
    )


@router.get("", summary="List suppressions", response_model=list[SuppressionResponse])
async def list_suppressions(
    repo: Annotated[SuppressionRepository, Depends(get_suppression_repo)],
    project_id: Annotated[str | None, Query(description="Filter by project ID")] = None,
) -> list[SuppressionResponse]:
    """Retrieve all auditable vulnerability suppressions."""
    db_sups = await repo.list_all(project_id=project_id)
    return [_to_suppression_response(repo.to_domain(s)) for s in db_sups]


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create suppression",
    response_model=SuppressionResponse,
)
async def create_suppression(
    body: SuppressionCreateRequest,
    repo: Annotated[SuppressionRepository, Depends(get_suppression_repo)],
) -> SuppressionResponse:
    """Register an auditable exception/suppression for a vulnerability or package."""
    domain_sup = Suppression(
        project_id=body.project_id,
        match_criteria=SuppressionMatchCriteria(
            vulnerability_id=body.match_criteria.vulnerability_id,
            package_name=body.match_criteria.package_name,
            ecosystem=body.match_criteria.ecosystem,
            package_version=body.match_criteria.package_version,
            finding_id=body.match_criteria.finding_id,
            project_id=body.match_criteria.project_id,
        ),
        reason=body.reason,
        owner=body.owner,
        reference=body.reference,
        expires_at=body.expires_at,
        enabled=body.enabled,
    )
    db_sup = await repo.create(domain_sup)
    return _to_suppression_response(repo.to_domain(db_sup))


@router.get(
    "/{suppression_id}", summary="Get suppression by ID", response_model=SuppressionResponse
)
async def get_suppression(
    suppression_id: str,
    repo: Annotated[SuppressionRepository, Depends(get_suppression_repo)],
) -> SuppressionResponse:
    """Retrieve an individual suppression by ID."""
    db_sup = await repo.get_by_id(suppression_id)
    if not db_sup:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suppression '{suppression_id}' not found",
        )
    return _to_suppression_response(repo.to_domain(db_sup))


@router.put("/{suppression_id}", summary="Update suppression", response_model=SuppressionResponse)
async def update_suppression(
    suppression_id: str,
    body: SuppressionUpdateRequest,
    repo: Annotated[SuppressionRepository, Depends(get_suppression_repo)],
) -> SuppressionResponse:
    """Update reason, owner, expiration, or target criteria of an existing suppression."""
    db_sup = await repo.get_by_id(suppression_id)
    if not db_sup:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suppression '{suppression_id}' not found",
        )

    updates: dict[str, Any] = {}
    if body.reason is not None:
        updates["reason"] = body.reason
    if body.owner is not None:
        updates["owner"] = body.owner
    if body.reference is not None:
        updates["reference"] = body.reference
    if body.expires_at is not None:
        updates["expires_at"] = body.expires_at
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.match_criteria is not None:
        updates["vulnerability_id"] = body.match_criteria.vulnerability_id
        updates["package_name"] = body.match_criteria.package_name
        updates["ecosystem"] = body.match_criteria.ecosystem
        updates["package_version"] = body.match_criteria.package_version
        updates["finding_id"] = body.match_criteria.finding_id
        if body.match_criteria.project_id is not None:
            updates["project_id"] = body.match_criteria.project_id

    updated = await repo.update(suppression_id, updates)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suppression '{suppression_id}' not found",
        )
    return _to_suppression_response(repo.to_domain(updated))


@router.delete("/{suppression_id}", summary="Delete suppression")
async def delete_suppression(
    suppression_id: str,
    repo: Annotated[SuppressionRepository, Depends(get_suppression_repo)],
) -> dict[str, bool]:
    """Delete a suppression exception by ID."""
    deleted = await repo.delete(suppression_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suppression '{suppression_id}' not found",
        )
    return {"deleted": True}
