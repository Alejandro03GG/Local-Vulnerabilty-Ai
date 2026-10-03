"""Scans router."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from vuln_ai.api.deps import get_policy_repo, get_policy_service, get_scan_service
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.components import ComponentResponse, DependencyGraphResponse
from vuln_ai.api.schemas.policy import PolicyEvaluateRequest, PolicyEvaluationResponse
from vuln_ai.api.schemas.scans import ScanCreateRequest, ScanResponse
from vuln_ai.api.services.scan_service import ScanService
from vuln_ai.db.repositories import PolicyRepository
from vuln_ai.policy.errors import PolicyError
from vuln_ai.policy.service import PolicyService

router = APIRouter(tags=["Scans"])


@router.post(
    "/projects/{project_id}/scans",
    status_code=status.HTTP_201_CREATED,
    summary="Trigger a project scan",
)
async def create_scan(
    project_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
    body: ScanCreateRequest | None = None,
) -> ScanResponse:
    """Execute a vulnerability scan on a project using the core ScanEngine."""
    run_ai = body.run_ai if body is not None else True
    return await service.run_scan(project_id=project_id, run_ai=run_ai)


@router.get("/scans", summary="List scans")
async def list_scans(
    service: Annotated[ScanService, Depends(get_scan_service)],
    project_id: Annotated[str | None, Query(description="Optional project ID filter")] = None,
    page: Annotated[int, Query(ge=1, description="Page number (1-based)")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[ScanResponse]:
    """Retrieve a paginated list of scans with optional project filtering."""
    return await service.list_scans(project_id=project_id, page=page, page_size=page_size)


@router.get("/scans/{scan_id}", summary="Get scan details")
async def get_scan(
    scan_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> ScanResponse:
    """Retrieve details and findings of a specific scan by ID."""
    return await service.get_scan(scan_id)


@router.get(
    "/scans/{scan_id}/dependencies",
    summary="Get scan resolved dependencies",
    response_model=list[ComponentResponse],
)
async def get_scan_dependencies(
    scan_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> list[ComponentResponse]:
    """Retrieve resolved dependencies for the project analyzed in this scan."""
    return await service.get_scan_dependencies(scan_id)


@router.get(
    "/scans/{scan_id}/dependencies/graph",
    summary="Get scan dependency graph topology",
    response_model=DependencyGraphResponse,
)
async def get_scan_dependency_graph(
    scan_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> DependencyGraphResponse:
    """Retrieve the dependency graph topology with edges and lockfile provenance."""
    return await service.get_scan_dependency_graph(scan_id)


@router.get(
    "/scans/{scan_id}/export/sarif",
    summary="Export scan results in SARIF 2.1.0 format",
)
async def export_scan_sarif(
    scan_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> Response:
    """Export scan findings to OASIS SARIF 2.1.0 format."""
    content, media_type, filename = await service.export_scan(scan_id, "sarif")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/scans/{scan_id}/export/cyclonedx",
    summary="Export scan results in CycloneDX 1.5 JSON SBOM format",
)
async def export_scan_cyclonedx(
    scan_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> Response:
    """Export resolved components, dependencies, and findings to CycloneDX 1.5 SBOM."""
    content, media_type, filename = await service.export_scan(scan_id, "cyclonedx")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/scans/{scan_id}/export/spdx",
    summary="Export scan results in SPDX 2.3 JSON SBOM format",
)
async def export_scan_spdx(
    scan_id: str,
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> Response:
    """Export software bill of materials in SPDX 2.3 format."""
    content, media_type, filename = await service.export_scan(scan_id, "spdx")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/scans/{scan_id}/policy/evaluate",
    summary="Evaluate scan findings against policy",
    response_model=PolicyEvaluationResponse,
)
async def evaluate_scan_policy(
    scan_id: str,
    policy_service: Annotated[PolicyService, Depends(get_policy_service)],
    body: PolicyEvaluateRequest | None = None,
) -> PolicyEvaluationResponse:
    """Evaluate findings of an existing scan against a specified or discovered policy."""
    policy_id = body.policy_id if body else None
    policy_content = body.policy_content if body else None
    try:
        result = await policy_service.evaluate_scan(
            scan_id=scan_id,
            policy_id=policy_id,
            policy_content=policy_content,
        )
    except PolicyError as err:
        if "not found" in str(err).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    data = result.model_dump()
    if "status" not in data or not data.get("status"):
        if result.has_violations:
            data["status"] = "VIOLATION"
        elif result.requires_review_count > 0:
            data["status"] = "REQUIRES_REVIEW"
        elif result.suppressed_count > 0:
            data["status"] = "SUPPRESSED"
        else:
            data["status"] = "ALLOWED"
    return PolicyEvaluationResponse.model_validate(data)


@router.get(
    "/scans/{scan_id}/policy",
    summary="Get scan policy evaluation snapshot",
    response_model=PolicyEvaluationResponse,
)
async def get_scan_policy(
    scan_id: str,
    policy_repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
) -> PolicyEvaluationResponse:
    """Retrieve saved policy evaluation snapshot for a scan."""
    eval_db = await policy_repo.get_evaluation_by_scan_id(scan_id)
    if not eval_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No policy evaluation found for scan '{scan_id}'",
        )
    data = json.loads(eval_db.evaluations_json)
    if "status" not in data or not data.get("status"):
        if data.get("has_violations"):
            data["status"] = "VIOLATION"
        elif data.get("requires_review_count", 0) > 0:
            data["status"] = "REQUIRES_REVIEW"
        elif data.get("suppressed_count", 0) > 0:
            data["status"] = "SUPPRESSED"
        else:
            data["status"] = "ALLOWED"
    return PolicyEvaluationResponse.model_validate(data)
