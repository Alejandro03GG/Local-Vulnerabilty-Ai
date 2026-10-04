"""Container and Image Scanning REST API router."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.api.deps import (
    get_ai_registry,
    get_app_settings,
    get_container_repo,
    get_db,
    get_match_service,
    get_policy_repo,
    get_scanner_registry,
    get_source_registry,
)
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.container import (
    ContainerComponentResponse,
    ContainerImageResponse,
    ContainerLayerResponse,
    ContainerScanRequest,
    DockerfileScanRequest,
    DockerfileScanResponse,
)
from vuln_ai.api.schemas.matches import MatchResponse
from vuln_ai.api.schemas.policy import PolicyEvaluationResponse
from vuln_ai.api.services.match_service import MatchService
from vuln_ai.config import Settings
from vuln_ai.container.dockerfile import (
    parse_dockerfile_content,
    parse_dockerfile_file,
)
from vuln_ai.container.models import ContainerImage
from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import ScanStatus
from vuln_ai.db.repositories import (
    ContainerRepository,
    PolicyRepository,
    ProjectRepository,
    ScanRepository,
    SuppressionRepository,
)
from vuln_ai.matching.conflict import ConflictResolver
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.policy.clock import SystemClock
from vuln_ai.policy.engine import PolicyEngine
from vuln_ai.policy.service import get_default_policy
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.registry import SourceRegistry

router = APIRouter(tags=["Container Images"])


def _map_image_response(db_image: Any) -> ContainerImageResponse:
    """Helper to convert ContainerImageDB into ContainerImageResponse."""
    layers = [
        ContainerLayerResponse(
            id=layer.id,
            layer_index=layer.layer_index,
            digest=layer.digest,
            size_bytes=layer.size_bytes,
            media_type=layer.media_type,
            command=layer.command,
        )
        for layer in getattr(db_image, "layers", [])
    ]
    try:
        metadata = json.loads(db_image.metadata_json or "{}")
    except (TypeError, json.JSONDecodeError):
        metadata = {}
    dockerfile_ast = metadata.get("dockerfile_ast")
    return ContainerImageResponse(
        id=db_image.id,
        scan_id=db_image.scan_id,
        reference=db_image.reference,
        digest=db_image.digest,
        architecture=db_image.architecture,
        os=db_image.os,
        os_family=db_image.os_family,
        os_version=db_image.os_version,
        os_codename=db_image.os_codename,
        source_type=db_image.source_type,
        source_path=db_image.source_path,
        created_at=db_image.created_at,
        layer_count=len(layers),
        layers=layers,
        metadata=metadata if isinstance(metadata, dict) else {},
        dockerfile_ast=dockerfile_ast if isinstance(dockerfile_ast, dict) else None,
    )


@router.post(
    "/images/scan",
    response_model=ContainerImageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Scan a container image archive",
)
async def scan_image(
    payload: ContainerScanRequest,
    session: Annotated[AsyncSession, Depends(get_db)],
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
    policy_repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
    scanner_reg: Annotated[ScannerRegistry, Depends(get_scanner_registry)],
    source_reg: Annotated[SourceRegistry, Depends(get_source_registry)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> ContainerImageResponse:
    """Execute static container image inspection on a local tarball without container execution."""
    archive_path = Path(payload.archive_path)
    if not archive_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Image archive not found at path: {payload.archive_path}",
        )

    ai_reg = None if payload.no_ai else get_ai_registry(settings)

    scan_engine = ScanEngine(
        session=session,
        scanner_registry=scanner_reg,
        source_registry=source_reg,
        matcher=VulnerabilityMatcher(),
        conflict_resolver=ConflictResolver(),
        ai_registry=ai_reg,
        risk_engine=DeterministicRiskEngine(),
        ai_enabled=not payload.no_ai,
        decision_enabled=not payload.no_ai,
    )

    try:
        summary, container_image, _os_pkgs, _graph = await scan_engine.scan_container_image(
            archive_path=archive_path,
            reference=payload.reference,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Container inspection failed: {exc}",
        ) from exc

    if summary.scan_status == ScanStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {summary.error}",
        )

    # Policy evaluation
    selected_policy = None
    if payload.policy_id:
        db_pol = await policy_repo.get_by_id(payload.policy_id)
        if not db_pol:
            db_pol = await policy_repo.get_by_name(payload.policy_id)
        if db_pol:
            selected_policy = policy_repo.to_domain(db_pol)
    if not selected_policy:
        selected_policy = get_default_policy()

    sup_repo = SuppressionRepository(session)
    sup_dbs = await sup_repo.list_all(enabled_only=True)
    suppressions = [sup_repo.to_domain(s) for s in sup_dbs]

    policy_engine = PolicyEngine(
        policy=selected_policy,
        suppressions=suppressions,
        clock=SystemClock(),
    )
    policy_eval = policy_engine.evaluate_scan(
        scan_result=summary,
        scan_id=summary.scan_id,
    )
    if summary.scan_id:
        await policy_repo.save_evaluation(
            eval_result=policy_eval,
            scan_id=summary.scan_id,
        )

    db_image = await container_repo.get_image_by_id(container_image.id)
    if not db_image:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Failed to retrieve persisted container image",
        )

    return _map_image_response(db_image)


@router.get(
    "/images",
    response_model=PaginatedResponse[ContainerImageResponse],
    summary="List scanned container images",
)
async def list_images(
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[ContainerImageResponse]:
    """Retrieve paginated list of scanned container images."""
    offset = (page - 1) * page_size
    total = await container_repo.count_images()
    items_db = await container_repo.list_images(limit=page_size, offset=offset)

    items = [_map_image_response(item) for item in items_db]
    return PaginatedResponse[ContainerImageResponse](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/images/{image_id}",
    response_model=ContainerImageResponse,
    summary="Get container image details",
)
async def get_image(
    image_id: str,
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
) -> ContainerImageResponse:
    """Retrieve metadata, layers, and configuration for a specific container image."""
    db_image = await container_repo.get_image_by_id(image_id)
    if not db_image:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container image not found: {image_id}",
        )
    return _map_image_response(db_image)


@router.get(
    "/images/{image_id}/layers",
    response_model=list[ContainerLayerResponse],
    summary="Get ordered layers of a container image",
)
async def get_image_layers(
    image_id: str,
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
) -> list[ContainerLayerResponse]:
    """Retrieve the ordered filesystem layers of a container image."""
    db_image = await container_repo.get_image_by_id(image_id)
    if not db_image:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container image not found: {image_id}",
        )

    return [
        ContainerLayerResponse(
            id=layer.id,
            layer_index=layer.layer_index,
            digest=layer.digest,
            size_bytes=layer.size_bytes,
            media_type=layer.media_type,
            command=layer.command,
        )
        for layer in db_image.layers
    ]


@router.get(
    "/images/{image_id}/components",
    response_model=list[ContainerComponentResponse],
    summary="Get components detected in a container image",
)
async def get_image_components(
    image_id: str,
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
) -> list[ContainerComponentResponse]:
    """Retrieve all OS and application components detected in a container image."""
    db_image = await container_repo.get_image_by_id(image_id)
    if not db_image:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container image not found: {image_id}",
        )

    # Build layer id to digest map
    layer_map = {layer.id: layer.digest for layer in db_image.layers}

    response_items: list[ContainerComponentResponse] = []
    for ic in db_image.image_components:
        comp = ic.component
        ldigest = layer_map.get(ic.layer_id) if ic.layer_id else None
        response_items.append(
            ContainerComponentResponse(
                id=comp.id,
                name=comp.name,
                version=comp.version,
                ecosystem=comp.ecosystem,
                component_type=comp.component_type,
                layer_digest=ldigest,
                container_path=ic.container_path,
                stage=ic.stage,
                package_manager=ic.package_manager,
                is_direct=comp.is_direct,
            )
        )

    return response_items


@router.get(
    "/images/{image_id}/vulnerabilities",
    response_model=list[MatchResponse],
    summary="Get matched vulnerabilities for a container image",
)
async def get_image_vulnerabilities(
    image_id: str,
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
    match_service: Annotated[MatchService, Depends(get_match_service)],
) -> list[MatchResponse]:
    """Retrieve vulnerability matches associated with the container image scan."""
    db_image = await container_repo.get_image_by_id(image_id)
    if not db_image:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container image not found: {image_id}",
        )

    res = await match_service.list_matches(page=1, page_size=1000, scan_id=db_image.scan_id)
    return res.items


@router.get(
    "/images/{image_id}/dependency-graph",
    summary="Get container dependency graph",
)
async def get_image_dependency_graph(
    image_id: str,
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    """Retrieve the dependency graph for a container image."""
    db_image = await container_repo.get_image_by_id(image_id)
    if not db_image:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container image not found: {image_id}",
        )

    scan_repo = ScanRepository(session)
    scan = await scan_repo.get_by_id(db_image.scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record not found for image: {image_id}",
        )

    # Query components and edges
    from vuln_ai.db.repositories import ComponentRepository

    comp_repo = ComponentRepository(session)
    edges = await comp_repo.get_dependency_edges(scan.project_id)
    components = await comp_repo.get_by_project(scan.project_id)

    nodes = [
        {
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "is_direct": c.is_direct,
            "dependency_type": c.dependency_type,
            "scope": c.scope,
            "source_file": c.source_file,
        }
        for c in components
    ]
    edge_list = [
        {
            "parent_name": e.parent_name,
            "child_name": e.child_name,
            "scope": e.scope,
            "requirement": e.requirement,
        }
        for e in edges
    ]

    return {
        "image_id": image_id,
        "scan_id": db_image.scan_id,
        "nodes": nodes,
        "edges": edge_list,
    }


@router.get(
    "/images/{image_id}/policy",
    response_model=PolicyEvaluationResponse,
    summary="Get policy evaluation for a container image",
)
async def get_image_policy(
    image_id: str,
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
    policy_repo: Annotated[PolicyRepository, Depends(get_policy_repo)],
) -> PolicyEvaluationResponse:
    """Retrieve the policy evaluation snapshot for a container image scan."""
    db_image = await container_repo.get_image_by_id(image_id)
    if not db_image:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container image not found: {image_id}",
        )

    eval_db = await policy_repo.get_evaluation_by_scan_id(db_image.scan_id)
    if not eval_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No policy evaluation record found for image {image_id}",
        )

    eval_dict = json.loads(eval_db.evaluations_json)
    return PolicyEvaluationResponse.model_validate(eval_dict)


@router.post(
    "/container/dockerfile/scan",
    response_model=DockerfileScanResponse,
    summary="Analyze a Dockerfile statically",
)
async def scan_dockerfile_endpoint(
    payload: DockerfileScanRequest,
    session: Annotated[AsyncSession, Depends(get_db)],
    container_repo: Annotated[ContainerRepository, Depends(get_container_repo)],
) -> DockerfileScanResponse:
    """Statically parse and analyze a Dockerfile without execution.

    When ``persist`` is true (default), stores the AST on a ContainerImage row
    with ``source_type=dockerfile`` so it appears in the Images UI (H9).
    """
    if payload.content is not None:
        doc = parse_dockerfile_content(payload.content, source_file="Dockerfile")
        source_path = ""
        reference = "Dockerfile"
    elif payload.path is not None:
        doc = parse_dockerfile_file(payload.path)
        source_path = str(Path(payload.path).resolve())
        reference = Path(payload.path).name
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either 'content' or 'path' for Dockerfile analysis",
        )

    image_id: str | None = None
    scan_id: str | None = None
    if payload.persist:
        try:
            proj_repo = ProjectRepository(session)
            scan_repo = ScanRepository(session)
            project_path = source_path or f"dockerfile://{reference}"
            project, _created = await proj_repo.get_or_create(
                name=f"dockerfile:{reference}",
                path=project_path,
                description="Dockerfile static AST scan",
            )
            db_scan = await scan_repo.create(project.id)
            scan_id = db_scan.id
            ast_payload = {
                "dockerfile_ast": {
                    "source_file": doc.source_file,
                    "stages": [s.model_dump(mode="json") for s in doc.stages],
                    "base_images": [b.model_dump(mode="json") for b in doc.base_images],
                    "package_installations": doc.package_installations,
                    "copied_files": doc.copied_files,
                    "dependency_manifests": doc.dependency_manifests,
                }
            }
            domain_image = ContainerImage(
                id=str(uuid.uuid4()),
                reference=reference,
                source_type="dockerfile",
                source_path=source_path,
                metadata=ast_payload,
            )
            db_image = await container_repo.create_image(
                scan_id=scan_id, image=domain_image, commit=True
            )
            image_id = db_image.id
            await scan_repo.complete(
                scan_id,
                components_found=0,
                vulnerabilities_found=0,
            )
        except Exception:
            # Persist is best-effort: static AST response must still succeed (H9).
            # Rollback so the request session is usable for the response lifecycle.
            await session.rollback()
            image_id = None
            scan_id = None

    return DockerfileScanResponse(
        source_file=doc.source_file,
        stages=[s.model_dump() for s in doc.stages],
        base_images=[b.model_dump() for b in doc.base_images],
        package_installations=doc.package_installations,
        copied_files=doc.copied_files,
        dependency_manifests=doc.dependency_manifests,
        image_id=image_id,
        scan_id=scan_id,
    )
