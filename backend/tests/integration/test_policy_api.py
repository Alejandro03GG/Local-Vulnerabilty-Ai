"""Integration tests for Policy and Suppression REST API endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import VulnerabilityRecord
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository


@pytest.mark.asyncio
async def test_policy_crud_and_validation_api(api_client: AsyncClient):
    """Test policy validation, creation, retrieval, update, and deletion via REST API."""
    # 1. Validate valid YAML policy
    valid_yaml = """
version: "1"
policy:
  name: "test-api-policy"
  description: "Policy created via API"
  thresholds:
    fail_on: ["CRITICAL"]
    fail_on_review: false
  rules:
    - id: "block-crit"
      description: "Block critical"
      when:
        severity: "CRITICAL"
      action: "BLOCK"
"""
    val_res = await api_client.post("/api/v1/policies/validate", json={"yaml_content": valid_yaml})
    assert val_res.status_code == 200
    val_data = val_res.json()
    assert val_data["valid"] is True
    assert val_data["policy"]["name"] == "test-api-policy"

    # 2. Validate invalid policy
    bad_val_res = await api_client.post(
        "/api/v1/policies/validate",
        json={"yaml_content": "invalid: yaml: [["},
    )
    assert bad_val_res.status_code == 200
    bad_data = bad_val_res.json()
    assert bad_data["valid"] is False
    assert len(bad_data["errors"]) > 0

    # 3. Create policy
    create_payload = {
        "name": "org-default-policy",
        "description": "Default organization policy",
        "version": "1.0",
        "thresholds": {"fail_on": ["HIGH", "CRITICAL"], "fail_on_review": True},
        "rules": [
            {
                "id": "block-high",
                "description": "Block high severity",
                "when": {"severity": "HIGH"},
                "action": "BLOCK",
                "reason": "High risk",
            }
        ],
        "default_action": "ALLOW",
    }
    create_res = await api_client.post("/api/v1/policies", json=create_payload)
    assert create_res.status_code == 201
    created_policy = create_res.json()
    policy_id = created_policy["id"]
    assert created_policy["name"] == "org-default-policy"
    assert len(created_policy["rules"]) == 1

    # 4. Duplicate policy creation -> 409
    dup_res = await api_client.post("/api/v1/policies", json=create_payload)
    assert dup_res.status_code == 409

    # 5. List policies
    list_res = await api_client.get("/api/v1/policies")
    assert list_res.status_code == 200
    policies = list_res.json()
    assert any(p["id"] == policy_id for p in policies)

    # 6. Get policy by ID
    get_res = await api_client.get(f"/api/v1/policies/{policy_id}")
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "org-default-policy"

    # 7. Update policy
    update_res = await api_client.put(
        f"/api/v1/policies/{policy_id}",
        json={"description": "Updated description", "enabled": False},
    )
    assert update_res.status_code == 200
    assert update_res.json()["description"] == "Updated description"
    assert update_res.json()["enabled"] is False

    # 8. Delete policy
    del_res = await api_client.delete(f"/api/v1/policies/{policy_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True

    # 9. Verify 404 after deletion
    not_found_res = await api_client.get(f"/api/v1/policies/{policy_id}")
    assert not_found_res.status_code == 404


@pytest.mark.asyncio
async def test_suppression_crud_api(api_client: AsyncClient):
    """Test suppression creation, listing, update, and deletion via REST API."""
    # 1. Create suppression
    payload = {
        "reason": "Documented false positive for testing",
        "owner": "security-team@example.com",
        "reference": "SEC-2026-9999",
        "match_criteria": {
            "vulnerability_id": "CVE-2024-9999",
            "package_name": "requests",
            "ecosystem": "PyPI",
        },
        "enabled": True,
    }
    create_res = await api_client.post("/api/v1/suppressions", json=payload)
    assert create_res.status_code == 201
    created_sup = create_res.json()
    sup_id = created_sup["id"]
    assert created_sup["owner"] == "security-team@example.com"
    assert created_sup["status"] == "ACTIVE"

    # 2. List suppressions
    list_res = await api_client.get("/api/v1/suppressions")
    assert list_res.status_code == 200
    assert any(s["id"] == sup_id for s in list_res.json())

    # 3. Get suppression by ID
    get_res = await api_client.get(f"/api/v1/suppressions/{sup_id}")
    assert get_res.status_code == 200
    assert get_res.json()["reference"] == "SEC-2026-9999"

    # 4. Update suppression
    update_res = await api_client.put(
        f"/api/v1/suppressions/{sup_id}",
        json={"reason": "Updated justification reason"},
    )
    assert update_res.status_code == 200
    assert update_res.json()["reason"] == "Updated justification reason"

    # 5. Delete suppression
    del_res = await api_client.delete(f"/api/v1/suppressions/{sup_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True

    # 6. Verify 404 after deletion
    not_found_res = await api_client.get(f"/api/v1/suppressions/{sup_id}")
    assert not_found_res.status_code == 404


@pytest.mark.asyncio
async def test_scan_policy_evaluation_api(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """Test policy evaluation on scan results via REST API endpoints."""
    # Seed vulnerability
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="cisa_kev")

    await vuln_repo.upsert_vulnerabilities(
        source.id,
        [
            VulnerabilityRecord(
                cve_id="CVE-2024-5555",
                source_name="CISA KEV",
                vendor_project="requests",
                product="requests",
                vulnerability_name="Requests critical bug",
                short_description="Critical bug in requests",
            )
        ],
    )

    # Register project
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "policy-eval-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    # Trigger scan
    scan_res = await api_client.post(
        f"/api/v1/projects/{proj_id}/scans",
        json={"run_ai": False},
    )
    assert scan_res.status_code == 201
    scan_id = scan_res.json()["id"]

    # Evaluate scan with custom inline policy
    custom_policy_yaml = """
version: "1"
policy:
  name: "strict-block-requests"
  thresholds:
    fail_on: ["CRITICAL"]
  rules:
    - id: "block-req"
      description: "Block requests package"
      when:
        package: "requests"
      action: "BLOCK"
      reason: "Blocked by organization rule"
"""
    eval_res = await api_client.post(
        f"/api/v1/scans/{scan_id}/policy/evaluate",
        json={"policy_content": custom_policy_yaml},
    )
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert eval_data["policy_name"] == "strict-block-requests"
    assert eval_data["violations_count"] >= 1
    assert eval_data["ci_exit_code"] == 1

    # Retrieve saved evaluation snapshot
    get_eval_res = await api_client.get(f"/api/v1/scans/{scan_id}/policy")
    assert get_eval_res.status_code == 200
    get_data = get_eval_res.json()
    assert get_data["policy_name"] == "strict-block-requests"
    assert get_data["ci_exit_code"] == 1

    # 404 for unknown scan
    unknown_res = await api_client.get("/api/v1/scans/non-existent-id/policy")
    assert unknown_res.status_code == 404


@pytest.mark.asyncio
async def test_policy_and_suppression_api_edge_branches(api_client: AsyncClient):
    """Test 404 and update edge cases for policy and suppression endpoints."""
    # 1. Update nonexistent policy -> 404
    p_up = await api_client.put("/api/v1/policies/non-existent-id", json={"name": "x"})
    assert p_up.status_code == 404

    # 2. Delete nonexistent policy -> 404
    p_del = await api_client.delete("/api/v1/policies/non-existent-id")
    assert p_del.status_code == 404

    # 3. Update nonexistent suppression -> 404
    s_up = await api_client.put("/api/v1/suppressions/non-existent-id", json={"reason": "x"})
    assert s_up.status_code == 404

    # 4. Delete nonexistent suppression -> 404
    s_del = await api_client.delete("/api/v1/suppressions/non-existent-id")
    assert s_del.status_code == 404

    # 5. Get nonexistent suppression -> 404
    s_get = await api_client.get("/api/v1/suppressions/non-existent-id")
    assert s_get.status_code == 404

    # 6. Create and update suppression with match_criteria
    create_res = await api_client.post(
        "/api/v1/suppressions",
        json={
            "reason": "Test criteria",
            "owner": "dev",
            "reference": "TEST-1",
            "match_criteria": {"package_name": "demo"},
        },
    )
    assert create_res.status_code == 201
    s_id = create_res.json()["id"]

    up_res = await api_client.put(
        f"/api/v1/suppressions/{s_id}",
        json={
            "owner": "new-owner",
            "reference": "REF-2",
            "enabled": False,
            "match_criteria": {
                "vulnerability_id": "CVE-2024-1234",
                "package_name": "demo-updated",
                "ecosystem": "npm",
                "package_version": "1.0.0",
                "finding_id": "fid-1",
                "project_id": "proj-1",
            },
        },
    )
    assert up_res.status_code == 200
    assert up_res.json()["owner"] == "new-owner"
    assert up_res.json()["enabled"] is False


@pytest.mark.asyncio
async def test_policy_validate_dict_and_empty(api_client: AsyncClient):
    """Test policy validation endpoint with dict payload and empty payload."""
    # 1. Dict payload
    res_dict = await api_client.post(
        "/api/v1/policies/validate",
        json={
            "policy": {
                "name": "dict-policy",
                "rules": [{"id": "r1", "when": {"severity": "LOW"}, "action": "ALLOW"}],
            }
        },
    )
    assert res_dict.status_code == 200
    assert res_dict.json()["valid"] is True

    # 2. Empty payload -> errors
    res_empty = await api_client.post("/api/v1/policies/validate", json={})
    assert res_empty.status_code == 200
    assert res_empty.json()["valid"] is False
    assert "Must provide either" in res_empty.json()["errors"][0]


@pytest.mark.asyncio
async def test_policy_update_full_fields(api_client: AsyncClient):
    """Test updating policy name, thresholds, default_action, metadata, and rules."""
    create_res = await api_client.post(
        "/api/v1/policies",
        json={
            "name": "updatable-policy",
            "thresholds": {"fail_on": ["CRITICAL"]},
            "rules": [{"id": "rule-1", "when": {"severity": "HIGH"}, "action": "BLOCK"}],
        },
    )
    assert create_res.status_code == 201
    pol_id = create_res.json()["id"]

    update_res = await api_client.put(
        f"/api/v1/policies/{pol_id}",
        json={
            "name": "updated-name",
            "default_action": "BLOCK",
            "metadata": {"team": "security"},
            "thresholds": {"fail_on": ["HIGH", "CRITICAL"], "fail_on_review": True},
            "rules": [
                {
                    "id": "new-rule",
                    "description": "New rule desc",
                    "when": {"severity": "CRITICAL"},
                    "action": "REQUIRE_REVIEW",
                    "reason": "Needs review",
                    "enabled": True,
                    "priority": 10,
                }
            ],
        },
    )
    assert update_res.status_code == 200
    updated_data = update_res.json()
    assert updated_data["name"] == "updated-name"
    assert updated_data["default_action"] == "BLOCK"
    assert updated_data["thresholds"]["fail_on_review"] is True
    assert len(updated_data["rules"]) == 1
    assert updated_data["rules"][0]["id"] == "new-rule"


@pytest.mark.asyncio
async def test_scan_policy_evaluate_not_found(api_client: AsyncClient):
    """Test evaluate scan policy with non-existent scan returns 404."""
    res = await api_client.post(
        "/api/v1/scans/non-existent-scan/policy/evaluate",
        json={"policy_content": "version: '1'\npolicy:\n  name: 'test'"},
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_scan_policy_evaluate_malformed_yaml(
    api_client: AsyncClient,
    sample_project_dir: Path,
):
    """Test evaluate scan policy with malformed yaml returns 422."""
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "malformed-eval-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]
    scan_res = await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    scan_id = scan_res.json()["id"]

    res = await api_client.post(
        f"/api/v1/scans/{scan_id}/policy/evaluate",
        json={"policy_content": "invalid: yaml: [["},
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_scan_policy_evaluate_statuses(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """Test evaluate scan policy returning REQUIRES_REVIEW and ALLOWED statuses."""
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="cisa_kev")

    await vuln_repo.upsert_vulnerabilities(
        source.id,
        [
            VulnerabilityRecord(
                cve_id="CVE-2024-5555",
                source_name="CISA KEV",
                vendor_project="requests",
                product="requests",
                vulnerability_name="Requests critical bug",
                short_description="Critical bug in requests",
            )
        ],
    )

    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "status-eval-proj", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]
    scan_res = await api_client.post(f"/api/v1/projects/{proj_id}/scans", json={"run_ai": False})
    scan_id = scan_res.json()["id"]

    # 1. Action: REQUIRE_REVIEW
    review_yaml = """
version: "1"
policy:
  name: "review-policy"
  rules:
    - id: "review-all"
      when:
        ecosystem: "pypi"
      action: "REQUIRE_REVIEW"
"""
    res_rev = await api_client.post(
        f"/api/v1/scans/{scan_id}/policy/evaluate",
        json={"policy_content": review_yaml},
    )
    assert res_rev.status_code == 200
    assert res_rev.json()["status"] == "REQUIRES_REVIEW"

    # Get cached snapshot
    snap_rev = await api_client.get(f"/api/v1/scans/{scan_id}/policy")
    assert snap_rev.status_code == 200
    assert snap_rev.json()["status"] == "REQUIRES_REVIEW"

    # 2. Action: ALLOW
    allow_yaml = """
version: "1"
policy:
  name: "allow-policy"
  rules: []
  default_action: "ALLOW"
"""
    res_allow = await api_client.post(
        f"/api/v1/scans/{scan_id}/policy/evaluate",
        json={"policy_content": allow_yaml},
    )
    assert res_allow.status_code == 200
    assert res_allow.json()["status"] == "ALLOWED"
