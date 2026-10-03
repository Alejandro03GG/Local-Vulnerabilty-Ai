# Declarative Policy & Security Enforcement Engine

## Overview

The **Policy Engine** in `Local Vulnerability AI` provides deterministic, auditable, and automated security gating for CI/CD pipelines and developer workstations.

### Core Architectural Axiom
- **`Finding = Hecho Técnico`**: A detected vulnerability or applicability state is immutable technical ground truth. It is never deleted, hidden, or altered by policies or suppressions.
- **`Policy = Decisión Organizacional`**: Policies define corporate appetite for security risk, threshold rules, and required governance workflows.
- **`Suppression = Excepción Documentada`**: A time-bounded, attributed exception granting immunity from CI failure.
- **`CI Violation = Resultado de Política`**: Pipeline failure (`exit code 1`) is solely determined by policy evaluation, never by arbitrary heuristics or generative AI hallucinations.

---

## Policy File Schema (`.vuln-ai.yaml`)

Policies can be authored as local YAML files placed at repository roots (`.vuln-ai.yaml`), supplied explicitly via `--policy <FILE>`, or registered in the centralized database via the REST API.

```yaml
version: "1"
policy:
  name: "enterprise-baseline-policy"
  description: "Organizational zero-trust baseline policy"
  
  thresholds:
    fail_on:
      - "CRITICAL"
      - "HIGH"
    fail_on_review: true

  rules:
    - id: "block-active-exploits"
      description: "Fail CI immediately on any known exploited vulnerability"
      when:
        has_kev_evidence: true
      action: "BLOCK"
      reason: "CISA KEV active exploitation confirmed"
      priority: 10

    - id: "block-high-cvss-direct"
      description: "Block direct dependencies with CVSS >= 8.5"
      when:
        dependency_type: "DIRECT"
        cvss_score: 8.5
        cvss_comparator: ">="
      action: "BLOCK"
      reason: "High CVSS direct dependency exceeds risk appetite"
      priority: 20

    - id: "review-transitive-high"
      description: "Require human security review for transitive vulnerabilities"
      when:
        dependency_type: "TRANSITIVE"
        severity: "HIGH"
      action: "REQUIRE_REVIEW"
      reason: "Transitive high risk requires architectural verification"
      priority: 50

    - id: "accept-dev-test-risk"
      description: "Accept risk for dev dependencies with medium severity"
      when:
        scope: "DEV"
        severity: "MEDIUM"
      action: "ACCEPT_RISK"
      reason: "Development scope does not reach production runtime"
      priority: 80

  default_action: "ALLOW"
```

---

## Condition Filters Supported

Every rule specifies a `when` condition block. All specified filters must match (`AND` logic):

| Condition Field | Types | Description |
|---|---|---|
| `severity` | `str \| list[str]` | Vulnerability advisory severity (e.g. `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `risk_level` | `str \| list[str]` | Deterministic risk level calculated by the risk engine |
| `applicability` | `str \| list[str]` | Canonical status (`AFFECTED`, `LIKELY_AFFECTED`, `SUSPECTED`, `REQUIRES_REVIEW`, `LIKELY_NOT_AFFECTED`, `NOT_AFFECTED`) |
| `dependency_type` | `str \| list[str]` | `DIRECT` or `TRANSITIVE` dependency location in graph |
| `scope` | `str \| list[str]` | Dependency scope: `RUNTIME`, `DEV`, `OPTIONAL`, `PEER` |
| `ecosystem` | `str \| list[str]` | Package ecosystem (`pypi`, `npm`, `cargo`) |
| `package_name` | `str \| list[str]` | Package name (exact or normalized) |
| `package_version` | `str` | Exact package version string |
| `vulnerability_id` | `str \| list[str]` | Canonical vulnerability ID (e.g. `CVE-2024-1234`, `GHSA-...`) |
| `source` | `str \| list[str]` | Advisory source (`CISA KEV`, `NVD`, `OSV`) |
| `has_kev_evidence` | `bool` | Whether the advisory is documented in the CISA KEV catalog |
| `cvss_score` | `float` | Base CVSS numeric score (0.0 to 10.0) |
| `cvss_comparator` | `str` | `>=` (default), `>`, `==`, `<=`, `<` |
| `requires_human_review` | `bool` | Whether finding has discrepancies or uncertainty requiring review |
| `conflict_detected` | `bool` | Whether multi-source discrepancies were identified |
| `conflict_type` | `str \| list[str]` | Type of discrepancy (`VERSION_OVERLAP`, `SEVERITY_DISCREPANCY`, etc.) |

---

## Rule Action Hierarchy & Precedence

When multiple rules match a single security finding, the engine resolves actions using strict deterministic hierarchy:

```
BLOCK > REQUIRE_REVIEW > ACCEPT_RISK > ALLOW
```

If two matching rules have different priorities, the lower integer priority evaluates first.

### Global Evaluation Order
1. **Active Suppression**: If an active, non-expired suppression matches the finding, the finding is marked `SUPPRESSED` and exempted from failing CI.
2. **Expired Suppression**: If a suppression has expired (`now >= expires_at`), a warning is emitted and the finding **proceeds to normal rule and threshold evaluation**. It does NOT receive exemption.
3. **Policy Rules Hierarchy**: Matching rules are evaluated; the most restrictive action wins.
4. **Global Security Thresholds**: `fail_on` severities (e.g., `['CRITICAL', 'HIGH']`) and `fail_on_review` flags evaluate.
5. **Default Action Fallback**: If no rules or thresholds matched, the policy `default_action` applies.

---

## Safety & Security Constraints
- **1MB File Limit**: Policy files larger than 1,048,576 bytes are rejected.
- **Forbid Arbitrary Code Execution**: Parsed strictly via standard YAML loaders without Python code execution.
- **No Extra Fields**: Unknown configuration keys trigger immediate `PolicyValidationError`.
- **Duplicate ID Enforcement**: Duplicate rule IDs within the same document are rejected.
- **Strict Canonical Terminology**: Non-canonical statuses (such as `VULNERABLE`) are rejected by schema validators.
