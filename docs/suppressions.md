# Vulnerability Suppressions & Audit Lifecycles

## Overview

Security suppressions in `Local Vulnerability AI` represent explicit, documented, and time-bounded organizational decisions to accept or temporarily exempt a vulnerability finding from causing CI/CD pipeline failures.

### Key Guarantees
1. **Findings are Never Deleted**: Suppressed findings continue to be detected, reported in SBOMs, exported to SARIF/CycloneDX/SPDX, and logged in audit trails.
2. **Deterministic Time-Bound Evaluation**: Suppressions feature mandatory or optional `expires_at` ISO 8601 timestamps. When `clock.now() >= expires_at`, the suppression transitions to `EXPIRED`.
3. **Expired Suppressions Do Not Exempt**: An expired suppression will never silence a vulnerability in CI/CD. The finding will immediately cause pipeline failure if it meets policy thresholds.
4. **Attribution & Auditability**: Every suppression records an owner, business/technical justification reason, and tracking reference (e.g. Jira ticket, PR, or internal security RFC).

---

## Suppression Lifecycle States

```
                ┌──────────────────────────────────────┐
                │               CREATED                │
                └──────────────────┬───────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │                ACTIVE                │
                │  (Immunity from CI policy violation) │
                └───────┬──────────────────────┬───────┘
                        │                      │
           expires_at <= now()         enabled == false
                        │                      │
                        ▼                      ▼
           ┌──────────────────────┐ ┌──────────────────────┐
           │       EXPIRED        │ │       DISABLED       │
           │ (Build Failure if    │ │ (Suppression ignored)│
           │  finding violates)   │ └──────────────────────┘
           └──────────────────────┘
```

- **`ACTIVE`**: Current timestamp is strictly before `expires_at` (or `expires_at` is null/permanent) and `enabled == true`. Finding is marked `SUPPRESSED` with `exit code 0`.
- **`EXPIRED`**: Current timestamp has reached or passed `expires_at`. The engine emits an audit warning and evaluates the finding as unsuppressed.
- **`DISABLED`**: Explicitly set to `enabled: false`. The suppression is completely ignored during evaluation.

---

## Inline Policy Suppressions vs Database Suppressions

Suppressions can be defined in two locations:

### 1. In Repository Policy Files (`.vuln-ai.yaml`)
Declared directly within the `suppressions` array of the policy file:

```yaml
version: "1"
policy:
  name: "repo-policy"
  suppressions:
    - id: "sup-temp-auth"
      reason: "Compensating control: AWS WAF regex filter blocks exploit payload"
      owner: "security-team@example.com"
      reference: "SEC-2026-1049"
      expires_at: "2026-12-31T23:59:59Z"
      match_criteria:
        vulnerability_id: "CVE-2024-34064"
        package_name: "jinja2"
        ecosystem: "pypi"
```

### 2. Centralized Database Suppressions
Created and managed via the REST API (`POST /api/v1/suppressions`) or CLI. Database suppressions can be scoped globally or to a specific `project_id`.

---

## Suppression Matching Criteria

The `match_criteria` object specifies which findings the suppression applies to:
- `vulnerability_id`: Exact canonical ID or alias (e.g. `CVE-2023-32681`).
- `package_name`: Package name (normalized according to ecosystem conventions).
- `ecosystem`: `pypi`, `npm`, `cargo`.
- `package_version`: Specific package version string.
- `finding_id`: Exact finding string identifier (`{ecosystem}:{package}:{version}:{vuln_id}`).
- `project_id`: Scopes suppression to a specific project.

---

## Export Format Representation

- **SARIF 2.1.0**: Represented using native SARIF `suppressions` objects:
  ```json
  "suppressions": [
    {
      "kind": "external",
      "status": "accepted",
      "justification": "Compensating control active",
      "properties": {
        "suppressionId": "sup-temp-auth",
        "owner": "security-team@example.com",
        "expiresAt": "2026-12-31T23:59:59Z"
      }
    }
  ]
  ```
- **CycloneDX 1.5**: Included in the vulnerability `properties`:
  ```json
  {
    "name": "vuln_ai:policy_status",
    "value": "SUPPRESSED"
  },
  {
    "name": "vuln_ai:suppression_reason",
    "value": "Compensating control active"
  }
  ```
- **SPDX 2.3**: Finding remains documented in annotations and package vulnerability relations while preserving strict `NOASSERTION` licensing.
