# Multi-Source Conflict Resolution

When multiple vulnerability intelligence feeds (OSV, NVD, CISA KEV) report information on the same software component and CVE, discrepancies naturally arise. The **ConflictResolver** (`vuln_ai.matching.conflict`) detects, categorizes, and audits these discrepancies deterministically.

---

## 1. Conflict Resolution Flow

```text
Source A (e.g. OSV)      Source B (e.g. NVD)      Source C (e.g. CISA KEV)
       │                         │                         │
       ▼                         ▼                         ▼
MatchEvidence A           MatchEvidence B           MatchEvidence C
(Status: AFFECTED)       (Status: NOT_AFFECTED)     (Status: DETECTED)
       │                         │                         │
       └─────────────────────────┼─────────────────────────┘
                                 ▼
                          ConflictResolver
                                 │
                   Discrepancy Detected: YES
             Category: Applicability Divergence (High)
                                 │
                                 ▼
                     ApplicabilityResolution
                   Status: REQUIRES_REVIEW
                  Conflict Logged: SourceConflict
                                 │
                                 ▼
                     Deterministic Risk Engine
                 requires_human_review = True
              rule_id = SOURCE_APPLICABILITY_CONFLICT
```

---

## 2. Multi-Source Applicability Truth Table

The resolver applies a conservative security policy. When authoritative sources provide contradictory information about whether an installed version is impacted, the system avoids picking winners arbitrarily and flags the item for human triage:

| Source Evidence Signals | Resolved Applicability | Conflict Generated? | Human Review Required? | Risk Engine Rule Triggered |
| :--- | :--- | :--- | :--- | :--- |
| `AFFECTED` + `AFFECTED` | `LIKELY_AFFECTED` | No | No | `APPLICABILITY_LIKELY_AFFECTED` |
| `AFFECTED` + `NOT_AFFECTED` | `REQUIRES_REVIEW` | **Yes** (High) | **Yes** (`True`) | `SOURCE_APPLICABILITY_CONFLICT` |
| `AFFECTED` + `UNKNOWN` | `LIKELY_AFFECTED` | No | No | `APPLICABILITY_LIKELY_AFFECTED` |
| `NOT_AFFECTED` + `UNKNOWN` | `LIKELY_NOT_AFFECTED`| No | No | — |
| `DETECTED` + `NOT_AFFECTED` | `REQUIRES_REVIEW` | **Yes** (High) | **Yes** (`True`) | `SOURCE_APPLICABILITY_CONFLICT` |
| `DETECTED` + `AFFECTED` | `LIKELY_AFFECTED` | No | No | `APPLICABILITY_LIKELY_AFFECTED`, `KEV_CONFIRMED` |
| `DETECTED` only | `DETECTED` | No | If KEV: `True` | `KEV_CONFIRMED` |
| `UNKNOWN` only | `UNKNOWN` | No | No | — |

---

## 3. Discrepancy Categories

Beyond overall applicability verdicts, the `ConflictResolver` checks for secondary discrepancies:

### 3.1 Range Boundary Conflicts (`range`)
- **Condition**: Both sources agree a component is affected, but specify divergent fixed versions (e.g., OSV states fixed in `2.14.1` while NVD states fixed in `2.15.0`).
- **Severity**: `Medium`.
- **Audit**: Logged in `SourceConflict` with raw ranges from each source for analyst inspection.

### 3.2 Severity Metric Conflicts (`severity`)
- **Condition**: Sources declare incompatible CVSS qualitative ratings (e.g., OSV rates `MODERATE` while NVD publishes `CRITICAL` 9.8).
- **Severity**: `Low`.
- **Audit**: Recorded in `SourceConflict`; the Risk Engine deterministically selects the highest corroborated base score.

---

## 4. Audit Persistence & API Representation

When a conflict occurs:
1. **Database Persistence**: Stored in the `source_conflicts` table linked via foreign key to `matches.id`.
2. **API Serialization**: Exposed as a list of `SourceConflictResponse` objects under `MatchResponse.conflicts`.
3. **Frontend Presentation**: Rendered in the Security Operations console via `ConflictPanel`, presenting side-by-side source values, conflict severity, and justification rationale.
