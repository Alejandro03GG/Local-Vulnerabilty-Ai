# Local AI & Decision Support Architecture

**Local Vulnerability AI** incorporates local machine learning and Large Language Model (LLM) providers to assist security analysts with contextual interpretations and fast probabilistic triage.

---

## 1. Architectural Philosophy: AI is Not the Final Authority

A core tenet of the platform is that generative AI and probabilistic classifiers must **never** hold unconstrained authority over vulnerability determinations:

```text
Deterministic Matcher (Authoritative)
         ↓
Conflict Resolver (Authoritative)
         ↓
Consolidated Applicability (Authoritative)
         ├─────────────────────────────────────────┐
         ▼                                         ▼
AI Contextual Narrative                   SystemOne Decision
(Ollama / llama3.2)                     (Fast Probabilistic)
Context & Advice Only                   Probabilities & Urgency Only
         │                                         │
         └───────────────────┬─────────────────────┘
                             ▼
               Deterministic Risk Engine (Final Authority)
               Rule-based Evaluation & Audit Trail
```

---

## 2. Layer 1: Contextual AI Analysis (`vuln_ai.ai.ollama_provider`)

### Purpose
Generates human-readable, context-aware security narratives evaluating how an advisory relates to the target project environment.

### Capabilities
- **Technical Explanation**: Translates dense CVE/CWE advisories into plain English.
- **Contextual Findings**: Assesses potential exposure vectors based on component type (library, runtime, tool).
- **Remediation Advice**: Recommends upgrading to patched versions or applying mitigations.

### Privacy Guarantee
- The target project's **source code is never transmitted** to the model.
- Only non-sensitive metadata is sent:
  ```json
  {
    "component_name": "urllib3",
    "installed_version": "2.31.0",
    "ecosystem": "pypi",
    "vulnerability_id": "CVE-2024-37891",
    "advisory_summary": "Proxy-Authorization header leak"
  }
  ```

---

## 3. Layer 2: SystemOne Decision Support (`vuln_ai.ai.ollama_systemone_provider`)

### Purpose
Provides structured probabilistic signals for rapid triaging before full manual review.

### Metrics Produced
- `applicability_probability`: Model confidence estimate (0.0 to 1.0) that the component is affected.
- `urgency_score`: Recommended remediation priority (0.0 to 1.0).
- `decision_probabilities`: Distribution across potential outcomes.

### Non-Authoritative Guardrail
The Deterministic Risk Engine consumes SystemOne probabilities strictly as supplementary input. Even if SystemOne predicts 0.99 applicability, if the deterministic version matcher proves the installed version is outside the affected range, the final state remains `LIKELY_NOT_AFFECTED`.

---

## 4. Offline & Failure Resilience

All AI capabilities run locally via [Ollama](https://ollama.ai/) (`http://localhost:11434`). The system is architected to be completely resilient when AI services are offline:

### What Happens When Ollama is Down or Times Out
1. **Zero Scan Interruption**: The scan does **not** fail.
2. **Transaction Integrity**: Matched vulnerabilities, evidence, and conflict records are persisted cleanly without database rollbacks.
3. **Deterministic Fallback**: The Deterministic Risk Engine evaluates all available rule-based signals.
4. **Audit Flag**: The rule `AI_UNAVAILABLE_FALLBACK` is appended to `RiskAssessment.rule_ids`.
5. **Safety Trigger**: `requires_human_review` is set to `True` to ensure an analyst reviews un-evaluated findings.
6. **Frontend State**: The UI displays an informative alert ("AI analysis unavailable; deterministic evaluation preserved") rather than an error banner.
