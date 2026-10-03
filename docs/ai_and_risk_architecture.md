# AI Layer, Decision Models & Deterministic Risk Engine

This document details the architecture, design principles, and operation of **Phase 2: AI Layer + Ollama SystemOne + Risk Engine** in `local-vulnerability-ai`.

---

## 1. Architectural Philosophy

Local Vulnerability AI adheres to a strict pipeline:

```text
Scanner (Dependency manifests)
   ↓ (DetectedComponent)
Multi-Source Catalog (CISA KEV, OSV, NVD)
   ↓ (Canonical catalog + Affected version ranges)
Version-aware Matcher
   ↓ (Ecosystem + Package + Range evaluation)
MatchResult + Structured MatchEvidence
   ↓
Conflict Resolver (Deterministic disambiguation: complementary vs conflicting)
   ↓ (Consolidated applicability)
AI Contextual Analysis (Ollama LLM contextual narrative)
   ↓
Ollama SystemOne Decision (Probabilistic evaluation: noul, choice, score)
   ↓
Deterministic Risk Engine (Explicit audit rules)
   ↓
RiskAssessment & Structured Findings
```

### Core Principles

1. **Version-aware Matcher as Authority**: The matcher is the sole authority on version range applicability (`LIKELY_AFFECTED` vs `LIKELY_NOT_AFFECTED`). AI and SystemOne do NOT evaluate or override version math.
2. **AI Contextual Analysis is Non-Decisive**: The LLM provides contextual explanations and nuance; it is never the authority declaring final risk. Source code is never transmitted to LLMs.
3. **SystemOne is Probabilistic Decision Support**: SystemOne probabilities indicate model evaluation over predefined options; they do not overwrite deterministic version evidence.
4. **Deterministic Risk Engine Produces Final Finding**: The Risk Engine uses explicit, auditable rules to synthesize applicability, source evidence, CVSS, KEV presence, and AI/SystemOne signals.
5. **Local-First Privacy & Safe Fallback**: All operations run locally. When AI/SystemOne is offline, the pipeline falls back gracefully to conservative deterministic assessments without failing.

---

## 2. Core Differences: AIAnalysis vs. DecisionResult vs. RiskAssessment

| Dimension | `AIAnalysis` | `DecisionResult` | `RiskAssessment` |
| :--- | :--- | :--- | :--- |
| **Layer** | LLM (`POST /api/chat`) | SystemOne (`POST /v1/systemone`) | Deterministic Rule Engine |
| **Provider** | `OllamaProvider` (e.g. `llama3.2`) | `OllamaSystemOneProvider` (`tev1:4b`, `nimble`, `tev1:0.8b`) | `DeterministicRiskEngine` |
| **Output Type** | Structured Narrative & Nuance | Probabilities & Numerical Prioritization | Categorical Status & Actionable Rationale |
| **Key Fields** | `explanation`, `evidence`, `contextual_findings`, `requires_human_review` | `decision_probabilities`, `applicability_probability`, `urgency_score` | `status`, `risk_level`, `certainty`, `rationale`, `rule_ids` |
| **Role in Pipeline** | Contextual enrichment | Structured probabilistic signals | **Final authoritative finding** |

---

## 3. Ollama Installation & Setup

### Prerequisites

Install [Ollama](https://ollama.com/) locally:

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh
```

### Pull Models

```bash
# LLM Contextual Analysis Model
ollama pull llama3.2

# Decision Models
ollama pull tev1:4b
# or lightweight variant:
ollama pull tev1:0.8b
# or nimble:
ollama pull nimble
```

---

## 4. Configuration

All configuration uses typed Pydantic Settings with the `VULN_AI_` environment prefix.

```bash
# Global AI Layer Toggle
export VULN_AI_AI__ENABLED=true

# Ollama LLM Contextual Settings
export VULN_AI_AI__OLLAMA__ENABLED=true
export VULN_AI_AI__OLLAMA__BASE_URL=http://localhost:11434
export VULN_AI_AI__OLLAMA__MODEL=llama3.2
export VULN_AI_AI__OLLAMA__TEMPERATURE=0.0
export VULN_AI_AI__OLLAMA__TIMEOUT_SECONDS=60

# Ollama SystemOne Decision Settings
export VULN_AI_AI__DECISION__ENABLED=true
export VULN_AI_AI__DECISION__BASE_URL=http://localhost:11434
export VULN_AI_AI__DECISION__MODEL=tev1:4b
export VULN_AI_AI__DECISION__TIMEOUT_SECONDS=30
```

---

## 5. Behavior When Ollama is Offline (Safe Fallback)

If Ollama is stopped, models are missing, or AI is disabled:

```text
Scanner → Matcher → Risk Engine (Fallback Rule: AI_UNAVAILABLE_FALLBACK) → Structured Result
```

- Scans continue without interruption.
- The Risk Engine triggers the `AI_UNAVAILABLE_FALLBACK` rule.
- Conservative statuses are applied:
  - `DETECTED` (when package version is declared)
  - `REQUIRES_REVIEW` (when package version is unknown)
  - `requires_human_review = True`
  - Explicit rationale logged: `"AI analysis and decision layers are unavailable or disabled; falling back to conservative deterministic baseline."`

---

## 6. Deterministic Risk Engine Rules

Every `RiskAssessment` records the exact audit trail of rules triggered:

- `MATCH_COMPONENT_ONLY`: Catalog product name matched component name.
- `NO_VERSION_EVIDENCE`: Manifest does not declare exact version bounds (forces `REQUIRES_REVIEW`).
- `VERSION_DECLARED`: Component declared with specific version string.
- `RANSOMWARE_CAMPAIGN_ASSOCIATED`: Documented in CISA KEV active ransomware campaigns (elevates to `HIGH` or `CRITICAL`).
- `AI_APPLICABILITY_HIGH`: SystemOne probability $\ge 0.75$ (supports `LIKELY_AFFECTED` if version is known).
- `AI_APPLICABILITY_LOW`: SystemOne probability $\le 0.25$ (produces `LIKELY_NOT_AFFECTED` and `LOW` risk).
- `AI_APPLICABILITY_MODERATE`: Probability between $0.25$ and $0.75$.
- `EXPOSURE_DIRECT` / `EXPOSURE_INDIRECT` / `EXPOSURE_UNKNOWN`: Evaluates runtime/manifest exposure posture.
- `URGENCY_HIGH`: Urgency score $\ge 8.0$.
- `CONFLICTING_SIGNALS`: Contradiction between AI narrative, high confidence matcher, or decision probabilities (mandates human triage).
- `SOURCE_APPLICABILITY_CONFLICT`: Contradiction between multiple intelligence sources regarding version applicability (e.g. OSV says OUTSIDE while NVD says WITHIN). Forces `REQUIRES_REVIEW` and mandates human triage without forging applicability.
- `AI_UNAVAILABLE_FALLBACK`: Applied when AI models cannot be reached.

---

## 7. Privacy & Security Guarantees

- **No Source Code Leakage**: Scanners inspect dependency manifests (`requirements.txt`, `pyproject.toml`). Source code files (`.py`) are never sent to Ollama.
- **Zero Cloud Leakage**: All default endpoints point to `http://localhost:11434` and local SQLite databases.
- **Sanitized Observability**: Raw responses are logged without credentials, tokens, or environment secrets.

---

## 8. Multi-Source Conflict Resolution & Risk Engine Interaction

In Stage 9, the Conflict Resolver sits upstream of both the AI Layer and the Risk Engine:

1. **Separation of Concerns**:
   - The **Version-aware Matcher** computes range boundaries for each source record.
   - The **Conflict Resolver** analyzes the set of evidences deterministically:
     - Disagreements on whether the installed version is affected produce `Applicability.REQUIRES_REVIEW` and `conflict_detected = True`.
     - Distinct ranges that both encompass or both exclude the version produce consensus without false conflict.
     - Presence in CISA KEV (`DETECTED`) complements but never falsifies verified version non-applicability.
2. **Authoritative Consumption by the Risk Engine**:
   - When `match.applicability == Applicability.REQUIRES_REVIEW` due to conflicting sources, the Risk Engine fires `SOURCE_APPLICABILITY_CONFLICT`.
   - The assessment status is set to `RiskStatus.REQUIRES_REVIEW` with `requires_human_review = True`.
   - The Risk Engine never converts `REQUIRES_REVIEW` to `LIKELY_AFFECTED`.

