# AI Layer, Decision Models & Deterministic Risk Engine

This document details the architecture, design principles, and operation of **Phase 2: AI Layer + Ollama SystemOne + Risk Engine** in `local-vulnerability-ai`.

---

## 1. Architectural Philosophy

Local Vulnerability AI adheres to a strict pipeline:

```text
Scanner
   ↓ (Manifest components)
CISA KEV
   ↓ (Known exploited vulnerabilities)
Deterministic Matcher
   ↓ (Rule-based exact & normalized matching)
AI Contextual Analysis
   ↓ (Ollama LLM contextual narrative)
Ollama SystemOne Decision
   ↓ (Probabilistic evaluation: noul, choice, score)
Deterministic Risk Engine
   ↓ (Explicit audit rules)
Risk Assessment & Structured Findings
```

### Core Principles

1. **Deterministic Matcher First**: The AI does NOT search for or invent vulnerabilities. Vulnerability candidates are identified strictly by deterministic catalog lookups.
2. **AI Does Not Decide Final Risk**: The LLM provides contextual explanations and nuance; it is never the sole authority declaring a component vulnerable.
3. **Transparent Probabilities**: SystemOne decision probabilities indicate the model's evaluation over predefined options; they do not equate to a mathematically guaranteed real-world exploit certainty.
4. **Local-First Privacy**: By default, all operations run on local hardware via SQLite and local Ollama instances. Source code is never transmitted externally.

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
- `AI_UNAVAILABLE_FALLBACK`: Applied when AI models cannot be reached.

---

## 7. Privacy & Security Guarantees

- **No Source Code Leakage**: Scanners inspect dependency manifests (`requirements.txt`, `pyproject.toml`). Source code files (`.py`) are never sent to Ollama.
- **Zero Cloud Leakage**: All default endpoints point to `http://localhost:11434` and local SQLite databases.
- **Sanitized Observability**: Raw responses are logged without credentials, tokens, or environment secrets.
