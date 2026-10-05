# Security Policy

The **Local Vulnerability AI** team takes the security and integrity of this software, its dependency analysis pipeline, and the privacy of its users seriously.

---

## Supported Versions

Security fixes are applied to the latest published release on the active `1.1.x` line. Older lines may not receive patches.

| Version | Supported |
| :--- | :--- |
| 1.1.x (latest, currently **1.1.3**) | :white_check_mark: |
| 1.0.x | :warning: Critical fixes only, best effort |
| &lt; 1.0.0 | :x: |

If you are unsure which version you run: `vuln-ai version` (CLI) or check `CHANGELOG.md` / Git tags.

---

## Reporting a Vulnerability

If you discover a security vulnerability or privacy flaw in **Local Vulnerability AI**, please do **NOT** open a public GitHub issue, discussion, or pull request.

### Preferred channel (private)

1. Open a **GitHub Security Advisory** for this repository:  
   **Security → Report a vulnerability**  
   Direct link (requires access to the repo’s Security tab):  
   https://github.com/Alejandro03GG/Local-Vulnerabilty-Ai/security/advisories/new

2. If the **Report a vulnerability** button is missing, the repository owner must enable **Private vulnerability reporting** in GitHub:  
   **Settings → Code security and analysis → Private vulnerability reporting**.  
   Until that is enabled, contact the repository owner via their GitHub profile: [@Alejandro03GG](https://github.com/Alejandro03GG) (ask for a private channel; do not post exploit details in public issues).

There is no separate public security email published for this project. Do not invent or guess contact addresses.

### What to include (privately)

- **Component**: backend core, scanners, sources/sync, matcher, risk/policy, API, CLI, frontend, exports, container inspection, etc.
- **Description**: what is wrong and the security/privacy impact.
- **Reproduction**: minimal steps, sanitized manifests, or HTTP payloads that do **not** include secrets.
- **Environment**: OS, Python/Node versions, Local Vulnerability AI version.
- **Suggested mitigation** (optional).

### What NOT to include publicly

- Do not disclose details until a patched release (or coordinated advisory) is published.
- Do not post exploit payloads in public forums or issues.
- Do not share proprietary manifests, credentials, tokens, API keys, or private registry auth material.

---

## Response Timeline

Coordinated disclosure expectations:

1. **Acknowledgment**: aim within **48 hours** of a private report.
2. **Assessment**: initial severity/repro assessment within **5 business days**.
3. **Remediation**: fix developed privately, validated against the automated suite, released as a security patch when appropriate.
4. **Public disclosure**: advisory (with reporter credit unless anonymity is requested) alongside the patched release when applicable.

---

## Scope — what is in / out

### In scope (examples)

- Path traversal, archive bombs, or unsafe parsing in scanners / container archive inspection
- Secret persistence in SQLite or logs
- Unintended network egress or data leakage to AI providers
- Policy/suppression bypass that silently drops real findings without auditability
- XSS or unsafe rendering in the local web console when viewing scan data
- Dependency or supply-chain issues in this repository’s own release artifacts

### Out of scope / limitations (product model)

- Requiring Docker/Podman **runtime** execution (the product is static analysis only)
- Cloud posture, Kubernetes runtime monitoring, or malware detonation
- Third-party advisory correctness of OSV / NVD / CISA KEV upstream feeds themselves
- Local misconfiguration (e.g. binding the API beyond localhost without operator controls)

See also [docs/security.md](docs/security.md), [docs/image-security.md](docs/image-security.md), and [docs/privacy.md](docs/privacy.md).

---

## Architecture Security Principles

- **Source Code Privacy**: Target project files are analyzed locally; source code is **never** transmitted to LLMs.
- **No Secret Persistence**: Registry/Docker credentials and similar secrets must not be stored in the local SQLite database.
- **Deterministic Risk Engine**: Risk conclusions are not delegated to unvetted LLM outputs.
- **Safe Network Boundaries**: Egress is limited to configured intelligence feeds (OSV, NVD, CISA KEV) and optional local Ollama (`http://localhost:11434` by default).

---

## Container Artifact Analysis

Local Vulnerability AI performs **static** container/image artifact analysis and does **not** execute container workloads during scanning.

- No `docker run` / `docker exec` / `docker build` / `podman run` during analysis.
- No execution of entrypoints, layer binaries, or Dockerfile commands.
- Registry credentials and tokens must never be persisted in the local database.

---

## Threat Model (Summary)

| Threat | Mitigation |
| :--- | :--- |
| Malicious project manifests / lockfiles | Strict parsers, size limits, no code execution |
| Malicious container archives / Dockerfiles | Static inspection only; archive bomb, path traversal, and symlink controls |
| Malicious policy YAML | `yaml.safe_load`, Pydantic `extra="forbid"`, size limits |
| Accidental secret persistence | No registry/Docker credentials stored in SQLite |
| AI data leakage | Optional local Ollama only; metadata-only prompts; `--no-ai` disables AI |
| Incorrect security decisions from AI | Deterministic Matcher / Conflict / Risk / Policy remain authoritative |

---

## Third-Party Dependencies

Dependency advisories are reviewed at release time. Known deferred items (see [docs/future-work.md](docs/future-work.md)):

- `react-router` / `react-router-dom` 6.30.x: moderate advisories with fixes primarily via React Router 7 (breaking). Local SPA without SSR; tracked as post-1.0 work.
