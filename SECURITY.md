# Security Policy

The **Local Vulnerability AI** team takes the security and integrity of this software, its dependency analysis pipeline, and the privacy of its users seriously.

---

## Supported Versions

Only the latest release branch receives active security updates and vulnerability patches.

| Version | Supported          |
| :---    | :---               |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability or privacy flaw in **Local Vulnerability AI**, please do **NOT** open a public GitHub issue, discussion thread, or pull request.

Instead, please report the vulnerability privately through one of the following channels:

1. **GitHub Private Security Advisory**: Use the **Security** tab of this repository and click **Report a vulnerability**. This creates a confidential channel between you and the maintainers.
2. **Direct Maintainer Contact**: If GitHub advisories are unavailable, contact the maintainers directly through their designated security contact listed on their GitHub profile (`@alejandro03hl`).

### What Information to Include

To help us triage and remediate the issue quickly, please provide as much context as possible:

- **Component Affected**: Specify whether the vulnerability is in the backend core (`vuln_ai`), the API layer, parsing routines, or the frontend web console.
- **Vulnerability Description**: Detailed explanation of the vulnerability and its potential security impact.
- **Proof of Concept / Steps to Reproduce**: Minimal reproducible code snippet, manifest, or HTTP payload.
- **Environment Details**: Operating system, Python version, Node.js version, and database configuration.
- **Mitigation Suggestions**: If you have identified a potential fix, please mention it.

### What NOT to Include Publicly

- Do **not** disclose details publicly until a patched release is published.
- Do **not** post exploit payloads or demonstration scripts in public forums.
- Do **not** share user manifests or proprietary source code in public channels.

---

## Response Timeline

We follow a coordinated vulnerability disclosure process:

1. **Acknowledgment**: We aim to acknowledge receipt of your report within **48 hours**.
2. **Assessment & Confirmation**: We will assess the severity, reproduce the issue, and provide an initial assessment within **5 business days**.
3. **Remediation**: A fix will be developed in a private branch, verified against the automated test suite, and published in a security patch release.
4. **Public Disclosure**: A public security advisory crediting the reporter (unless anonymity is requested) will be published alongside the patched release.

---

## Architecture Security Principles

As a local-first application, Local Vulnerability AI is designed around strict security boundaries:

- **Source Code Privacy**: Target project code files are analyzed locally via AST/static parsers; source code is **never** transmitted to local or external AI models.
- **No Secret Persistence**: No credentials, tokens, or external API keys are stored in the local SQLite database.
- **Deterministic Risk Engine**: The system does not delegate risk conclusions to unvetted LLM outputs. All risk classifications are derived deterministically.
- **Safe Network Boundaries**: Network egress is strictly restricted to user-configured intelligence feeds (OSV, NVD, CISA KEV) and the local Ollama instance (`http://localhost:11434` by default).


---

## Container Artifact Analysis (Etapa 17)

Local Vulnerability AI performs **static** container/image artifact analysis and does **not** execute container workloads during scanning.

- No `docker run` / `docker exec` / `docker build` / `podman run` during analysis.
- No execution of entrypoints, layer binaries, or Dockerfile commands.
- No mandatory Docker Desktop dependency for local OCI/Docker archive inspection.
- Registry credentials and tokens must never be persisted in the local database.

See [docs/security.md](docs/security.md) and [docs/image-security.md](docs/image-security.md) for hardening details.
