# Security Model — Local Vulnerability AI

This document summarizes the security boundaries of Local Vulnerability AI, including container and image scanning constraints introduced in Etapa 17.

For vulnerability disclosure and maintainer contact, see the root [SECURITY.md](../SECURITY.md).

---

## Core Principles

- **Local-first**: analysis runs on the operator workstation or CI runner. Project source and container archives are not uploaded to a remote SaaS by default.
- **Deterministic risk**: Risk Engine and Policy Engine conclusions are rule-based. Optional AI never overrides applicability, risk, or policy decisions.
- **No secret persistence**: registry passwords, Docker credentials, access tokens, and environment secrets must not be stored in SQLite.
- **Canonical vocabulary**: findings use `LIKELY_AFFECTED`, `LIKELY_NOT_AFFECTED`, `REQUIRES_REVIEW`, etc. The status `VULNERABLE` is prohibited.

---

## Container & Image Scanning Guarantee

> Local Vulnerability AI performs static/container artifact analysis and does not execute container workloads during scanning.

The scanner never invokes:

```text
docker run
docker exec
docker build
podman run
podman exec
docker compose up
```

It also never executes:

- image entrypoints
- shell scripts found in layers
- binaries discovered in the filesystem
- Dockerfile `RUN` commands

Acquisition and inspection are separated through the `ImageSource` abstraction:

```text
ImageSource
├── LocalOCIArchiveSource   (implemented — static .tar analysis)
├── DockerDaemonSource      (placeholder — not implemented)
└── OCIRegistrySource       (placeholder — not implemented)
```

Etapa 17 only implements `LocalOCIArchiveSource`. Remote registry authentication and daemon pulls are intentionally out of scope.

---

## Archive Hardening

Static archive inspection enforces:

- maximum archive / member size limits
- maximum file counts and nesting depth
- compression-ratio checks (archive bomb defense)
- path traversal rejection (`../`, absolute escapes)
- symlink escape rejection outside the logical image root
- strict JSON/type validation for OCI/Docker manifests

Rejected malicious archives fail closed with a security error; they do not partially execute or extract unsafe paths.

---

## AI Boundaries

When AI analysis is enabled:

- only component metadata, vulnerability metadata, and limited container metadata may be sent to the local model
- filesystem contents, secrets, registry tokens, and Docker credentials are never sent
- if Ollama is unavailable, scanning continues without AI

---

## Policy & Suppression Scope

Policies and suppressions may optionally target a container image digest (`sha256:...`) so an exception for one immutable image cannot silently apply to another.

Suppressions never delete technical findings; they only change `PolicyEvaluation` outcomes.

---

## Related Documents

- [docs/container-scanning.md](container-scanning.md)
- [docs/dockerfile-scanning.md](dockerfile-scanning.md)
- [docs/image-security.md](image-security.md)
- [docs/privacy.md](privacy.md)
- [SECURITY.md](../SECURITY.md)
