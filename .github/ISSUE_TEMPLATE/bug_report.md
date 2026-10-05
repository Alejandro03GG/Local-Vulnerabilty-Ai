---
name: Bug Report
about: Report a defect in Local Vulnerability AI (not a security vulnerability)
title: '[BUG] '
labels: ['bug']
assignees: ''
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1.
2.
3.

Include the exact command(s), target path/manifest/image (sanitized), and flags used.

## Expected Behavior

What you expected to happen.

## Actual Behavior

What happened instead (exit code, unexpected UI state, wrong applicability, etc.).

## Version

- Local Vulnerability AI: (e.g. `vuln-ai version` / `1.1.3`)
- Git commit (optional):

## Environment

- OS & architecture: (e.g. macOS 14 arm64, Ubuntu 22.04 x86_64)
- Python: (e.g. `python --version`)
- Node.js (if UI): (e.g. `node --version`)
- Install method: (e.g. `pip install -e "backend/[dev]"`, from source)
- Offline / no-AI mode?: (yes/no)

## Relevant Logs / Output

```text
Paste terminal or console output here (redact secrets)
```

## Configuration (sanitized)

Describe relevant config only (policy file name, source sync mode, custom data dir).  
**Do not** paste API keys, tokens, passwords, private registry credentials, or full `.env` contents.

## Impact

- Severity for you: (blocker / major / minor / cosmetic)
- Affects: (CLI / API / UI / scanner / matching / sources / policy / other)

## Reproduction tips

Anything else needed to reproduce reliably (fixture shape, ecosystem, container archive type).
