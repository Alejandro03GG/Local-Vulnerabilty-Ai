# CI/CD Integration & Automated Security Gating

## Overview

`Local Vulnerability AI` provides deterministic security gating for continuous integration pipelines (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, Bitbucket Pipelines).

### Deterministic Exit Codes
The CLI communicates scan status and policy compliance through strict exit codes:

| Exit Code | Classification | Meaning | Pipeline Result |
|---|---|---|---|
| `0` | `SUCCESS` | Scan succeeded and policy passed (or all violations were covered by active suppressions) | Pass |
| `1` | `POLICY_VIOLATION` | Scan detected one or more unsuppressed policy violations, or encountered an expired suppression failure | Fail |
| `2` | `USAGE_ERROR` | Malformed CLI arguments, missing target path, or invalid `.vuln-ai.yaml` syntax | Fail (Config error) |
| `3` | `INTERNAL_ERROR` | Unhandled database error or internal exception | Fail (System error) |

---

## Integration Examples

### GitHub Actions Workflow

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  vuln-ai-scan:
    name: Local Vulnerability AI Audit
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"

      - name: Install Local Vulnerability AI
        run: |
          pip install --upgrade pip
          pip install -e ./backend

      - name: Initialize Database
        run: |
          cd backend
          alembic upgrade head

      - name: Run Policy Gated Scan
        run: |
          vuln-ai scan . \
            --policy .vuln-ai.yaml \
            --show-policy \
            --show-suppressions \
            --format sarif \
            --output results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI Pipeline

```yaml
stages:
  - security

vulnerability_policy_gate:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install -e ./backend
    - (cd backend && alembic upgrade head)
  script:
    - vuln-ai scan . --policy .vuln-ai.yaml --show-policy --format cyclonedx --output bom.json
  artifacts:
    when: always
    paths:
      - bom.json
```

---

## Managing Security Exceptions in CI/CD

1. **Active Suppressions**: When a vulnerability cannot be immediately remediated, an engineer defines an active suppression with an expiration date (`expires_at`) and ticket reference (`reference`).
2. **Exemption**: The pipeline passes (`exit 0`), and the suppression details are embedded into the generated SARIF and CycloneDX SBOM artifacts.
3. **Auto-Expiry**: Once the expiration date passes, the suppression transitions to `EXPIRED`. In the subsequent CI build, the pipeline will fail (`exit 1`), alerting the team that the exception has expired and requires remediation or renewal.

---

## Container Image Scanning in CI/CD Pipelines (Etapa 17)

Because `vuln-ai` inspects container archives completely statically without requiring `docker.sock` or root daemon privileges, container security gates can run inside standard rootless CI container runners.

### GitHub Actions: Build & Static Scan Container
```yaml
      - name: Build Container Image Archive
        run: |
          docker build -t myapp:ci .
          docker save myapp:ci -o myapp.tar

      - name: Scan Container Image with Local Vulnerability AI
        run: |
          vuln-ai image scan myapp.tar \
            --reference "myapp:ci" \
            --policy .vuln-ai.yaml \
            --format sarif \
            --output container-results.sarif

      - name: Upload Container SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: container-results.sarif
```

### GitLab CI: Build & Scan Container
```yaml
container_security_gate:
  stage: security
  image: python:3.12-slim
  services:
    - docker:dind
  before_script:
    - pip install -e ./backend
    - (cd backend && alembic upgrade head)
  script:
    - docker build -t myapp:ci .
    - docker save myapp:ci -o myapp.tar
    - vuln-ai image scan myapp.tar --reference "myapp:ci" --policy .vuln-ai.yaml --format cyclonedx --output container-sbom.cdx.json
  artifacts:
    when: always
    paths:
      - container-sbom.cdx.json
```

### Jenkins: Build & Scan Container
```groovy
stage('Container Security Audit') {
    steps {
        sh 'docker build -t myapp:ci .'
        sh 'docker save myapp:ci -o myapp.tar'
        sh '''
            vuln-ai image scan myapp.tar \
              --reference "myapp:ci" \
              --policy .vuln-ai.yaml \
              --format sarif \
              --output container-results.sarif
        '''
    }
    post {
        always {
            archiveArtifacts artifacts: 'container-results.sarif', fingerprint: true
        }
    }
}
```
