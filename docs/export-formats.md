# Security & Software Composition Export Formats

Local Vulnerability AI implements a formal export layer following the architectural principle:
**ONE SECURITY ENGINE, MULTIPLE EXPORT FORMATS**.

Canonical scan results are transformed into standard machine-readable security and software composition documents via a unified `CanonicalExportModel` (`ExportScan`).

---

## Supported Standards & Versions

| Format | Specification Version | MIME Content Type | Primary Use Case |
|---|---|---|---|
| **SARIF** | 2.1.0 | `application/sarif+json` | Static analysis findings, GitHub Code Scanning, CI/CD security quality gates |
| **CycloneDX** | 1.5 JSON | `application/vnd.cyclonedx+json` | Software Bill of Materials (SBOM), dependency graph topology, vulnerability intelligence |
| **SPDX** | 2.3 JSON | `application/spdx+json` | Software Bill of Materials (SBOM), package catalog, open-source compliance |

---

## 1. SARIF (Static Analysis Results Interchange Format)

### Specification
Conforms to **SARIF 2.1.0** (`https://json.schemastore.org/sarif-2.1.0.json`).

### Tool Metadata
- **Driver Name:** `Local Vulnerability AI`
- **Driver Version:** Derived dynamically from application version (`0.1.0`).
- **Information URI:** Official repository URL (`https://github.com/Alejandro03GG/Local-Vulnerabilty-Ai`).

### Rules & Results Architecture
- **Rule Deduplication:** Vulnerabilities are represented as rules (`ruleId` = canonical ID like `CVE-2023-32681`). If multiple components are affected by the same CVE, **1 Rule** is defined with **N Results**.
- **Level Mapping:** Deterministically mapped from the Risk Engine assessment:
  - `CRITICAL` / `HIGH` $\rightarrow$ `error`
  - `MEDIUM` $\rightarrow$ `warning`
  - `LOW` / `INFO` / `NONE` $\rightarrow$ `note`
- **Honest Locations:** Dependabot/lockfile findings do not fabricate synthetic line or column numbers (`line 1, col 1`). Real manifest or lockfile filepaths are placed in `locations[].physicalLocation.artifactLocation.uri` without artificial line ranges.
- **Enriched Properties:**
  ```json
  "properties": {
    "componentName": "urllib3",
    "componentVersion": "1.26.5",
    "ecosystem": "pypi",
    "dependencyType": "direct",
    "scope": "runtime",
    "sourceFile": "requirements.txt",
    "applicability": "REQUIRES_REVIEW",
    "riskLevel": "MEDIUM",
    "requiresHumanReview": true,
    "confidence": 0.85,
    "sourceConflicts": [...]
  }
  ```

---

## 2. CycloneDX SBOM

### Specification
Conforms to **CycloneDX 1.5 JSON** (`http://cyclonedx.org/schema/bom-1.5.schema.json`).

### Components & Package URLs
- **PURL Standard:** Package URLs (`pkg:<type>/<name>@<version>`) are generated according to the official specification for supported ecosystems:
  - PyPI: `pkg:pypi/requests@2.25.0`
  - npm: `pkg:npm/lodash@4.17.21`, with URL-encoded namespaces `pkg:npm/%40types/node@20.1.0`
  - Cargo: `pkg:cargo/serde@1.0.104`
- **Identity & Bom-Ref:** Every component has a unique, deterministic `bom-ref`.
- **Scopes & Provenance:** Direct vs transitive classification, scope (`runtime`, `dev`), and source manifest/lockfile are preserved in component properties.

### Dependency Graph Topology
CycloneDX `dependencies` preserves the full directed graph resolved from lockfiles:
```json
"dependencies": [
  {
    "ref": "pkg:root/project",
    "dependsOn": ["pkg:pypi/fastapi@0.100.0"]
  },
  {
    "ref": "pkg:pypi/fastapi@0.100.0",
    "dependsOn": ["pkg:pypi/starlette@0.27.0"]
  }
]
```

### Vulnerability Ratings & Analysis
When findings exist, CycloneDX incorporates them with vulnerability source, score, severity, affected components, and triage state (`exploitable`, `in_triage`, `not_affected`, `false_positive`).

---

## 3. SPDX SBOM

### Specification
Conforms to **SPDX 2.3 JSON** (`SPDX-2.3`).

### Packages & License Representation
- **Root Package:** Represents the scanned project (`SPDXRef-Package-Root`).
- **Component Packages:** Each resolved dependency is cataloged with sanitized SPDX identifier (`SPDXRef-Package-<eco>-<name>-<version>`), package download location, and Package URL external references.
- **Honest Licenses:** Local Vulnerability AI does not guess licenses without verified license scanners. Fields are truthfully represented as:
  ```json
  "licenseConcluded": "NOASSERTION",
  "licenseDeclared": "NOASSERTION"
  ```

### Relationships
- `SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-Root`
- `SPDXRef-Package-Root DEPENDS_ON SPDXRef-Package-<direct>`
- `SPDXRef-Package-<parent> DEPENDS_ON SPDXRef-Package-<child>`

---

## Container Image Scanning Export Support (Etapa 17)

When findings originate from container image analysis, all three export formats include container-specific provenance metadata alongside standard vulnerability data.

### SARIF Container Properties

Container findings include additional `properties` on each result:

```json
"properties": {
  "containerImage": "myorg/service:1.2.0",
  "containerDigest": "sha256:abc123...",
  "containerLayer": "sha256:def456...",
  "containerPath": "/var/lib/dpkg/status",
  "packageManager": "dpkg"
}
```

Locations reference real filesystem paths within the container (e.g., `/app/requirements.txt`, `/var/lib/dpkg/status`). No fabricated `line 1 column 1` values are generated.

### CycloneDX Container Properties

Component entries for container-sourced packages include `vuln_ai:container_*` properties:

```json
"properties": [
  { "name": "vuln_ai:container_layer", "value": "sha256:def456..." },
  { "name": "vuln_ai:container_path", "value": "/app/requirements.txt" }
]
```

When the scanned artifact is a container image, the root `metadata.component.type` is set to `"container"` and `version` contains the image digest.

### SPDX Container Properties

The root package `primaryPackagePurpose` is set to `"CONTAINER"` for image scans. If a digest is available, it appears as `versionInfo`. Component packages preserve the same PURL-based external references and `NOASSERTION` license honesty as application scans.

### CLI Usage

```bash
# Container image SARIF export
vuln-ai image scan image.tar --format sarif --output container-results.sarif

# Container image CycloneDX SBOM
vuln-ai image scan image.tar --format cyclonedx --output container-sbom.cdx.json

# Container image SPDX SBOM
vuln-ai image scan image.tar --format spdx --output container-sbom.spdx.json
```

---

## 4. CLI Usage

The `vuln-ai scan` command supports `--format` and `--output` options:

```bash
# Export SARIF to stdout (clean machine-readable stream)
vuln-ai scan . --format sarif | jq .

# Export SARIF to a file with atomic replacement
vuln-ai scan . --format sarif --output results.sarif

# Export CycloneDX SBOM to a file
vuln-ai scan . --format cyclonedx --output sbom.cdx.json

# Export SPDX SBOM to a file
vuln-ai scan . --format spdx --output sbom.spdx.json

# CI scan: fail build if HIGH or CRITICAL findings exist
vuln-ai scan . \
  --format sarif \
  --output vuln-results.sarif \
  --fail-on high
```

### Stream Contract
- **stdout:** Pure JSON document. No progress logs or diagnostic text interfere with stdout.
- **stderr:** Diagnostic messages, warnings, and error details.
- **Exit codes:**
  - `0`: Scan successful, no threshold violation.
  - `1`: Policy threshold violated (`--fail-on`).
  - `2`: CLI usage / argument error.
  - `3`: Internal scan or export error.

---

## 5. REST API Endpoints

Export endpoints generate the requested format directly from scan records:

```http
GET /api/v1/scans/{scan_id}/export/sarif
Content-Type: application/sarif+json

GET /api/v1/scans/{scan_id}/export/cyclonedx
Content-Type: application/vnd.cyclonedx+json

GET /api/v1/scans/{scan_id}/export/spdx
Content-Type: application/spdx+json
```

---

## 6. CI/CD Integration Examples

### GitHub Actions (Code Scanning / SARIF Upload)
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  vuln-ai-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Local Vulnerability AI
        run: pip install .

      - name: Run Scan & Export SARIF
        run: |
          vuln-ai scan . --no-ai --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI
```yaml
security_scan:
  stage: test
  script:
    - vuln-ai scan . --no-ai --format cyclonedx --output gl-sbom.cdx.json
    - vuln-ai scan . --no-ai --format sarif --output results.sarif
  artifacts:
    when: always
    paths:
      - gl-sbom.cdx.json
      - results.sarif
```

### Jenkins Pipeline
```groovy
stage('Security & SBOM Scan') {
  steps {
    sh 'vuln-ai scan . --no-ai --format sarif --output results.sarif --fail-on high'
    sh 'vuln-ai scan . --no-ai --format cyclonedx --output sbom.cdx.json'
  }
  post {
    always {
      archiveArtifacts artifacts: 'results.sarif, sbom.cdx.json', fingerprint: true
    }
  }
}
```

---

## 7. Local-First Privacy Notice

> [!IMPORTANT]
> **SBOM Privacy Notice:**
> Software Bill of Materials (SBOM) documents disclose complete software composition details, including dependency names, versions, scopes, and graph topology. The user is responsible for reviewing SBOM files before publishing them publicly, especially when projects contain internal dependencies, private packages, or proprietary structures.
> Local Vulnerability AI is strictly **local-first**: exported files and data are stored locally and are never transmitted to external services automatically.
