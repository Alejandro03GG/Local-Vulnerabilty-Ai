# Future Work (Post 1.0)

Ideas discovered during Etapa 18 that are **intentionally out of scope** for Local Vulnerability AI 1.0.0:

## Container / Image

- `DockerDaemonSource` and `OCIRegistrySource` implementations (no credential storage in SQLite)
- Dedicated CLI commands: `vuln-ai image list`, `vuln-ai image info`
- Multi-platform OCI index target selection UX
- Hardlink escape edge-case hardening beyond current archive limits

## Platform

- Kubernetes / Helm / Terraform scanning
- Runtime container monitoring
- Cloud security posture management
- Dedicated license compliance scanner
- SIEM / EDR integrations

## Product

- Richer offline feed packaging / air-gapped sync bundles
- Additional SBOM validators as optional CI plugins
- Expanded accessibility automation in frontend CI

Do not treat this list as a commitment. Prioritize only after 1.0 release feedback.
