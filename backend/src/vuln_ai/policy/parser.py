"""Parser and schema validator for declarative policy YAML files (Etapa 16 §6, §23).

Enforces safety guarantees:
- Pure YAML parsing via PyYAML SafeLoader (no custom tags or code execution).
- Strict size limits preventing memory exhaustion (1MB max).
- Schema validation via Pydantic models with forbidden extra fields.
- Duplicate rule ID detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from vuln_ai.policy.errors import PolicyParseError, PolicyValidationError
from vuln_ai.policy.models import Policy

MAX_POLICY_FILE_SIZE_BYTES = 1024 * 1024  # 1 MB limit


def parse_policy_dict(data: dict[str, Any]) -> Policy:
    """Validate and instantiate Policy domain model from dictionary."""
    if not isinstance(data, dict):
        raise PolicyValidationError("Policy configuration root must be a YAML mapping")

    # If document is wrapped in top-level 'policy:' key
    raw_policy = data.get("policy", data)
    if not isinstance(raw_policy, dict):
        raise PolicyValidationError("Content under 'policy' must be a mapping")

    # Merge top-level version if defined outside
    if "version" in data and "version" not in raw_policy:
        raw_policy["version"] = str(data["version"])

    # Merge top-level suppressions if defined outside
    if "suppressions" in data and "suppressions" not in raw_policy:
        raw_policy["suppressions"] = data["suppressions"]

    try:
        policy = Policy.model_validate(raw_policy)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise PolicyValidationError(f"Invalid policy schema: {details}") from exc

    # Enforce duplicate rule ID check
    seen_ids: set[str] = set()
    for rule in policy.rules:
        if rule.id in seen_ids:
            raise PolicyValidationError(f"Duplicate rule ID detected: '{rule.id}'")
        seen_ids.add(rule.id)

    return policy


def parse_policy_yaml(content: str) -> Policy:
    """Parse policy from YAML text string with safety checks."""
    if not content or not content.strip():
        raise PolicyParseError("Policy document is empty")

    if len(content.encode("utf-8")) > MAX_POLICY_FILE_SIZE_BYTES:
        raise PolicyParseError(
            f"Policy file exceeds maximum allowed size of {MAX_POLICY_FILE_SIZE_BYTES} bytes"
        )

    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise PolicyParseError(f"Malformed YAML syntax: {exc}") from exc

    if not isinstance(parsed, dict):
        raise PolicyValidationError("Policy document root must be a dictionary")

    return parse_policy_dict(parsed)


def load_policy_file(filepath: Path | str) -> Policy:
    """Read and validate a policy file from local filesystem."""
    path = Path(filepath).resolve()
    if not path.exists():
        raise PolicyParseError(f"Policy file not found: '{path}'")
    if not path.is_file():
        raise PolicyParseError(f"Policy path is not a file: '{path}'")

    file_size = path.stat().st_size
    if file_size > MAX_POLICY_FILE_SIZE_BYTES:
        raise PolicyParseError(
            f"Policy file size ({file_size} bytes) exceeds limit of {MAX_POLICY_FILE_SIZE_BYTES} bytes"
        )

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise PolicyParseError(f"Failed to read policy file '{path}': {exc}") from exc

    return parse_policy_yaml(content)
