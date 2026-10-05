"""H12: documented policy YAML examples must validate against the real schema."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

from vuln_ai.policy.parser import load_policy_file, parse_policy_yaml

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "backend" / "tests" / "fixtures" / "sample_policy.yaml"
POLICY_DOC = ROOT / "docs" / "policy.md"


def _extract_yaml_fences(markdown: str) -> list[str]:
    return re.findall(r"```yaml\n(.*?)```", markdown, flags=re.DOTALL)


def test_sample_policy_fixture_validates():
    policy = load_policy_file(FIXTURE)
    assert policy.name
    assert policy.suppressions
    for sup in policy.suppressions:
        assert sup.owner
        assert sup.reference
        assert sup.reason


def test_docs_aligned_suppression_example(tmp_path: Path):
    """Minimal documented shape with required audit fields parses successfully."""
    yaml_text = """
version: "1"
policy:
  name: docs-example-policy
  thresholds:
    fail_on: [HIGH]
  rules: []
  suppressions:
    - id: SUP-DOC
      match_criteria:
        vulnerability_id: CVE-2024-0001
      reason: Temporary exception pending upgrade
      owner: security@example.com
      reference: JIRA-1234
  default_action: ALLOW
"""
    path = tmp_path / "docs-example.yaml"
    path.write_text(yaml_text)
    policy = load_policy_file(path)
    assert policy.suppressions[0].owner == "security@example.com"
    assert policy.suppressions[0].reference == "JIRA-1234"


def test_h12_all_docs_policy_yaml_fences_validate():
    """Every ```yaml fence in docs/policy.md must parse with the real schema."""
    assert POLICY_DOC.is_file()
    blocks = _extract_yaml_fences(POLICY_DOC.read_text(encoding="utf-8"))
    assert len(blocks) >= 3
    for idx, block in enumerate(blocks):
        policy = parse_policy_yaml(block)
        assert policy.name, f"block {idx} missing name"
        for sup in policy.suppressions:
            assert sup.owner, f"block {idx} suppression missing owner"
            assert sup.reference, f"block {idx} suppression missing reference"
            assert sup.reason, f"block {idx} suppression missing reason"


def test_h12_docs_examples_pass_cli_policy_validate():
    """Canonical docs examples must exit 0 under `vuln-ai policy validate`."""
    blocks = _extract_yaml_fences(POLICY_DOC.read_text(encoding="utf-8"))
    assert blocks
    with tempfile.TemporaryDirectory() as tmp:
        for idx, block in enumerate(blocks):
            path = Path(tmp) / f"docs-policy-{idx}.yaml"
            path.write_text(block, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "vuln_ai.cli", "policy", "validate", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, (
                f"docs YAML block {idx} failed policy validate\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )


def test_h12_docs_applicability_vocabulary_is_canonical():
    text = POLICY_DOC.read_text(encoding="utf-8")
    assert "SUSPECTED" not in text
    assert "`AFFECTED`" not in text
    assert "`NOT_AFFECTED`" not in text
    assert "LIKELY_AFFECTED" in text
    assert "LIKELY_NOT_AFFECTED" in text
    assert "REQUIRES_REVIEW" in text
    assert "UNKNOWN" in text
