"""H12: documented policy YAML examples must validate against the real schema."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.policy.parser import load_policy_file

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "backend" / "tests" / "fixtures" / "sample_policy.yaml"


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
