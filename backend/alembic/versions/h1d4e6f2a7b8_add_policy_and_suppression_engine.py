"""Add policy and suppression engine tables

Revision ID: h1d4e6f2a7b8
Revises: g9c3d5e2f1b4
Create Date: 2026-10-03 12:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "h1d4e6f2a7b8"
down_revision: str | Sequence[str] | None = "g9c3d5e2f1b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create policies, policy_rules, suppressions, and policy_evaluations tables."""
    # 1. policies
    op.create_table(
        "policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=50), server_default="1", nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("default_action", sa.String(length=50), server_default="ALLOW", nullable=False),
        sa.Column("thresholds_json", sa.Text(), server_default="{}", nullable=False),
        sa.Column("metadata_json", sa.Text(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policies_name", "policies", ["name"], unique=False)

    # 2. policy_rules
    op.create_table(
        "policy_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("conditions_json", sa.Text(), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("priority", sa.Integer(), server_default="100", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_id", "rule_id", name="uq_policy_rule_id"),
    )
    op.create_index("ix_policy_rules_policy", "policy_rules", ["policy_id"], unique=False)

    # 3. suppressions
    op.create_table(
        "suppressions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("vulnerability_id", sa.String(length=100), nullable=True),
        sa.Column("package_name", sa.String(length=255), nullable=True),
        sa.Column("ecosystem", sa.String(length=50), nullable=True),
        sa.Column("package_version", sa.String(length=100), nullable=True),
        sa.Column("finding_id", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=False),
        sa.Column("reference", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by", sa.String(length=255), server_default="system", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.Text(), server_default="{}", nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_suppressions_project", "suppressions", ["project_id"], unique=False)
    op.create_index("ix_suppressions_vuln", "suppressions", ["vulnerability_id"], unique=False)
    op.create_index("ix_suppressions_pkg", "suppressions", ["package_name"], unique=False)

    # 4. policy_evaluations
    op.create_table(
        "policy_evaluations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=True),
        sa.Column("policy_name", sa.String(length=255), nullable=False),
        sa.Column("total_findings", sa.Integer(), server_default="0", nullable=False),
        sa.Column("allowed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("violations_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("suppressed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("accepted_risk_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("requires_review_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("has_violations", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("ci_exit_code", sa.Integer(), server_default="0", nullable=False),
        sa.Column("evaluations_json", sa.Text(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_policy_evaluations_scan", "policy_evaluations", ["scan_id"], unique=False)


def downgrade() -> None:
    """Drop policy and suppression tables."""
    op.drop_index("ix_policy_evaluations_scan", table_name="policy_evaluations")
    op.drop_table("policy_evaluations")

    op.drop_index("ix_suppressions_pkg", table_name="suppressions")
    op.drop_index("ix_suppressions_vuln", table_name="suppressions")
    op.drop_index("ix_suppressions_project", table_name="suppressions")
    op.drop_table("suppressions")

    op.drop_index("ix_policy_rules_policy", table_name="policy_rules")
    op.drop_table("policy_rules")

    op.drop_index("ix_policies_name", table_name="policies")
    op.drop_table("policies")
