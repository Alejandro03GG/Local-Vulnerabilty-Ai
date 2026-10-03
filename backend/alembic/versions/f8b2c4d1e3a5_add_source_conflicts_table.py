"""Add source_conflicts table for multi-source conflict resolution

Revision ID: f8b2c4d1e3a5
Revises: e7a1b3c9d2f4
Create Date: 2026-10-02 12:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f8b2c4d1e3a5"
down_revision: str | Sequence[str] | None = "e7a1b3c9d2f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create source_conflicts table."""
    op.create_table(
        "source_conflicts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("match_id", sa.String(length=36), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=36), nullable=True),
        sa.Column("conflict_type", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("field", sa.String(length=50), nullable=False),
        sa.Column("sources", sa.Text(), server_default="[]", nullable=False),
        sa.Column("identifiers", sa.Text(), server_default="[]", nullable=False),
        sa.Column("values", sa.Text(), server_default="{}", nullable=False),
        sa.Column("resolution", sa.String(length=50), nullable=False),
        sa.Column("rationale", sa.Text(), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["match_id"],
            ["matches.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "match_id",
            "conflict_type",
            "field",
            name="uq_source_conflict_match_field",
        ),
    )
    op.create_index(
        "ix_source_conflicts_match",
        "source_conflicts",
        ["match_id"],
        unique=False,
    )
    op.create_index(
        "ix_source_conflicts_vuln",
        "source_conflicts",
        ["vulnerability_id"],
        unique=False,
    )
    op.create_index(
        "ix_source_conflicts_type",
        "source_conflicts",
        ["conflict_type"],
        unique=False,
    )


def downgrade() -> None:
    """Drop source_conflicts table."""
    op.drop_table("source_conflicts")
