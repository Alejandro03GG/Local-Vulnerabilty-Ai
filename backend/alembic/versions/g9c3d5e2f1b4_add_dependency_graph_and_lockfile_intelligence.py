"""Add dependency graph and lockfile intelligence

Revision ID: g9c3d5e2f1b4
Revises: f8b2c4d1e3a5
Create Date: 2026-10-02 14:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "g9c3d5e2f1b4"
down_revision: str | Sequence[str] | None = "f8b2c4d1e3a5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create dependency_edges table and extend project_components."""
    # 1. Create dependency_edges table
    op.create_table(
        "dependency_edges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("parent_name", sa.String(length=255), nullable=False),
        sa.Column("parent_version", sa.String(length=100), nullable=True),
        sa.Column("child_name", sa.String(length=255), nullable=False),
        sa.Column("child_version", sa.String(length=100), nullable=True),
        sa.Column("scope", sa.String(length=30), server_default="runtime", nullable=False),
        sa.Column("requirement", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_dep_edges_project",
        "dependency_edges",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_dep_edges_parent",
        "dependency_edges",
        ["parent_name"],
        unique=False,
    )
    op.create_index(
        "ix_dep_edges_child",
        "dependency_edges",
        ["child_name"],
        unique=False,
    )

    # 2. Add dependency intelligence columns to project_components
    with op.batch_alter_table("project_components") as batch_op:
        batch_op.add_column(
            sa.Column(
                "is_direct",
                sa.Boolean(),
                server_default=sa.text("1"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "dependency_type",
                sa.String(length=20),
                server_default="direct",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "scope",
                sa.String(length=20),
                server_default="runtime",
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("manifest_source", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("lockfile_source", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("parent_name", sa.String(length=255), nullable=True))
        batch_op.add_column(
            sa.Column("dependency_path", sa.Text(), server_default="[]", nullable=False)
        )
        batch_op.create_index(
            "ix_components_dep_type",
            ["dependency_type"],
            unique=False,
        )


def downgrade() -> None:
    """Drop dependency_edges table and remove columns from project_components."""
    op.drop_table("dependency_edges")
    with op.batch_alter_table("project_components") as batch_op:
        batch_op.drop_index("ix_components_dep_type")
        batch_op.drop_column("dependency_path")
        batch_op.drop_column("parent_name")
        batch_op.drop_column("lockfile_source")
        batch_op.drop_column("manifest_source")
        batch_op.drop_column("scope")
        batch_op.drop_column("dependency_type")
        batch_op.drop_column("is_direct")
