"""Add container image and layer intelligence tables

Revision ID: i2e5f7a3b8c9
Revises: h1d4e6f2a7b8
Create Date: 2026-10-03 14:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "i2e5f7a3b8c9"
down_revision: str | Sequence[str] | None = "h1d4e6f2a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create container_images, container_layers, and container_image_components tables."""
    # 1. container_images
    op.create_table(
        "container_images",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("reference", sa.String(length=255), nullable=False),
        sa.Column("digest", sa.String(length=100), nullable=True),
        sa.Column("architecture", sa.String(length=50), server_default="amd64", nullable=False),
        sa.Column("os", sa.String(length=100), server_default="linux", nullable=False),
        sa.Column("os_family", sa.String(length=50), nullable=True),
        sa.Column("os_version", sa.String(length=50), nullable=True),
        sa.Column("os_codename", sa.String(length=50), nullable=True),
        sa.Column(
            "source_type", sa.String(length=50), server_default="docker_archive", nullable=False
        ),
        sa.Column("source_path", sa.String(length=500), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.Text(), server_default="{}", nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", name="uq_container_images_scan_id"),
    )
    op.create_index("ix_container_images_scan", "container_images", ["scan_id"], unique=False)
    op.create_index("ix_container_images_digest", "container_images", ["digest"], unique=False)
    op.create_index(
        "ix_container_images_reference", "container_images", ["reference"], unique=False
    )

    # 2. container_layers
    op.create_table(
        "container_layers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("image_id", sa.String(length=36), nullable=False),
        sa.Column("layer_index", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(length=100), nullable=False),
        sa.Column("size_bytes", sa.Integer(), server_default="0", nullable=False),
        sa.Column("media_type", sa.String(length=100), server_default="", nullable=False),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.Text(), server_default="{}", nullable=False),
        sa.ForeignKeyConstraint(["image_id"], ["container_images.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_container_layers_image", "container_layers", ["image_id"], unique=False)
    op.create_index("ix_container_layers_digest", "container_layers", ["digest"], unique=False)

    # 3. container_image_components
    op.create_table(
        "container_image_components",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("image_id", sa.String(length=36), nullable=False),
        sa.Column("component_id", sa.String(length=36), nullable=False),
        sa.Column("layer_id", sa.String(length=36), nullable=True),
        sa.Column("container_path", sa.String(length=500), server_default="", nullable=False),
        sa.Column("stage", sa.String(length=100), server_default="runtime", nullable=False),
        sa.Column("package_manager", sa.String(length=50), nullable=True),
        sa.Column("is_runtime", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("metadata_json", sa.Text(), server_default="{}", nullable=False),
        sa.ForeignKeyConstraint(["image_id"], ["container_images.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["project_components.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["layer_id"], ["container_layers.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_cont_img_comp_image", "container_image_components", ["image_id"], unique=False
    )
    op.create_index(
        "ix_cont_img_comp_component", "container_image_components", ["component_id"], unique=False
    )
    op.create_index(
        "ix_cont_img_comp_layer", "container_image_components", ["layer_id"], unique=False
    )


def downgrade() -> None:
    """Drop container_image_components, container_layers, and container_images tables."""
    op.drop_index("ix_cont_img_comp_layer", table_name="container_image_components")
    op.drop_index("ix_cont_img_comp_component", table_name="container_image_components")
    op.drop_index("ix_cont_img_comp_image", table_name="container_image_components")
    op.drop_table("container_image_components")

    op.drop_index("ix_container_layers_digest", table_name="container_layers")
    op.drop_index("ix_container_layers_image", table_name="container_layers")
    op.drop_table("container_layers")

    op.drop_index("ix_container_images_reference", table_name="container_images")
    op.drop_index("ix_container_images_digest", table_name="container_images")
    op.drop_index("ix_container_images_scan", table_name="container_images")
    op.drop_table("container_images")
