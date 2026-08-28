"""Add persistent dataset asset registry.

Revision ID: 20260722_0005
Revises: 20260721_0004
Create Date: 2026-07-22
"""

from alembic import op
import sqlalchemy as sa


revision = "20260722_0005"
down_revision = "20260721_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dataset_assets",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("source_uri", sa.Text(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("format", sa.String(24), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64)),
        sa.Column("label_column", sa.String(160)),
        sa.Column("normal_labels", sa.JSON(), nullable=False),
        sa.Column("total_samples", sa.BigInteger(), nullable=False),
        sa.Column("normal_samples", sa.BigInteger(), nullable=False),
        sa.Column("attack_samples", sa.BigInteger(), nullable=False),
        sa.Column("feature_count", sa.Integer(), nullable=False),
        sa.Column("missing_values", sa.BigInteger(), nullable=False),
        sa.Column("feature_columns", sa.JSON(), nullable=False),
        sa.Column("label_distribution", sa.JSON(), nullable=False),
        sa.Column("split", sa.JSON(), nullable=False),
        sa.Column("main_training_set", sa.Boolean(), nullable=False),
        sa.Column("unknown_holdout", sa.Boolean(), nullable=False),
        sa.Column("rule_replay", sa.Boolean(), nullable=False),
        sa.Column("uses", sa.JSON(), nullable=False),
        sa.Column("inspected_at", sa.DateTime(timezone=True)),
        sa.Column("inspection_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_dataset_relative_path", "dataset_assets", ["relative_path"], unique=True)
    op.create_index("ix_dataset_state_updated", "dataset_assets", ["state", "updated_at"])


def downgrade() -> None:
    op.drop_table("dataset_assets")
