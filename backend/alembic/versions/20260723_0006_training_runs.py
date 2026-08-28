"""Add real baseline training run registry.

Revision ID: 20260723_0006
Revises: 20260722_0005
Create Date: 2026-07-23
"""

from alembic import op
import sqlalchemy as sa


revision = "20260723_0006"
down_revision = "20260722_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "training_runs",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("dataset_id", sa.String(96), sa.ForeignKey("dataset_assets.id"), nullable=False),
        sa.Column("model_id", sa.String(96), sa.ForeignKey("model_versions.id")),
        sa.Column("task", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("requested_by", sa.String(120), nullable=False),
        sa.Column("dataset_sha256", sa.String(64), nullable=False),
        sa.Column("feature_version", sa.String(32), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("samples_seen", sa.BigInteger(), nullable=False),
        sa.Column("samples_used", sa.BigInteger(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("artifact_uri", sa.Text()),
        sa.Column("artifact_sha256", sa.String(64)),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_training_state_created", "training_runs", ["state", "created_at"])
    op.create_index("ix_training_dataset_created", "training_runs", ["dataset_id", "created_at"])


def downgrade() -> None:
    op.drop_table("training_runs")
