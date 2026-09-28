"""Outbound integration deliveries ledger (Phase 10).

Revision ID: 20260909_0016
Revises: 20260909_0013
Create Date: 2026-09-09

``down_revision`` is ``20260909_0013`` (the current head of this branch in this
checkout) rather than ``20260909_0015``: revision ``20260909_0015`` does not exist
in ``alembic/versions`` at the time this migration was written, and pointing at a
missing revision would break the whole chain. If ``20260909_0015`` lands later,
re-parent this file by changing the two ``down_revision`` occurrences below.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260909_0016"
down_revision = "20260909_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integration_deliveries",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("connector", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("object_id", sa.String(length=96), nullable=False),
        sa.Column("dedup_key", sa.String(length=255), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("request_summary", sa.JSON(), nullable=False),
        sa.Column("response_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_integration_delivery_target",
        "integration_deliveries",
        ["connector", "dedup_key"],
        unique=True,
    )
    op.create_index(
        "ix_integration_delivery_state",
        "integration_deliveries",
        ["state", "updated_at"],
    )
    op.create_index(
        "ix_integration_delivery_object",
        "integration_deliveries",
        ["event_type", "object_id"],
    )
    op.create_index(
        "ix_integration_delivery_connector",
        "integration_deliveries",
        ["connector", "updated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_integration_delivery_connector", table_name="integration_deliveries")
    op.drop_index("ix_integration_delivery_object", table_name="integration_deliveries")
    op.drop_index("ix_integration_delivery_state", table_name="integration_deliveries")
    op.drop_index("uq_integration_delivery_target", table_name="integration_deliveries")
    op.drop_table("integration_deliveries")
