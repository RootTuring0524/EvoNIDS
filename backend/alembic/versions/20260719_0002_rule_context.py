"""Persist rule lineage and validation context.

Revision ID: 20260719_0002
Revises: 20260719_0001
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "20260719_0002"
down_revision = "20260719_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "rules",
        sa.Column("source_alert_id", sa.String(96), nullable=False, server_default=""),
    )
    op.add_column(
        "rules",
        sa.Column("diff_reason", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "rules",
        sa.Column("expected_coverage_change", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "rules",
        sa.Column("false_positive_risk", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("rules", "false_positive_risk")
    op.drop_column("rules", "expected_coverage_change")
    op.drop_column("rules", "diff_reason")
    op.drop_column("rules", "source_alert_id")
