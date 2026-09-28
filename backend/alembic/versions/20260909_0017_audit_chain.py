"""Tamper-evident audit chain: sequence and hash columns.

Revision ID: 20260909_0017
Revises: 20260909_0016
Create Date: 2026-09-10

Adds ``workspace_id``, ``sequence``, ``prev_hash`` and ``content_hash`` to
``audit_events`` plus the unique per-workspace sequence index. Existing rows keep
NULL chain columns and are reported as "unchained" by the verifier instead of
being silently treated as valid.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260909_0017"
down_revision = "20260909_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default="default"),
    )
    op.add_column("audit_events", sa.Column("sequence", sa.Integer(), nullable=True))
    op.add_column("audit_events", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_events", sa.Column("content_hash", sa.String(length=64), nullable=True))
    op.create_index(
        "ix_audit_workspace_sequence", "audit_events", ["workspace_id", "sequence"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_audit_workspace_sequence", table_name="audit_events")
    for column in ("content_hash", "prev_hash", "sequence", "workspace_id"):
        op.drop_column("audit_events", column)
