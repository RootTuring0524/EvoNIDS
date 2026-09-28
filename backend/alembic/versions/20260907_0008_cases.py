"""Add case management core (cases, case_alerts, case_timeline_events).

Revision ID: 20260907_0008
Revises: 20260907_0007
Create Date: 2026-09-07
"""

from alembic import op
import sqlalchemy as sa


revision = "20260907_0008"
down_revision = "20260907_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("assignee", sa.String(length=120), nullable=True),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("highest_risk_score", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cases_status_updated", "cases", ["status", "updated_at"])
    op.create_index("ix_cases_severity_updated", "cases", ["severity", "updated_at"])

    op.create_table(
        "case_alerts",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("case_id", sa.String(length=96), nullable=False),
        sa.Column("alert_id", sa.String(length=96), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("uq_case_alert", "case_alerts", ["case_id", "alert_id"], unique=True)

    op.create_table(
        "case_timeline_events",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("case_id", sa.String(length=96), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_case_timeline_created", "case_timeline_events", ["case_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_case_timeline_created", table_name="case_timeline_events")
    op.drop_table("case_timeline_events")
    op.drop_index("uq_case_alert", table_name="case_alerts")
    op.drop_table("case_alerts")
    op.drop_index("ix_cases_severity_updated", table_name="cases")
    op.drop_index("ix_cases_status_updated", table_name="cases")
    op.drop_table("cases")
