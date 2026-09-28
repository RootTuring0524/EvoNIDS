"""LLM gateway tables, hybrid-RAG columns and analyst feedback.

Revision ID: 20260909_0012
Revises: 20260909_0011
Create Date: 2026-09-09
"""

from alembic import op
import sqlalchemy as sa


revision = "20260909_0012"
down_revision = "20260909_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- hybrid retrieval support on the knowledge table -------------------
    op.add_column(
        "knowledge_evidence",
        sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default="default"),
    )
    op.add_column("knowledge_evidence", sa.Column("embedding", sa.JSON(), nullable=True))
    op.add_column(
        "knowledge_evidence", sa.Column("embedding_model", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "knowledge_evidence",
        sa.Column("embedding_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "knowledge_evidence", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index(
        "ix_knowledge_workspace_allowed", "knowledge_evidence", ["workspace_id", "allowed"]
    )

    op.create_table(
        "investigation_runs",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("alert_id", sa.String(length=96), nullable=True),
        sa.Column("case_id", sa.String(length=96), nullable=True),
        sa.Column("requested_by", sa.String(length=120), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("mode", sa.String(length=24), nullable=False),
        sa.Column("provider", sa.String(length=48), nullable=True),
        sa.Column("model_id", sa.String(length=120), nullable=True),
        sa.Column("prompt_template_version", sa.String(length=64), nullable=False),
        sa.Column("tool_registry_version", sa.String(length=64), nullable=False),
        sa.Column("knowledge_version", sa.String(length=64), nullable=True),
        sa.Column("max_tool_calls", sa.Integer(), nullable=False, server_default="6"),
        sa.Column("budget_usd", sa.Float(), nullable=False),
        sa.Column("input_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("retrieval", sa.JSON(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("uncertainty", sa.Float(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False),
        sa.Column("completion_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_estimate_usd", sa.Float(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("degraded_reasons", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigation_alert_created", "investigation_runs", ["alert_id", "created_at"])
    op.create_index("ix_investigation_state_created", "investigation_runs", ["state", "created_at"])

    op.create_table(
        "investigation_claims",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("run_id", sa.String(length=96), nullable=False),
        sa.Column("claim_index", sa.Integer(), nullable=False),
        sa.Column("claim_type", sa.String(length=24), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("uncertainty", sa.Float(), nullable=False),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("rejection_reason", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["investigation_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigation_claim_run", "investigation_claims", ["run_id", "claim_index"])

    op.create_table(
        "tool_executions",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("run_id", sa.String(length=96), nullable=False),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("tool_version", sa.String(length=32), nullable=False),
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("result_summary", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("error", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["investigation_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tool_execution_run", "tool_executions", ["run_id", "created_at"])

    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("object_type", sa.String(length=24), nullable=False),
        sa.Column("object_id", sa.String(length=96), nullable=False),
        sa.Column("verdict", sa.String(length=24), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyst_feedback_object", "analyst_feedback", ["object_type", "object_id"])


def downgrade() -> None:
    op.drop_index("ix_analyst_feedback_object", table_name="analyst_feedback")
    op.drop_table("analyst_feedback")
    op.drop_index("ix_tool_execution_run", table_name="tool_executions")
    op.drop_table("tool_executions")
    op.drop_index("ix_investigation_claim_run", table_name="investigation_claims")
    op.drop_table("investigation_claims")
    op.drop_index("ix_investigation_state_created", table_name="investigation_runs")
    op.drop_index("ix_investigation_alert_created", table_name="investigation_runs")
    op.drop_table("investigation_runs")
    op.drop_index("ix_knowledge_workspace_allowed", table_name="knowledge_evidence")
    for column in (
        "expires_at",
        "embedding_updated_at",
        "embedding_model",
        "embedding",
        "workspace_id",
    ):
        op.drop_column("knowledge_evidence", column)
