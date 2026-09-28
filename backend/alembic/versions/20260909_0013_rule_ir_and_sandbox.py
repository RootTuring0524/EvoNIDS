"""Rule IR versions, sandbox validation runs, sensor groups and deployments.

Revision ID: 20260909_0013
Revises: 20260909_0012
Create Date: 2026-09-09
"""

from alembic import op
import sqlalchemy as sa


revision = "20260909_0013"
down_revision = "20260909_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_ir_versions",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("rule_id", sa.String(length=96), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("sid", sa.Integer(), nullable=False),
        sa.Column("rev", sa.Integer(), nullable=False),
        sa.Column("ir_digest", sa.String(length=64), nullable=False),
        sa.Column("ir_document", sa.JSON(), nullable=False),
        sa.Column("suricata_text", sa.Text(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("uq_rule_ir_version", "rule_ir_versions", ["rule_id", "version"], unique=True)
    op.create_index("ix_rule_ir_sid", "rule_ir_versions", ["sid"])

    op.create_table(
        "rule_sandbox_runs",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("rule_id", sa.String(length=96), nullable=False),
        sa.Column("rule_version_id", sa.String(length=96), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("suricata_available", sa.Boolean(), nullable=False),
        sa.Column("suricata_version", sa.String(length=64), nullable=True),
        sa.Column("syntax_passed", sa.Boolean(), nullable=True),
        sa.Column("executor_version", sa.String(length=64), nullable=False),
        sa.Column("normal_pcap", sa.Text(), nullable=True),
        sa.Column("malicious_pcap", sa.Text(), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("blocked_reason", sa.String(length=255), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rule_sandbox_rule", "rule_sandbox_runs", ["rule_id", "created_at"])
    op.create_index("ix_rule_sandbox_status", "rule_sandbox_runs", ["status", "created_at"])

    op.create_table(
        "sensor_groups",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("sensor_ids", sa.JSON(), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "rule_deployments",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("rule_id", sa.String(length=96), nullable=False),
        sa.Column("rule_version_id", sa.String(length=96), nullable=False),
        sa.Column("sensor_group_id", sa.String(length=96), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("deployed_by", sa.String(length=120), nullable=False),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_reason", sa.Text(), nullable=True),
        sa.Column("monitoring", sa.JSON(), nullable=False),
        sa.Column("previous_version_id", sa.String(length=96), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rule_deployment_rule", "rule_deployments", ["rule_id", "created_at"])
    op.create_index("ix_rule_deployment_state", "rule_deployments", ["state", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_rule_deployment_state", table_name="rule_deployments")
    op.drop_index("ix_rule_deployment_rule", table_name="rule_deployments")
    op.drop_table("rule_deployments")
    op.drop_table("sensor_groups")
    op.drop_index("ix_rule_sandbox_status", table_name="rule_sandbox_runs")
    op.drop_index("ix_rule_sandbox_rule", table_name="rule_sandbox_runs")
    op.drop_table("rule_sandbox_runs")
    op.drop_index("ix_rule_ir_sid", table_name="rule_ir_versions")
    op.drop_index("uq_rule_ir_version", table_name="rule_ir_versions")
    op.drop_table("rule_ir_versions")
