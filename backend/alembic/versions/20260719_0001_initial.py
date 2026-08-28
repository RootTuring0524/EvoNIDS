"""Create the initial EvoNIDS operational tables.

Revision ID: 20260719_0001
Revises:
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "20260719_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sensors",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("location", sa.String(255)),
        sa.Column("version", sa.String(80)),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "flows",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("external_id", sa.String(128), nullable=False),
        sa.Column("sensor_id", sa.String(80), sa.ForeignKey("sensors.id"), nullable=False),
        sa.Column("time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("destination", sa.String(64), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(24), nullable=False),
        sa.Column("service", sa.String(64), nullable=False),
        sa.Column("activity", sa.String(255), nullable=False),
        sa.Column("packets", sa.Integer(), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(24), nullable=False),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("feature_version", sa.String(32), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("raw_reference", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_flows_time", "flows", ["time"])
    op.create_index("ix_flows_src_dst", "flows", ["source", "destination"])
    op.create_index("uq_flows_sensor_external", "flows", ["sensor_id", "external_id"], unique=True)
    op.create_table(
        "model_versions",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("role", sa.String(255), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("artifact_uri", sa.Text()),
        sa.Column("feature_version", sa.String(32), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "inferences",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("flow_id", sa.String(96), sa.ForeignKey("flows.id"), nullable=False),
        sa.Column("transformer_model_id", sa.String(96), sa.ForeignKey("model_versions.id")),
        sa.Column("autoencoder_model_id", sa.String(96), sa.ForeignKey("model_versions.id")),
        sa.Column("transformer_output", sa.JSON(), nullable=False),
        sa.Column("autoencoder_output", sa.JSON(), nullable=False),
        sa.Column("fusion_output", sa.JSON(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("flow_id", sa.String(96), sa.ForeignKey("flows.id")),
        sa.Column("inference_id", sa.String(96), sa.ForeignKey("inferences.id")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("source_ip", sa.String(64), nullable=False),
        sa.Column("destination_ip", sa.String(64), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(24), nullable=False),
        sa.Column("sensor", sa.String(96), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detector", sa.String(160), nullable=False),
        sa.Column("owner", sa.String(120)),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"])
    op.create_table(
        "rules",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("coverage", sa.String(255), nullable=False),
        sa.Column("hit_rate", sa.Float(), nullable=False),
        sa.Column("false_positive_rate", sa.Float(), nullable=False),
        sa.Column("author", sa.String(120), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("quality_score", sa.Float()),
        sa.Column("active_version_id", sa.String(96)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "rule_versions",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("rule_id", sa.String(96), sa.ForeignKey("rules.id"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("parent_version_id", sa.String(96), sa.ForeignKey("rule_versions.id")),
        sa.Column("structured_rule", sa.JSON(), nullable=False),
        sa.Column("generated_by", sa.String(120), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_rule_version", "rule_versions", ["rule_id", "version"], unique=True)
    op.create_table(
        "rule_validations",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("rule_version_id", sa.String(96), sa.ForeignKey("rule_versions.id"), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("replay_dataset_version", sa.String(96), nullable=False),
        sa.Column("executor_version", sa.String(64), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(120), nullable=False),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("object_type", sa.String(80), nullable=False),
        sa.Column("object_id", sa.String(96), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("request_id", sa.String(96)),
        sa.Column("before_state", sa.JSON()),
        sa.Column("after_state", sa.JSON()),
        sa.Column("note", sa.Text()),
    )
    op.create_index("ix_audit_created", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("rule_validations")
    op.drop_table("rule_versions")
    op.drop_table("rules")
    op.drop_table("alerts")
    op.drop_table("inferences")
    op.drop_table("model_versions")
    op.drop_table("flows")
    op.drop_table("sensors")

