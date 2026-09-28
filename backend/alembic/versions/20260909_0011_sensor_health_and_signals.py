"""Sensor identity/health, ingestion batch idempotency and explainable detection signals.

Revision ID: 20260909_0011
Revises: 20260909_0010
Create Date: 2026-09-09
"""

from alembic import op
import sqlalchemy as sa


revision = "20260909_0011"
down_revision = "20260909_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Collector identity/health. All columns are nullable or defaulted so the
    # migration is safe on a populated deployment.
    op.add_column("sensors", sa.Column("agent_version", sa.String(length=80), nullable=True))
    op.add_column("sensors", sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("sensors", sa.Column("clock_skew_seconds", sa.Float(), nullable=True))
    op.add_column(
        "sensors", sa.Column("dropped_events", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("sensors", sa.Column("spool_depth", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(
        "sensors",
        sa.Column("expected_interval_seconds", sa.Integer(), nullable=False, server_default="60"),
    )
    op.add_column("sensors", sa.Column("capabilities", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("sensors", sa.Column("enrolled_key_id", sa.String(length=96), nullable=True))
    op.add_column(
        "sensors", sa.Column("certificate_fingerprint", sa.String(length=128), nullable=True)
    )
    # SQLite (used by the CI migration gate and local dev) cannot ALTER-add a
    # foreign key; PostgreSQL - the production database - gets the real
    # constraint. Application code resolves enrolled_key_id through the API-key
    # service, so a missing constraint on SQLite cannot silently authorise a key.
    if op.get_bind().dialect.name != "sqlite":
        op.create_foreign_key(
            "fk_sensors_enrolled_key", "sensors", "api_keys", ["enrolled_key_id"], ["id"]
        )

    op.create_table(
        "ingestion_batches",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("sensor_id", sa.String(length=80), nullable=False),
        sa.Column("batch_id", sa.String(length=120), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("encoding", sa.String(length=16), nullable=False),
        sa.Column("payload_bytes", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("accepted_count", sa.Integer(), nullable=False),
        sa.Column("duplicate_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), nullable=False),
        sa.Column("created_flows", sa.Integer(), nullable=False),
        sa.Column("created_alerts", sa.Integer(), nullable=False),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("clock_skew_seconds", sa.Float(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["sensor_id"], ["sensors.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_ingestion_batch_sensor", "ingestion_batches", ["sensor_id", "batch_id"], unique=True
    )
    op.create_index("ix_ingestion_batch_received", "ingestion_batches", ["received_at"])

    op.create_table(
        "detection_signals",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_id", sa.String(length=96), nullable=True),
        sa.Column("alert_id", sa.String(length=96), nullable=True),
        sa.Column("sensor_id", sa.String(length=80), nullable=False),
        sa.Column("channel", sa.String(length=24), nullable=False),
        sa.Column("channel_version", sa.String(length=96), nullable=False),
        sa.Column("model_id", sa.String(length=96), nullable=True),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("calibrated_score", sa.Float(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("uncertainty", sa.Float(), nullable=False),
        sa.Column("feature_version", sa.String(length=32), nullable=False),
        sa.Column("feature_source", sa.String(length=24), nullable=False),
        sa.Column("imputed_features", sa.JSON(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("degraded", sa.Boolean(), nullable=False),
        sa.Column("degraded_reason", sa.String(length=160), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.ForeignKeyConstraint(["model_id"], ["model_versions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_detection_signal_flow", "detection_signals", ["flow_id", "created_at"])
    op.create_index("ix_detection_signal_channel", "detection_signals", ["channel", "created_at"])
    op.create_index("ix_detection_signal_decision", "detection_signals", ["decision", "created_at"])

    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_id", sa.String(length=96), nullable=True),
        sa.Column("alert_id", sa.String(length=96), nullable=True),
        sa.Column("sensor_id", sa.String(length=80), nullable=False),
        sa.Column("signal_ids", sa.JSON(), nullable=False),
        sa.Column("inputs", sa.JSON(), nullable=False),
        sa.Column("weights", sa.JSON(), nullable=False),
        sa.Column("final_score", sa.Float(), nullable=False),
        sa.Column("uncertainty", sa.Float(), nullable=False),
        sa.Column("decision", sa.String(length=24), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("degraded_reasons", sa.JSON(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_risk_assessment_flow", "risk_assessments", ["flow_id", "created_at"])
    op.create_index("ix_risk_assessment_decision", "risk_assessments", ["decision", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_risk_assessment_decision", table_name="risk_assessments")
    op.drop_index("ix_risk_assessment_flow", table_name="risk_assessments")
    op.drop_table("risk_assessments")
    op.drop_index("ix_detection_signal_decision", table_name="detection_signals")
    op.drop_index("ix_detection_signal_channel", table_name="detection_signals")
    op.drop_index("ix_detection_signal_flow", table_name="detection_signals")
    op.drop_table("detection_signals")
    op.drop_index("ix_ingestion_batch_received", table_name="ingestion_batches")
    op.drop_index("uq_ingestion_batch_sensor", table_name="ingestion_batches")
    op.drop_table("ingestion_batches")
    for column in (
        "certificate_fingerprint",
        "enrolled_key_id",
        "capabilities",
        "expected_interval_seconds",
        "spool_depth",
        "dropped_events",
        "clock_skew_seconds",
        "last_heartbeat_at",
        "agent_version",
    ):
        op.drop_column("sensors", column)
