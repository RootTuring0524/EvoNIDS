"""Add generic evidence registry (evidence_records, evidence_artifacts).

Revision ID: 20260907_0009
Revises: 20260907_0008
Create Date: 2026-09-07
"""

from alembic import op
import sqlalchemy as sa


revision = "20260907_0009"
down_revision = "20260907_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_records",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("sensor_id", sa.String(length=80), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("integrity", sa.String(length=16), nullable=False),
        sa.Column("data_missing", sa.String(length=32), nullable=False),
        sa.Column("parser_version", sa.String(length=64), nullable=False),
        sa.Column("redacted", sa.Boolean(), nullable=False),
        sa.Column("source_ref_type", sa.String(length=24), nullable=True),
        sa.Column("source_ref_id", sa.String(length=96), nullable=True),
        sa.Column("artifact_size_bytes", sa.Integer(), nullable=False),
        sa.Column("fields", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_sensor_time", "evidence_records", ["sensor_id", "observed_at"])
    op.create_index("ix_evidence_content_hash", "evidence_records", ["content_sha256"])

    op.create_table(
        "evidence_artifacts",
        sa.Column("evidence_id", sa.String(length=96), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content_text", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_records.id"]),
        sa.PrimaryKeyConstraint("evidence_id"),
    )


def downgrade() -> None:
    op.drop_table("evidence_artifacts")
    op.drop_index("ix_evidence_content_hash", table_name="evidence_records")
    op.drop_index("ix_evidence_sensor_time", table_name="evidence_records")
    op.drop_table("evidence_records")
