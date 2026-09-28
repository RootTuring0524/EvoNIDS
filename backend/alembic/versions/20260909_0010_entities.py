"""Add entity discovery and entity relations.

Revision ID: 20260909_0010
Revises: 20260907_0009
Create Date: 2026-09-09
"""

from alembic import op
import sqlalchemy as sa


revision = "20260909_0010"
down_revision = "20260907_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entities",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("entity_type", sa.String(length=24), nullable=False),
        sa.Column("value", sa.String(length=160), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("sensor_ids", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("uq_entity_type_value", "entities", ["entity_type", "value"], unique=True)
    op.create_index("ix_entity_last_seen", "entities", ["last_seen_at"])

    op.create_table(
        "entity_relations",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("relation_type", sa.String(length=32), nullable=False),
        sa.Column("entity_a", sa.String(length=96), nullable=False),
        sa.Column("entity_b", sa.String(length=96), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_relation_pair", "entity_relations", ["relation_type", "entity_a", "entity_b"], unique=True
    )


def downgrade() -> None:
    op.drop_index("uq_relation_pair", table_name="entity_relations")
    op.drop_table("entity_relations")
    op.drop_index("ix_entity_last_seen", table_name="entities")
    op.drop_index("uq_entity_type_value", table_name="entities")
    op.drop_table("entities")
