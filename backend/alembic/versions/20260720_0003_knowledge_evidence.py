"""Add persistent RAG evidence registry.

Revision ID: 20260720_0003
Revises: 20260719_0002
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "20260720_0003"
down_revision = "20260719_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "knowledge_evidence",
        sa.Column("id", sa.String(96), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("trust", sa.String(16), nullable=False),
        sa.Column("excerpt", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("prompt_injection_risk", sa.String(16), nullable=False),
        sa.Column("keywords", sa.JSON(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_knowledge_source",
        "knowledge_evidence",
        ["source_type", "source_id"],
    )
    op.create_index(
        "ix_knowledge_trust_allowed",
        "knowledge_evidence",
        ["trust", "allowed"],
    )


def downgrade() -> None:
    op.drop_table("knowledge_evidence")
