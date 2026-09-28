"""Add hashed, scoped API keys for machine identities.

Revision ID: 20260907_0007
Revises: 20260723_0006
Create Date: 2026-09-07
"""

from alembic import op
import sqlalchemy as sa


revision = "20260907_0007"
down_revision = "20260723_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("scope", sa.String(length=24), nullable=False),
        sa.Column("key_hash", sa.String(length=160), nullable=False),
        sa.Column("prefix", sa.String(length=24), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_keys_scope_enabled", "api_keys", ["scope", "enabled"])
    op.create_index("uq_api_keys_prefix", "api_keys", ["prefix"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_api_keys_prefix", table_name="api_keys")
    op.drop_index("ix_api_keys_scope_enabled", table_name="api_keys")
    op.drop_table("api_keys")
