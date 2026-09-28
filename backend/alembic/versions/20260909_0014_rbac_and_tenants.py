"""Tenant/workspace scope for cases, evidence, detection signals and investigations.

Revision ID: 20260909_0014
Revises: 20260909_0013
Create Date: 2026-09-09

Adds a ``workspace_id`` column to the four tenant-scoped tables plus the indexes
that make the mandatory read filter cheap. Every existing row is stamped with
``default`` (server default), which is also the workspace the identity layer
assigns to a principal that carries no workspace claim, so pre-existing data
stays reachable and nothing is orphaned by the upgrade.

SQLite cannot ``ALTER TABLE ... ADD CONSTRAINT``, so the foreign key to
``workspaces`` is created only on dialects that support it (PostgreSQL). The
column itself is added everywhere.
"""
from alembic import op
import sqlalchemy as sa


revision = "20260909_0014"
down_revision = "20260909_0013"
branch_labels = None
depends_on = None

TENANT_TABLES: tuple[tuple[str, str], ...] = (
    # (table, index name) - one workspace index per tenant-scoped table.
    ("cases", "ix_cases_workspace_updated"),
    ("evidence_records", "ix_evidence_workspace_observed"),
    ("detection_signals", "ix_detection_signal_workspace_created"),
    ("risk_assessments", "ix_risk_assessment_workspace_created"),
    ("investigation_runs", "ix_investigation_workspace_created"),
)

WORKSPACE_INDEX_COLUMNS: dict[str, list[str]] = {
    "cases": ["workspace_id", "updated_at"],
    "evidence_records": ["workspace_id", "observed_at"],
    "detection_signals": ["workspace_id", "created_at"],
    "risk_assessments": ["workspace_id", "created_at"],
    "investigation_runs": ["workspace_id", "created_at"],
}


def upgrade() -> None:
    for table, index_name in TENANT_TABLES:
        op.add_column(
            table,
            sa.Column(
                "workspace_id",
                sa.String(length=64),
                nullable=False,
                server_default="default",
            ),
        )
        op.create_index(index_name, table, WORKSPACE_INDEX_COLUMNS[table])

    # The reference table for tenant metadata is intentionally not created here:
    # a workspace is an identifier carried by the identity provider and by these
    # columns. On PostgreSQL we still enforce referential integrity through a
    # lightweight registry table so a typo cannot create a phantom tenant.
    if op.get_bind().dialect.name != "sqlite":
        op.create_table(
            "workspaces",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.execute(
            sa.text(
                "INSERT INTO workspaces (id, name, created_at, updated_at) "
                "VALUES ('default', 'Default workspace', NOW(), NOW()) "
                "ON CONFLICT (id) DO NOTHING"
            )
        )
        for table, _ in TENANT_TABLES:
            op.create_foreign_key(
                f"fk_{table}_workspace",
                table,
                "workspaces",
                ["workspace_id"],
                ["id"],
            )


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        for table, _ in TENANT_TABLES:
            op.drop_constraint(f"fk_{table}_workspace", table, type_="foreignkey")
        op.drop_table("workspaces")
    for table, index_name in reversed(TENANT_TABLES):
        op.drop_index(index_name, table_name=table)
        op.drop_column(table, "workspace_id")
