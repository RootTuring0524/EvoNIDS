"""Add operational indexes for sensor health and alert correlation.

Revision ID: 20260721_0004
Revises: 20260720_0003
Create Date: 2026-07-21
"""

from alembic import op


revision = "20260721_0004"
down_revision = "20260720_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_sensors_state_last_seen", "sensors", ["state", "last_seen_at"])
    op.create_index("ix_alerts_sensor_timestamp", "alerts", ["sensor", "timestamp"])


def downgrade() -> None:
    op.drop_index("ix_alerts_sensor_timestamp", table_name="alerts")
    op.drop_index("ix_sensors_state_last_seen", table_name="sensors")
