"""Persistence model for the outbound integration layer.

The table lives in this package (not in ``app/db/models.py``) because that module
is owned by a different change in flight. It uses the same
``app.db.base.Base``, so:

* Alembic migration ``20260909_0016`` creates it, and
* ``Base.metadata.create_all`` picks it up **as long as this module has been
  imported**. The coordinator must therefore add one line to
  ``app/db/models.py``::

      from app.integrations import models as integration_models  # noqa: F401

  That single line registers ``integration_deliveries`` for every code path that
  calls ``Base.metadata.create_all`` (``EVONIDS_AUTO_CREATE_DB=true``, tests,
  ``alembic autogenerate``). Until it is added, ``app.integrations.recorder``
  imports this module itself before writing, so the running API still works; only
  a foreign ``create_all`` in another process would miss the table.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin

DELIVERY_STATES = ("delivered", "failed", "skipped")


class IntegrationDelivery(TimestampMixin, Base):
    """One row per (connector, dedup key): the live state of an outbound event.

    A retried or re-dispatched event updates the existing row (``attempts``
    accumulates, ``state`` / ``last_error`` / summaries are overwritten with the
    latest outcome) so the table always answers "what is the current state of
    this event for this connector?" without unbounded growth.
    """

    __tablename__ = "integration_deliveries"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    connector: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    object_id: Mapped[str] = mapped_column(String(96), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    response_summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("uq_integration_delivery_target", "connector", "dedup_key", unique=True),
        Index("ix_integration_delivery_state", "state", "updated_at"),
        Index("ix_integration_delivery_object", "event_type", "object_id"),
        Index("ix_integration_delivery_connector", "connector", "updated_at"),
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "connector": self.connector,
            "eventType": self.event_type,
            "objectId": self.object_id,
            "dedupKey": self.dedup_key,
            "state": self.state,
            "attempts": self.attempts,
            "lastError": self.last_error,
            "requestSummary": self.request_summary or {},
            "responseSummary": self.response_summary or {},
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
        }


__all__ = ["DELIVERY_STATES", "IntegrationDelivery"]
