"""Integration administration API (Phase 10).

All endpoints are administrative: the outbound integration layer moves detection
data to third-party systems, so listing configuration, triggering a real test
delivery and reading the delivery ledger all require the admin credential.

Endpoints:

* ``GET /integrations`` — connector list with enabled state, capabilities, health
  and the dispatcher's honest health report;
* ``POST /integrations/{name}/test`` — send a clearly-labelled **synthetic**
  event through the real connector and return the real result;
* ``GET /integrations/deliveries`` — the delivery ledger, filterable;
* ``POST /integrations/events`` — manually dispatch an event for an existing
  alert or case.

Nothing here fabricates a result: a delivery that fails is returned as ``failed``
with its error, and a connector that is not configured is a 404.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.security import request_actor, require_admin_token
from app.db.models import Alert, Case, EvidenceRecord
from app.db.session import get_db
from app.integrations.base import CAPABILITY_ALERT, CAPABILITY_CASE
from app.integrations.dispatcher import synthetic_test_event
from app.integrations.factory import get_dispatcher
from app.integrations.models import IntegrationDelivery
from app.integrations.payloads import alert_to_notification, case_to_notification


router = APIRouter()


def _camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class _ApiModel(BaseModel):
    """Same alias convention as ``app.schemas.api.ApiModel`` (camelCase on the wire)."""

    model_config = ConfigDict(from_attributes=True, alias_generator=_camel, populate_by_name=True)


class IntegrationTestRequest(_ApiModel):
    """Optional overrides for the synthetic self-test event."""

    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    note: str = Field(default="", max_length=200)


class IntegrationEventRequest(_ApiModel):
    """Manually dispatch one alert or case through the enabled connectors."""

    object_type: Literal["alert", "case"]
    object_id: str = Field(min_length=1, max_length=96)
    connectors: list[str] = Field(default_factory=list)


class IntegrationTestResponse(_ApiModel):
    connector: str
    synthetic: bool = True
    outcome: dict[str, Any]


class DeliveryRead(_ApiModel):
    id: str
    connector: str
    event_type: str
    object_id: str
    dedup_key: str
    state: str
    attempts: int
    last_error: str | None
    request_summary: dict[str, Any]
    response_summary: dict[str, Any]
    created_at: Any
    updated_at: Any


class DeliveriesResponse(_ApiModel):
    items: list[DeliveryRead]
    total: int
    page: int
    page_size: int


@router.get("")
def list_integrations(_: Any = Depends(require_admin_token)) -> dict[str, Any]:
    """Connector inventory: what exists, what is enabled, what it can carry."""
    dispatcher = get_dispatcher()
    registry = dispatcher.registry
    report = dispatcher.health_report()
    return {
        "enabled": bool(registry.enabled()),
        "configured": bool(registry.all()),
        "note": (
            "集成框架默认关闭；未配置任何连接器时本列表为空，且不会产生任何投递记录。"
            if not registry.all()
            else "连接器由环境变量配置；enabled=false 的连接器不会被投递。"
        ),
        "connectors": registry.descriptors(),
        "health": report,
    }


@router.post("/{name}/test", response_model=IntegrationTestResponse, response_model_by_alias=True)
def test_integration(
    name: str,
    payload: IntegrationTestRequest | None = None,
    _: Any = Depends(require_admin_token),
) -> IntegrationTestResponse:
    """Send a synthetic event through one connector and return the real result."""
    dispatcher = get_dispatcher()
    connector = dispatcher.registry.get(name)
    if connector is None:
        raise HTTPException(status_code=404, detail=f"Integration connector {name!r} is not configured")
    request = payload or IntegrationTestRequest()
    event = synthetic_test_event(connector=name, severity=request.severity)
    outcome = dispatcher.deliver_to(name, event)
    return IntegrationTestResponse(
        connector=name,
        synthetic=True,
        outcome={**outcome.as_dict(), "requestedBy": request.note or "admin-console"},
    )


@router.get("/deliveries", response_model=DeliveriesResponse, response_model_by_alias=True)
def list_deliveries(
    connector: str = "",
    state: str = Query("all", pattern="^(all|delivered|failed|skipped)$"),
    object_id: str = Query("", alias="objectId"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=200),
    db: Session = Depends(get_db),
    _: Any = Depends(require_admin_token),
) -> DeliveriesResponse:
    """The delivery ledger: what was actually sent, and what actually happened."""
    filters = []
    if connector.strip():
        filters.append(IntegrationDelivery.connector == connector.strip())
    if state != "all":
        filters.append(IntegrationDelivery.state == state)
    if object_id.strip():
        filters.append(IntegrationDelivery.object_id == object_id.strip())
    total = db.scalar(select(func.count()).select_from(IntegrationDelivery).where(*filters)) or 0
    rows = db.scalars(
        select(IntegrationDelivery)
        .where(*filters)
        .order_by(desc(IntegrationDelivery.updated_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return DeliveriesResponse(
        items=[DeliveryRead.model_validate(row) for row in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.post("/events")
def dispatch_event(
    payload: IntegrationEventRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: Any = Depends(require_admin_token),
) -> dict[str, Any]:
    """Manually dispatch an existing alert or case through the connectors."""
    dispatcher = get_dispatcher()
    requested = [item for item in payload.connectors if item.strip()]
    if payload.object_type == "alert":
        alert = db.get(Alert, payload.object_id)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"Alert {payload.object_id} was not found")
        evidence = list(
            db.scalars(
                select(EvidenceRecord).where(
                    EvidenceRecord.source_ref_id.in_([alert.id, alert.flow_id or alert.id])
                )
            ).all()
        )
        event = alert_to_notification(alert, evidence=evidence)
    else:
        case = db.get(Case, payload.object_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"Case {payload.object_id} was not found")
        event = case_to_notification(case)
    outcome = dispatcher.dispatch(event, connectors=requested or None)
    return {
        "objectType": payload.object_type,
        "objectId": payload.object_id,
        "capability": CAPABILITY_ALERT if payload.object_type == "alert" else CAPABILITY_CASE,
        "requestedBy": request_actor(request, fallback="admin"),
        "outcome": outcome.as_dict(),
    }
