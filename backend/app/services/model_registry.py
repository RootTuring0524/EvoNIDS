from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlparse

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import AuditEvent, ModelVersion

RolloutState = Literal["shadow", "canary", "active", "retired"]
ROLLOUT_STATES: tuple[RolloutState, ...] = ("shadow", "canary", "active", "retired")


def artifact_state(uri: str | None) -> str:
    if not uri or not uri.strip():
        return "missing"
    value = uri.strip()
    parsed = urlparse(value)
    windows_drive_path = len(value) >= 3 and value[1] == ":" and value[2] in {"/", "\\"}
    if parsed.scheme and parsed.scheme not in {"file"} and not windows_drive_path:
        return "unverified"
    try:
        if parsed.scheme == "file":
            raw_path = unquote(parsed.path)
            if parsed.netloc:
                raw_path = f"//{parsed.netloc}{raw_path}"
            if len(raw_path) >= 3 and raw_path[0] == "/" and raw_path[2] == ":":
                raw_path = raw_path[1:]
            path = Path(raw_path)
        else:
            path = Path(value)
        return "available" if path.expanduser().resolve().is_file() else "missing"
    except (OSError, ValueError):
        return "missing"


@dataclass(frozen=True, slots=True)
class RolloutInfo:
    state: str
    updated_at: str | None
    updated_by: str | None
    note: str | None


def rollout_of(model: ModelVersion) -> RolloutInfo:
    parameters = model.parameters or {}
    rollout = parameters.get("rollout")
    if not isinstance(rollout, dict):
        # Models registered before rollout tracking are treated as shadow: they
        # may be scored, but nothing treats them as the approved production model.
        return RolloutInfo(state="shadow", updated_at=None, updated_by=None, note="未声明发布状态")
    return RolloutInfo(
        state=str(rollout.get("state", "shadow")),
        updated_at=rollout.get("updatedAt"),
        updated_by=rollout.get("updatedBy"),
        note=rollout.get("note"),
    )


def set_rollout(
    db: Session,
    *,
    model_id: str,
    state: str,
    actor: str,
    note: str | None = None,
) -> ModelVersion:
    if state not in ROLLOUT_STATES:
        raise HTTPException(status_code=422, detail=f"rollout state must be one of {list(ROLLOUT_STATES)}")
    model = db.get(ModelVersion, model_id)
    if model is None:
        raise HTTPException(status_code=404, detail=f"Model {model_id} was not found")
    if state in {"canary", "active"} and artifact_state(model.artifact_uri) != "available":
        raise HTTPException(
            status_code=409,
            detail=f"model {model_id} cannot be {state}: its artifact is {artifact_state(model.artifact_uri)}",
        )
    if state == "active":
        # Only one active model per role: the previous one becomes retired so a
        # rollback has an explicit target.
        others = db.scalars(
            select(ModelVersion).where(
                ModelVersion.role == model.role, ModelVersion.id != model.id
            )
        ).all()
        for other in others:
            if rollout_of(other).state == "active":
                other.parameters = {
                    **(other.parameters or {}),
                    "rollout": {
                        "state": "retired",
                        "updatedAt": utc_now().isoformat(),
                        "updatedBy": actor,
                        "note": f"superseded by {model_id}",
                    },
                }
    model.parameters = {
        **(model.parameters or {}),
        "rollout": {
            "state": state,
            "updatedAt": utc_now().isoformat(),
            "updatedBy": actor,
            "note": note,
        },
    }
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=actor,
            action="model.rollout",
            object_type="model_version",
            object_id=model_id,
            outcome="completed",
            request_id=None,
            before_state=None,
            after_state={"state": state, "role": model.role, "note": note},
            note="模型发布状态变更；active 表示在线检测将优先使用该制品。",
        )
    )
    db.commit()
    db.refresh(model)
    return model


def rollback_model(db: Session, *, role: str, actor: str, reason: str) -> ModelVersion:
    """Reactivate the most recently retired model for a role."""
    if len(reason.strip()) < 10:
        raise HTTPException(status_code=422, detail="rollback requires a reason of at least 10 characters")
    candidates = db.scalars(
        select(ModelVersion)
        .where(ModelVersion.role == role)
        .order_by(desc(ModelVersion.updated_at))
    ).all()
    target = next(
        (
            model
            for model in candidates
            if rollout_of(model).state == "retired" and artifact_state(model.artifact_uri) == "available"
        ),
        None,
    )
    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"no retired model with an available artifact exists for role {role}",
        )
    model = set_rollout(db, model_id=target.id, state="active", actor=actor, note=f"rollback: {reason}")
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=actor,
            action="model.rolled_back",
            object_type="model_version",
            object_id=target.id,
            outcome="completed",
            request_id=None,
            before_state=None,
            after_state={"role": role, "reason": reason},
            note="模型已回滚到上一可用版本。",
        )
    )
    db.commit()
    return model


def active_model_for_role(db: Session, role: str) -> ModelVersion | None:
    rows = db.scalars(select(ModelVersion).where(ModelVersion.role == role)).all()
    for model in rows:
        if rollout_of(model).state == "active":
            return model
    return None


def rollout_summary(db: Session) -> dict[str, Any]:
    rows = db.scalars(select(ModelVersion).order_by(ModelVersion.name.asc())).all()
    items = []
    for model in rows:
        info = rollout_of(model)
        items.append(
            {
                "id": model.id,
                "name": model.name,
                "role": model.role,
                "version": model.version,
                "state": model.state,
                "rollout": info.state,
                "rolloutUpdatedAt": info.updated_at,
                "rolloutUpdatedBy": info.updated_by,
                "rolloutNote": info.note,
                "artifactState": artifact_state(model.artifact_uri),
                "featureVersion": model.feature_version,
                "contractMatches": (model.parameters or {}).get("featureContract")
                == "flow-online-v1",
            }
        )
    return {
        "items": items,
        "active": {item["role"]: item["id"] for item in items if item["rollout"] == "active"},
    }
