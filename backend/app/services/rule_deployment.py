"""Rule compilation, sandbox gating and canary deployment with rollback.

Deployment is deliberately gated: a rule revision cannot reach a sensor group
unless it has a Suricata-backed sandbox run that actually ran and passed. When
Suricata is unavailable the request is refused with the exact reason instead of
being silently allowed, and every state change is written to the audit log.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import (
    AuditEvent,
    Rule,
    RuleDeployment,
    RuleIRVersion,
    RuleSandboxRun,
    Sensor,
    SensorGroup,
)
from app.domain.rule_ir import RuleIR, allocate_sid, compile_suricata, parse_rule_ir

CANARY_STATES = ("canary", "deployed", "rolled_back")
DeploymentState = Literal["canary", "deployed", "rolled_back"]


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20].upper()
    return f"{prefix}-{digest}"


def _audit(
    db: Session,
    *,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    outcome: str,
    after: dict[str, Any] | None = None,
    note: str | None = None,
) -> None:
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            outcome=outcome,
            request_id=None,
            before_state=None,
            after_state=after,
            note=note,
        )
    )


def compile_rule_ir(
    db: Session,
    *,
    rule_id: str,
    ir_payload: dict[str, Any],
    actor: str,
    sid: int | None = None,
) -> RuleIRVersion:
    """Validate an untrusted IR document, allocate a SID and persist the revision."""
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} was not found")
    try:
        ir = parse_rule_ir(ir_payload)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"rule IR rejected: {error}") from error
    if sid is not None and sid != ir.meta.sid:
        ir = _with_sid(ir, sid)
    if ir.meta.sid == 0:
        ir = _with_sid(ir, allocate_sid(db))
    try:
        text = compile_suricata(ir)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"rule compilation failed: {error}") from error

    latest = db.scalar(
        select(RuleIRVersion)
        .where(RuleIRVersion.rule_id == rule_id)
        .order_by(desc(RuleIRVersion.version))
        .limit(1)
    )
    version_number = (latest.version + 1) if latest else 1
    version = RuleIRVersion(
        id=_stable_id("RIRV", rule_id, str(version_number)),
        rule_id=rule_id,
        version=version_number,
        sid=ir.meta.sid,
        rev=ir.meta.rev,
        ir_digest=ir.digest(),
        ir_document=ir.canonical(),
        suricata_text=text,
        state="compiled",
        created_by=actor,
    )
    db.add(version)
    _audit(
        db,
        actor=actor,
        action="rule.compiled",
        object_type="rule",
        object_id=rule_id,
        outcome="completed",
        after={"versionId": version.id, "sid": ir.meta.sid, "rev": ir.meta.rev, "digest": version.ir_digest},
        note="Rule IR 已校验并编译为 Suricata 文本；尚未经过真实沙箱回放。",
    )
    db.commit()
    db.refresh(version)
    return version


def _with_sid(ir: RuleIR, sid: int) -> RuleIR:
    from dataclasses import replace

    return replace(ir, meta=replace(ir.meta, sid=sid))


def list_versions(db: Session, rule_id: str) -> list[RuleIRVersion]:
    return list(
        db.scalars(
            select(RuleIRVersion)
            .where(RuleIRVersion.rule_id == rule_id)
            .order_by(desc(RuleIRVersion.version))
        ).all()
    )


def latest_passed_sandbox(db: Session, version_id: str) -> RuleSandboxRun | None:
    return db.scalar(
        select(RuleSandboxRun)
        .where(RuleSandboxRun.rule_version_id == version_id, RuleSandboxRun.passed.is_(True))
        .order_by(desc(RuleSandboxRun.created_at))
        .limit(1)
    )


def create_sensor_group(
    db: Session,
    *,
    name: str,
    sensor_ids: list[str],
    description: str = "",
    stage: str = "canary",
    actor: str,
) -> SensorGroup:
    if stage not in {"canary", "production"}:
        raise HTTPException(status_code=422, detail="stage must be 'canary' or 'production'")
    known = {row for row in db.scalars(select(Sensor.id)).all()}
    unknown = [sensor_id for sensor_id in sensor_ids if sensor_id not in known]
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown sensors: {sorted(unknown)}")
    group = SensorGroup(
        id=_stable_id("SGRP", name, uuid.uuid4().hex),
        name=name,
        description=description,
        sensor_ids=sensor_ids,
        stage=stage,
    )
    db.add(group)
    _audit(
        db,
        actor=actor,
        action="sensor_group.created",
        object_type="sensor_group",
        object_id=group.id,
        outcome="completed",
        after={"name": name, "sensorIds": sensor_ids, "stage": stage},
    )
    db.commit()
    db.refresh(group)
    return group


def list_sensor_groups(db: Session) -> list[SensorGroup]:
    return list(db.scalars(select(SensorGroup).order_by(SensorGroup.name.asc())).all())


def deploy_rule(
    db: Session,
    *,
    rule_id: str,
    version_id: str,
    sensor_group_id: str,
    actor: str,
    state: DeploymentState = "canary",
    note: str | None = None,
) -> RuleDeployment:
    """Deploy a compiled revision, gated by a passed Suricata sandbox run."""
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} was not found")
    version = db.get(RuleIRVersion, version_id)
    if version is None or version.rule_id != rule_id:
        raise HTTPException(status_code=404, detail=f"Rule version {version_id} was not found")
    group = db.get(SensorGroup, sensor_group_id)
    if group is None:
        raise HTTPException(status_code=404, detail=f"Sensor group {sensor_group_id} was not found")
    if state not in {"canary", "deployed"}:
        raise HTTPException(status_code=422, detail="state must be 'canary' or 'deployed'")

    sandbox = latest_passed_sandbox(db, version_id)
    if sandbox is None:
        blocked = db.scalar(
            select(RuleSandboxRun)
            .where(RuleSandboxRun.rule_version_id == version_id)
            .order_by(desc(RuleSandboxRun.created_at))
            .limit(1)
        )
        reason = (
            blocked.blocked_reason
            if blocked is not None and blocked.blocked_reason
            else "no passed Suricata sandbox run exists for this revision"
        )
        raise HTTPException(
            status_code=409,
            detail=(
                "deployment refused: a passed Suricata sandbox run is required "
                f"(latest run status: {blocked.status if blocked else 'none'}; reason: {reason})"
            ),
        )
    if state == "deployed" and group.stage != "production":
        raise HTTPException(
            status_code=409,
            detail="full deployment requires a sensor group whose stage is 'production'",
        )

    active = db.scalar(
        select(RuleDeployment)
        .where(RuleDeployment.rule_id == rule_id, RuleDeployment.state.in_(("canary", "deployed")))
        .order_by(desc(RuleDeployment.created_at))
        .limit(1)
    )
    deployment = RuleDeployment(
        id=_stable_id("RDEP", rule_id, sensor_group_id, uuid.uuid4().hex),
        rule_id=rule_id,
        rule_version_id=version_id,
        sensor_group_id=sensor_group_id,
        state=state,
        deployed_by=actor,
        deployed_at=utc_now(),
        promoted_at=utc_now() if state == "deployed" else None,
        monitoring={},
        previous_version_id=active.rule_version_id if active else None,
    )
    db.add(deployment)
    rule.stage = "deployed" if state == "deployed" else "canary"
    rule.active_version_id = version_id
    _audit(
        db,
        actor=actor,
        action=f"rule.{'deployed' if state == 'deployed' else 'canary'}",
        object_type="rule",
        object_id=rule_id,
        outcome="completed",
        after={
            "deploymentId": deployment.id,
            "versionId": version_id,
            "sid": version.sid,
            "sensorGroupId": sensor_group_id,
            "sandboxRunId": sandbox.id,
            "state": state,
        },
        note=note or "灰度/正式部署已执行，回滚可通过 rollback 接口完成。",
    )
    db.commit()
    db.refresh(deployment)
    return deployment


def promote_deployment(
    db: Session,
    *,
    deployment_id: str,
    actor: str,
    note: str | None = None,
    target_group_id: str | None = None,
) -> RuleDeployment:
    """Promote a canary revision to a production sensor group.

    Promotion always creates a separate production deployment row so the canary
    history stays intact and a rollback can target either record.
    """
    deployment = db.get(RuleDeployment, deployment_id)
    if deployment is None:
        raise HTTPException(status_code=404, detail=f"Deployment {deployment_id} was not found")
    if deployment.state != "canary":
        raise HTTPException(status_code=409, detail=f"deployment is in state {deployment.state}, not canary")
    group = db.get(SensorGroup, target_group_id or deployment.sensor_group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="target sensor group was not found")
    if group.stage != "production":
        raise HTTPException(
            status_code=409,
            detail=(
                "promotion requires a production sensor group; "
                f"group {group.id} has stage {group.stage!r}"
            ),
        )
    deployment.state = "deployed"
    deployment.promoted_at = utc_now()
    production = RuleDeployment(
        id=_stable_id("RDEP", deployment.rule_id, group.id, uuid.uuid4().hex),
        rule_id=deployment.rule_id,
        rule_version_id=deployment.rule_version_id,
        sensor_group_id=group.id,
        state="deployed",
        deployed_by=actor,
        deployed_at=utc_now(),
        promoted_at=utc_now(),
        monitoring={},
        previous_version_id=deployment.previous_version_id,
    )
    db.add(production)
    rule = db.get(Rule, deployment.rule_id)
    if rule is not None:
        rule.stage = "deployed"
        rule.active_version_id = deployment.rule_version_id
    _audit(
        db,
        actor=actor,
        action="rule.promoted",
        object_type="rule",
        object_id=deployment.rule_id,
        outcome="completed",
        after={
            "canaryDeploymentId": deployment.id,
            "productionDeploymentId": production.id,
            "sensorGroupId": group.id,
        },
        note=note or "灰度观察期结束，提升为正式部署。",
    )
    db.commit()
    db.refresh(production)
    return production


def rollback_deployment(
    db: Session, *, deployment_id: str, actor: str, reason: str
) -> RuleDeployment:
    if not reason or len(reason.strip()) < 10:
        raise HTTPException(status_code=422, detail="rollback requires a reason of at least 10 characters")
    deployment = db.get(RuleDeployment, deployment_id)
    if deployment is None:
        raise HTTPException(status_code=404, detail=f"Deployment {deployment_id} was not found")
    if deployment.state == "rolled_back":
        raise HTTPException(status_code=409, detail="deployment was already rolled back")
    deployment.state = "rolled_back"
    deployment.rolled_back_at = utc_now()
    deployment.rollback_reason = reason.strip()
    rule = db.get(Rule, deployment.rule_id)
    if rule is not None:
        rule.stage = "rolled_back"
        rule.active_version_id = deployment.previous_version_id
    _audit(
        db,
        actor=actor,
        action="rule.rolled_back",
        object_type="rule",
        object_id=deployment.rule_id,
        outcome="completed",
        after={
            "deploymentId": deployment.id,
            "restoredVersionId": deployment.previous_version_id,
            "reason": deployment.rollback_reason,
        },
        note="已回滚到上一版本；回滚原因已写入审计日志。",
    )
    db.commit()
    db.refresh(deployment)
    return deployment


def list_deployments(db: Session, *, rule_id: str | None = None, limit: int = 100) -> list[RuleDeployment]:
    query = select(RuleDeployment).order_by(desc(RuleDeployment.created_at)).limit(limit)
    if rule_id:
        query = query.where(RuleDeployment.rule_id == rule_id)
    return list(db.scalars(query).all())


def list_sandbox_runs(db: Session, *, rule_id: str, limit: int = 20) -> list[RuleSandboxRun]:
    return list(
        db.scalars(
            select(RuleSandboxRun)
            .where(RuleSandboxRun.rule_id == rule_id)
            .order_by(desc(RuleSandboxRun.created_at))
            .limit(limit)
        ).all()
    )


@dataclass(frozen=True, slots=True)
class DeploymentSummary:
    total: int
    canary: int
    deployed: int
    rolled_back: int


def deployment_summary(db: Session, *, rule_id: str) -> DeploymentSummary:
    counts = {state: 0 for state in CANARY_STATES}
    for state, count in db.execute(
        select(RuleDeployment.state, func.count()).where(RuleDeployment.rule_id == rule_id).group_by(
            RuleDeployment.state
        )
    ).all():
        if state in counts:
            counts[state] = int(count)
    return DeploymentSummary(
        total=sum(counts.values()),
        canary=counts["canary"],
        deployed=counts["deployed"],
        rolled_back=counts["rolled_back"],
    )
