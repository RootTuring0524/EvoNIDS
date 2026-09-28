"""Rule governance: IR compilation, Suricata sandbox validation, canary/rollback."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.security import request_actor, require_admin_token
from app.db.session import get_db
from app.db.models import Rule
from app.schemas.api import (
    RuleBridgeRequest,
    RuleBridgeResponse,
    RuleCompileRequest,
    RuleDeploymentCreate,
    RuleDeploymentRead,
    RuleDeploymentsResponse,
    RuleIRVersionRead,
    RulePromoteRequest,
    RuleRollbackRequest,
    RuleSandboxRequest,
    RuleSandboxRunRead,
    SandboxCapability,
    SensorGroupCreate,
    SensorGroupRead,
    SensorGroupsResponse,
)
from app.services.rule_deployment import (
    compile_rule_ir,
    create_sensor_group,
    deploy_rule,
    list_deployments,
    list_sandbox_runs,
    list_sensor_groups,
    list_versions,
    promote_deployment,
    rollback_deployment,
)
from app.services.replay_corpus import corpus_summary
from app.services.rule_bridge import structured_to_ir
from app.services.rule_sandbox import deployment_monitoring, sandbox_capability, validate_rule


router = APIRouter()


@router.get("/sandbox-capability", response_model=SandboxCapability, response_model_by_alias=True)
def get_sandbox_capability() -> SandboxCapability:
    return SandboxCapability.model_validate(sandbox_capability())


@router.post(
    "/rules/{rule_id}/compile",
    response_model=RuleIRVersionRead,
    status_code=201,
    response_model_by_alias=True,
)
def compile_rule(
    rule_id: str,
    payload: RuleCompileRequest,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> RuleIRVersionRead:
    version = compile_rule_ir(
        db, rule_id=rule_id, ir_payload=payload.ir, actor=request_actor(request), sid=payload.sid
    )
    return RuleIRVersionRead.model_validate(version)


@router.get(
    "/rules/{rule_id}/versions",
    response_model=list[RuleIRVersionRead],
    response_model_by_alias=True,
)
def get_rule_versions(rule_id: str, db: Session = Depends(get_db)) -> list[RuleIRVersionRead]:
    return [RuleIRVersionRead.model_validate(row) for row in list_versions(db, rule_id)]


@router.post(
    "/rules/{rule_id}/versions/{version_id}/sandbox",
    response_model=RuleSandboxRunRead,
    status_code=201,
    response_model_by_alias=True,
)
def run_sandbox(
    rule_id: str,
    version_id: str,
    payload: RuleSandboxRequest,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> RuleSandboxRunRead:
    """Run the real Suricata syntax check and labelled PCAP replay.

    When Suricata is not installed the run is stored as ``blocked`` with the
    exact reason and carries no metrics.
    """
    try:
        run = validate_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            normal_pcap=payload.normal_pcap,
            malicious_pcap=payload.malicious_pcap,
            malicious_flows=payload.malicious_flows,
            normal_flows=payload.normal_flows,
            recall_floor=payload.recall_floor,
            fp_per_million_ceiling=payload.false_positives_per_million_ceiling,
            actor=request_actor(request),
            regression_version_id=payload.regression_version_id,
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return RuleSandboxRunRead.model_validate(run)


@router.get(
    "/rules/{rule_id}/sandbox-runs",
    response_model=list[RuleSandboxRunRead],
    response_model_by_alias=True,
)
def get_sandbox_runs(
    rule_id: str, limit: int = Query(20, ge=1, le=200), db: Session = Depends(get_db)
) -> list[RuleSandboxRunRead]:
    return [RuleSandboxRunRead.model_validate(row) for row in list_sandbox_runs(db, rule_id=rule_id, limit=limit)]


@router.get(
    "/rules/{rule_id}/deployments",
    response_model=RuleDeploymentsResponse,
    response_model_by_alias=True,
)
def get_deployments(rule_id: str, db: Session = Depends(get_db)) -> RuleDeploymentsResponse:
    return RuleDeploymentsResponse.model_validate(
        {"items": list_deployments(db, rule_id=rule_id)}
    )


@router.post(
    "/rules/{rule_id}/deployments",
    response_model=RuleDeploymentRead,
    status_code=201,
    response_model_by_alias=True,
)
def create_deployment(
    rule_id: str,
    payload: RuleDeploymentCreate,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> RuleDeploymentRead:
    deployment = deploy_rule(
        db,
        rule_id=rule_id,
        version_id=payload.rule_version_id,
        sensor_group_id=payload.sensor_group_id,
        actor=request_actor(request),
        state=payload.state,
        note=payload.note,
    )
    return RuleDeploymentRead.model_validate(deployment)


@router.post(
    "/deployments/{deployment_id}/promote",
    response_model=RuleDeploymentRead,
    response_model_by_alias=True,
)
def promote(
    deployment_id: str,
    payload: RulePromoteRequest,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> RuleDeploymentRead:
    return RuleDeploymentRead.model_validate(
        promote_deployment(
            db,
            deployment_id=deployment_id,
            actor=request_actor(request),
            note=payload.note,
            target_group_id=payload.target_group_id,
        )
    )


@router.post(
    "/deployments/{deployment_id}/rollback",
    response_model=RuleDeploymentRead,
    response_model_by_alias=True,
)
def rollback(
    deployment_id: str,
    payload: RuleRollbackRequest,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> RuleDeploymentRead:
    return RuleDeploymentRead.model_validate(
        rollback_deployment(
            db, deployment_id=deployment_id, actor=request_actor(request), reason=payload.reason
        )
    )


@router.post(
    "/rules/{rule_id}/from-structured",
    response_model=RuleBridgeResponse,
    response_model_by_alias=True,
)
def bridge_structured_rule(
    rule_id: str,
    payload: RuleBridgeRequest,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> RuleBridgeResponse:
    """Compile a legacy structured rule into Rule IR, stating what cannot be mapped.

    The conversion is explicitly lossy: conditions that have no Suricata equivalent
    are reported instead of silently dropped, and ``acceptPartial`` must be set
    before a partial rule is produced.
    """
    if db.get(Rule, rule_id) is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} was not found")
    from app.domain.rule_ir import allocate_sid

    sid = payload.sid or allocate_sid(db)
    result = structured_to_ir(
        payload.structured,
        sid=sid,
        msg=payload.msg,
        accept_partial=payload.accept_partial,
    )
    body = result.as_dict()
    body["droppedCount"] = len(result.dropped)
    return RuleBridgeResponse.model_validate(body)


@router.get("/deployments/{deployment_id}/monitoring")
def get_deployment_monitoring(
    deployment_id: str,
    window_hours: int = Query(24, alias="windowHours", ge=1, le=720),
    db: Session = Depends(get_db),
) -> dict:
    """Post-deployment alert volume; unchanged values are reported as unmeasured."""
    try:
        return deployment_monitoring(db, deployment_id, window_hours=window_hours)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/corpus")
def get_replay_corpus() -> dict:
    """Inventory of the local replay corpus (what can actually be replayed)."""
    from app.core.config import get_settings

    return corpus_summary(get_settings().replay_corpus_root)


@router.get("/sensor-groups", response_model=SensorGroupsResponse, response_model_by_alias=True)
def get_sensor_groups(db: Session = Depends(get_db)) -> SensorGroupsResponse:
    return SensorGroupsResponse.model_validate({"items": list_sensor_groups(db)})


@router.post(
    "/sensor-groups",
    response_model=SensorGroupRead,
    status_code=201,
    response_model_by_alias=True,
)
def post_sensor_group(
    payload: SensorGroupCreate,
    request: Request,
    _: None = Depends(require_admin_token),
    db: Session = Depends(get_db),
) -> SensorGroupRead:
    group = create_sensor_group(
        db,
        name=payload.name,
        sensor_ids=payload.sensor_ids,
        description=payload.description,
        stage=payload.stage,
        actor=request_actor(request),
    )
    return SensorGroupRead.model_validate(group)
