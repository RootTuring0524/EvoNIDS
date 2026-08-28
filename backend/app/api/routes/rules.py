from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.security import require_admin_token
from app.db.models import Rule
from app.db.session import get_db
from app.schemas.api import (
    RuleAction,
    RuleCandidateCreate,
    RuleDetail,
    RuleRead,
    RulesResponse,
    RuleTimeline,
)
from app.services.rule_lifecycle import (
    build_rule_detail,
    create_candidate,
    rule_timeline,
    transition_rule,
    validate_or_advance,
)


router = APIRouter()


@router.get("", response_model=RulesResponse, response_model_by_alias=True)
def list_rules(db: Session = Depends(get_db)) -> RulesResponse:
    total = db.scalar(select(func.count()).select_from(Rule)) or 0
    rows = db.scalars(select(Rule).order_by(desc(Rule.updated_at))).all()
    return RulesResponse(items=[RuleRead.model_validate(row) for row in rows], total=total)


@router.post(
    "",
    response_model=RuleDetail,
    response_model_by_alias=True,
    status_code=201,
    dependencies=[Depends(require_admin_token)],
)
def post_rule(
    payload: RuleCandidateCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> RuleDetail:
    return create_candidate(
        db,
        payload,
        request_id=getattr(request.state, "request_id", None),
    )


@router.get("/{rule_id}", response_model=RuleDetail, response_model_by_alias=True)
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> RuleDetail:
    return build_rule_detail(db, _get_rule(db, rule_id))


@router.get(
    "/{rule_id}/timeline",
    response_model=RuleTimeline,
    response_model_by_alias=True,
)
def get_rule_timeline(rule_id: str, db: Session = Depends(get_db)) -> RuleTimeline:
    return rule_timeline(db, _get_rule(db, rule_id))


@router.post(
    "/{rule_id}/validate",
    response_model=RuleDetail,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)
def validate_rule(
    rule_id: str,
    action: RuleAction,
    request: Request,
    db: Session = Depends(get_db),
) -> RuleDetail:
    return validate_or_advance(
        db,
        _get_rule(db, rule_id),
        action,
        request_id=getattr(request.state, "request_id", None),
    )


def _lifecycle_endpoint(target: str):
    def endpoint(
        rule_id: str,
        action: RuleAction,
        request: Request,
        db: Session = Depends(get_db),
    ) -> RuleDetail:
        return transition_rule(
            db,
            _get_rule(db, rule_id),
            target,
            action,
            request_id=getattr(request.state, "request_id", None),
        )

    return endpoint


router.add_api_route(
    "/{rule_id}/reject",
    _lifecycle_endpoint("rejected"),
    methods=["POST"],
    response_model=RuleDetail,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)
router.add_api_route(
    "/{rule_id}/confirm",
    _lifecycle_endpoint("confirmed"),
    methods=["POST"],
    response_model=RuleDetail,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)
router.add_api_route(
    "/{rule_id}/deploy",
    _lifecycle_endpoint("deployed"),
    methods=["POST"],
    response_model=RuleDetail,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)
router.add_api_route(
    "/{rule_id}/repair",
    _lifecycle_endpoint("repaired"),
    methods=["POST"],
    response_model=RuleDetail,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)
router.add_api_route(
    "/{rule_id}/deprecate",
    _lifecycle_endpoint("deprecated"),
    methods=["POST"],
    response_model=RuleDetail,
    response_model_by_alias=True,
    dependencies=[Depends(require_admin_token)],
)


def _get_rule(db: Session, rule_id: str) -> Rule:
    row = db.get(Rule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} was not found")
    return row
