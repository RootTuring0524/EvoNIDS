from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Alert, Flow, Rule
from app.db.session import get_db
from app.schemas.api import OverviewRead
from app.services.sensor_operations import list_sensors


router = APIRouter()


@router.get("", response_model=OverviewRead, response_model_by_alias=True)
def get_overview(db: Session = Depends(get_db)) -> OverviewRead:
    pending_alerts = db.scalar(
        select(func.count()).select_from(Alert).where(Alert.status.in_(["new", "investigating"]))
    ) or 0
    high_risk_alerts = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.severity.in_(["critical", "high"]), Alert.status != "closed"
        )
    ) or 0
    unassigned_alerts = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.status.in_(["new", "investigating"]), Alert.owner.is_(None)
        )
    ) or 0
    flows = db.scalar(select(func.count()).select_from(Flow)) or 0
    anomalous_flows = db.scalar(
        select(func.count()).select_from(Flow).where(Flow.verdict.in_(["suspicious", "malicious"]))
    ) or 0
    candidate_rules = db.scalar(
        select(func.count()).select_from(Rule).where(
            Rule.stage.in_(["candidate", "validating", "validated", "repaired", "confirmed"])
        )
    ) or 0
    deployed_rules = db.scalar(select(func.count()).select_from(Rule).where(Rule.stage == "deployed")) or 0
    return OverviewRead(
        pending_alerts=pending_alerts,
        high_risk_alerts=high_risk_alerts,
        unassigned_alerts=unassigned_alerts,
        flows=flows,
        anomalous_flows=anomalous_flows,
        candidate_rules=candidate_rules,
        deployed_rules=deployed_rules,
        sensors=list_sensors(db).summary,
    )
