"""Alert correlation, suppression and auto-aggregation endpoints."""
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.security import request_actor, require_analyst_token
from app.db.session import get_db
from app.services.alert_correlation import (
    DEFAULT_MIN_CLUSTER_SIZE,
    DEFAULT_WINDOW_MINUTES,
    alert_totals,
    auto_aggregate_cases,
    cluster_alerts,
)

router = APIRouter()


@router.get("/clusters")
def get_alert_clusters(
    window_minutes: int = Query(DEFAULT_WINDOW_MINUTES, alias="windowMinutes", ge=1, le=1440),
    lookback_hours: int = Query(24, alias="lookbackHours", ge=1, le=720),
    min_size: int = Query(2, alias="minSize", ge=2, le=1000),
    db: Session = Depends(get_db),
) -> dict:
    """Duplicate/near-duplicate alert clusters (largest first)."""
    clusters = cluster_alerts(
        db, window_minutes=window_minutes, lookback_hours=lookback_hours, min_size=min_size
    )
    return {
        "windowMinutes": window_minutes,
        "lookbackHours": lookback_hours,
        "totals": alert_totals(db, lookback_hours=lookback_hours),
        "clusterCount": len(clusters),
        "clusters": [cluster.as_dict() for cluster in clusters[:200]],
        "note": (
            "聚类签名 = 传感器 + 类别 + 源/目的地址 + 目的端口 + 时间窗；"
            "只做分组与计数，不修改告警状态。"
        ),
    }


@router.post("/aggregate")
def aggregate_alerts_into_cases(
    request: Request,
    window_minutes: int = Query(DEFAULT_WINDOW_MINUTES, alias="windowMinutes", ge=1, le=1440),
    min_cluster_size: int = Query(DEFAULT_MIN_CLUSTER_SIZE, alias="minClusterSize", ge=2, le=1000),
    max_cases: int = Query(10, alias="maxCases", ge=1, le=50),
    lookback_hours: int = Query(24, alias="lookbackHours", ge=1, le=720),
    dry_run: bool = Query(False, alias="dryRun"),
    _: None = Depends(require_analyst_token),
    db: Session = Depends(get_db),
) -> dict:
    """Create cases for large unassigned clusters (never closes or actions anything)."""
    return auto_aggregate_cases(
        db,
        actor=request_actor(request),
        window_minutes=window_minutes,
        min_cluster_size=min_cluster_size,
        max_cases=max_cases,
        lookback_hours=lookback_hours,
        dry_run=dry_run,
    )

