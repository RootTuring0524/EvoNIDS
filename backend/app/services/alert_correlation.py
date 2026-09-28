"""Alert correlation: duplicate clustering, suppression policy and case aggregation.

Suricata alerts for one campaign arrive as many near-identical rows (same sensor,
same endpoints, same signature, seconds apart). Without correlation the analyst
queue is noise, and the case workbench is filled by hand. This module provides:

* a deterministic dedup signature and clustering over a time window;
* an explicit suppression policy layer (an alert is suppressed, never deleted,
  and every decision carries the rule that made it);
* automatic case aggregation for clusters that cross a threshold - it creates
  cases and attaches alerts, but never closes, contains or executes anything.

The aggregation report always states counts for created/attached/skipped so the
UI can show what the automation actually did instead of implying more.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import Alert, Case, CaseAlert

DEFAULT_WINDOW_MINUTES = 30
DEFAULT_MIN_CLUSTER_SIZE = 3
MAX_CLUSTER_SCAN = 5_000
Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Categories whose alerts are worth auto-aggregating. A bare "Unknown Anomaly"
# with a low score is deliberately excluded: aggregating it would create cases
# out of noise.
AGGREGATABLE_CATEGORIES = frozenset(
    {
        "DoS",
        "DDoS",
        "Port Scan",
        "Brute Force",
        "Botnet",
        "C2 Communication",
        "Web Attack",
        "Infiltration",
        "Abnormal Outbound Connection",
        "Known Attack",
        "Known Attack + Anomaly",
    }
)


@dataclass(frozen=True, slots=True)
class SuppressionRule:
    """One operator-authored suppression rule.

    ``reason`` is mandatory: a suppression without a written reason is how real
    incidents get lost, so the API rejects it and the report always carries it.
    """

    id: str
    reason: str
    categories: tuple[str, ...] = ()
    sensors: tuple[str, ...] = ()
    source_networks: tuple[str, ...] = ()
    destination_networks: tuple[str, ...] = ()
    max_risk_score: float | None = None
    active_from: datetime | None = None
    active_until: datetime | None = None
    enabled: bool = True

    def matches(self, alert: Alert, *, now: datetime | None = None) -> str | None:
        """Return the reason this rule suppresses the alert, or None."""
        if not self.enabled:
            return None
        stamp = _naive(alert.timestamp)
        if self.active_from is not None and stamp < _naive(self.active_from):
            return None
        if self.active_until is not None and stamp > _naive(self.active_until):
            return None
        if self.categories and alert.category not in self.categories:
            return None
        if self.sensors and alert.sensor not in self.sensors:
            return None
        if self.max_risk_score is not None and alert.risk_score > self.max_risk_score:
            return None
        if self.source_networks and not any(
            _in_network(alert.source_ip, network) for network in self.source_networks
        ):
            return None
        if self.destination_networks and not any(
            _in_network(alert.destination_ip, network) for network in self.destination_networks
        ):
            return None
        return self.reason


@dataclass(slots=True)
class AlertCluster:
    signature: str
    category: str
    sensor: str
    source_ip: str
    destination_ip: str
    destination_port: int
    alert_ids: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    highest_risk: float = 0.0
    severity: str = "low"
    case_ids: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.alert_ids)

    @property
    def suppressed(self) -> bool:
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "category": self.category,
            "sensor": self.sensor,
            "sourceIp": self.source_ip,
            "destinationIp": self.destination_ip,
            "destinationPort": self.destination_port,
            "alertIds": self.alert_ids,
            "size": self.size,
            "firstSeen": self.first_seen.isoformat() if self.first_seen else None,
            "lastSeen": self.last_seen.isoformat() if self.last_seen else None,
            "highestRisk": round(self.highest_risk, 2),
            "severity": self.severity,
            "caseIds": self.case_ids,
        }


def dedup_signature(alert: Alert, *, window_minutes: int = DEFAULT_WINDOW_MINUTES) -> str:
    """Stable signature: same campaign, same window.

    The time component is the alert timestamp floored to the window, so two
    alerts that describe the same behaviour inside one window collapse while a
    repeat next window stays visible.
    """
    bucket = int(_naive(alert.timestamp).timestamp() // max(window_minutes * 60, 1))
    parts = (
        alert.sensor,
        alert.category,
        alert.source_ip,
        alert.destination_ip,
        str(alert.destination_port),
        str(bucket),
    )
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]


def cluster_alerts(
    db: Session,
    *,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    lookback_hours: int = 24,
    min_size: int = 2,
    include_suppressed: bool = False,
    suppression_rules: Sequence[SuppressionRule] = (),
) -> list[AlertCluster]:
    """Group recent alerts into duplicate clusters (largest first)."""
    since = utc_now() - timedelta(hours=max(1, min(lookback_hours, 24 * 30)))
    rows = list(
        db.scalars(
            select(Alert)
            .where(Alert.timestamp >= since)
            .order_by(Alert.timestamp.desc())
            .limit(MAX_CLUSTER_SCAN)
        ).all()
    )
    clusters: dict[str, AlertCluster] = {}
    for alert in rows:
        suppressed_reason = None
        for rule in suppression_rules:
            suppressed_reason = rule.matches(alert)
            if suppressed_reason:
                break
        if suppressed_reason and not include_suppressed:
            continue
        signature = dedup_signature(alert, window_minutes=window_minutes)
        cluster = clusters.get(signature)
        if cluster is None:
            cluster = AlertCluster(
                signature=signature,
                category=alert.category,
                sensor=alert.sensor,
                source_ip=alert.source_ip,
                destination_ip=alert.destination_ip,
                destination_port=alert.destination_port,
                first_seen=_naive(alert.timestamp),
                last_seen=_naive(alert.timestamp),
                highest_risk=alert.risk_score,
                severity=alert.severity,
            )
            clusters[signature] = cluster
        cluster.alert_ids.append(alert.id)
        stamp = _naive(alert.timestamp)
        cluster.first_seen = min(cluster.first_seen or stamp, stamp)
        cluster.last_seen = max(cluster.last_seen or stamp, stamp)
        cluster.highest_risk = max(cluster.highest_risk, alert.risk_score)
        if SEVERITY_ORDER.get(alert.severity, 0) > SEVERITY_ORDER.get(cluster.severity, 0):
            cluster.severity = alert.severity
    candidates = [cluster for cluster in clusters.values() if cluster.size >= min_size]
    if candidates:
        _attach_case_membership(db, candidates)
    return sorted(candidates, key=lambda item: (item.size, item.highest_risk), reverse=True)


def _attach_case_membership(db: Session, clusters: Sequence[AlertCluster]) -> None:
    all_ids = [alert_id for cluster in clusters for alert_id in cluster.alert_ids]
    if not all_ids:
        return
    rows = db.execute(
        select(CaseAlert.alert_id, CaseAlert.case_id).where(CaseAlert.alert_id.in_(all_ids))
    ).all()
    by_alert: dict[str, list[str]] = {}
    for alert_id, case_id in rows:
        by_alert.setdefault(str(alert_id), []).append(str(case_id))
    for cluster in clusters:
        found: list[str] = []
        for alert_id in cluster.alert_ids:
            for case_id in by_alert.get(alert_id, []):
                if case_id not in found:
                    found.append(case_id)
        cluster.case_ids = found


def apply_suppression(
    db: Session,
    *,
    rules: Sequence[SuppressionRule],
    lookback_hours: int = 24,
) -> dict[str, Any]:
    """Classify recent alerts as suppressed (nothing is deleted or mutated)."""
    since = utc_now() - timedelta(hours=max(1, min(lookback_hours, 24 * 30)))
    rows = list(
        db.scalars(
            select(Alert)
            .where(Alert.timestamp >= since)
            .order_by(Alert.timestamp.desc())
            .limit(MAX_CLUSTER_SCAN)
        ).all()
    )
    suppressed: list[dict[str, Any]] = []
    for alert in rows:
        for rule in rules:
            reason = rule.matches(alert)
            if reason:
                suppressed.append(
                    {
                        "alertId": alert.id,
                        "ruleId": rule.id,
                        "reason": reason,
                        "category": alert.category,
                        "sensor": alert.sensor,
                        "riskScore": alert.risk_score,
                    }
                )
                break
    return {
        "scanned": len(rows),
        "suppressed": len(suppressed),
        "ruleCount": len(rules),
        "items": suppressed[:200],
        "note": (
            "抑制只影响告警队列的呈现与聚合，不删除告警、不修改证据；"
            "所有抑制都带有人工填写的原因。"
        ),
    }


def auto_aggregate_cases(
    db: Session,
    *,
    actor: str,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    min_cluster_size: int = DEFAULT_MIN_CLUSTER_SIZE,
    max_cases: int = 10,
    lookback_hours: int = 24,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Create cases for large unassigned clusters and attach their alerts.

    Deliberately conservative: only alerts that are not already in a case, only
    categories in ``AGGREGATABLE_CATEGORIES``, at most ``max_cases`` per call,
    and nothing is ever closed or actioned automatically.
    """
    clusters = cluster_alerts(
        db,
        window_minutes=window_minutes,
        lookback_hours=lookback_hours,
        min_size=min_cluster_size,
    )
    created: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for cluster in clusters:
        if len(created) >= max_cases:
            skipped.append({"signature": cluster.signature, "reason": "max_cases_reached"})
            continue
        if cluster.category not in AGGREGATABLE_CATEGORIES:
            skipped.append({"signature": cluster.signature, "reason": "category_not_aggregatable"})
            continue
        if cluster.case_ids:
            skipped.append({"signature": cluster.signature, "reason": "already_in_case"})
            continue
        unassigned = _alerts_without_case(db, cluster.alert_ids)
        if len(unassigned) < min_cluster_size:
            skipped.append({"signature": cluster.signature, "reason": "too_few_unassigned_alerts"})
            continue
        if dry_run:
            created.append(
                {
                    "signature": cluster.signature,
                    "dryRun": True,
                    "wouldAttach": len(unassigned),
                    "title": _case_title(cluster),
                }
            )
            continue
        case = _create_case(db, cluster=cluster, alert_ids=unassigned, actor=actor)
        created.append(
            {
                "signature": cluster.signature,
                "caseId": case.id,
                "title": case.title,
                "attachedAlerts": len(unassigned),
                "severity": case.severity,
            }
        )
    if not dry_run:
        db.commit()
    return {
        "dryRun": dry_run,
        "windowMinutes": window_minutes,
        "minClusterSize": min_cluster_size,
        "clustersConsidered": len(clusters),
        "casesCreated": len([item for item in created if not item.get("dryRun")]),
        "created": created,
        "skipped": skipped,
        "note": (
            "自动聚合只创建案件并挂载告警，写入时间线与审计；"
            "不会关闭案件、不会执行任何阻断或响应动作。"
        ),
    }


def _alerts_without_case(db: Session, alert_ids: Sequence[str]) -> list[str]:
    existing = set(
        str(row)
        for row in db.scalars(
            select(CaseAlert.alert_id).where(CaseAlert.alert_id.in_(list(alert_ids)))
        ).all()
    )
    return [alert_id for alert_id in alert_ids if alert_id not in existing]


def _case_title(cluster: AlertCluster) -> str:
    endpoints = f"{cluster.source_ip} → {cluster.destination_ip}:{cluster.destination_port}"
    return f"[自动聚合] {cluster.category} · {endpoints}"[:255]


def _create_case(
    db: Session, *, cluster: AlertCluster, alert_ids: Sequence[str], actor: str
) -> Case:
    case = Case(
        id=_case_id(cluster.signature),
        title=_case_title(cluster),
        summary=(
            f"由告警聚类自动创建：窗口 {cluster.first_seen} ~ {cluster.last_seen}，"
            f"共 {cluster.size} 条同源告警，最高风险 {cluster.highest_risk:.2f}，"
            f"传感器 {cluster.sensor}。需要人工确认事件性质。"
        ),
        severity=cluster.severity,
        status="open",
        assignee=None,
        created_by=actor,
        alert_count=0,
        highest_risk_score=0.0,
    )
    db.add(case)
    db.flush()
    from app.services.cases import attach_alert

    alerts = {alert.id: alert for alert in db.scalars(select(Alert).where(Alert.id.in_(list(alert_ids)))).all()}
    for alert_id in alert_ids:
        alert = alerts.get(alert_id)
        if alert is None:
            continue
        attach_alert(db, case, alert, actor=actor, request_id=None)
    db.refresh(case)
    return case


def _case_id(signature: str) -> str:
    return f"CASE-{signature[:12].upper()}"


def _naive(value: datetime) -> datetime:
    """Normalise to naive UTC, matching the storage convention used everywhere."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _in_network(ip: str, network: str) -> bool:
    """Minimal CIDR containment for IPv4 without an extra dependency."""
    try:
        if "/" not in network:
            return ip == network
        base, _, prefix_raw = network.partition("/")
        prefix = int(prefix_raw)
        if not 0 <= prefix <= 32:
            return False
        return (_ip_to_int(ip) >> (32 - prefix)) == (_ip_to_int(base) >> (32 - prefix))
    except (ValueError, TypeError):
        return False


def _ip_to_int(value: str) -> int:
    parts = value.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"not an IPv4 address: {value!r}")
    total = 0
    for part in parts:
        octet = int(part)
        if not 0 <= octet <= 255:
            raise ValueError(f"invalid octet in {value!r}")
        total = (total << 8) | octet
    return total


def alert_totals(db: Session, *, lookback_hours: int = 24) -> dict[str, Any]:
    """Small summary used by the correlation report header."""
    since = utc_now() - timedelta(hours=max(1, min(lookback_hours, 24 * 30)))
    total = db.scalar(select(func.count()).select_from(Alert).where(Alert.timestamp >= since)) or 0
    unassigned = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.timestamp >= since,
                ~Alert.id.in_(select(CaseAlert.alert_id)),
            )
        )
        or 0
    )
    return {"windowHours": lookback_hours, "alerts": int(total), "unassigned": int(unassigned)}


__all__ = [
    "AlertCluster",
    "SuppressionRule",
    "alert_totals",
    "apply_suppression",
    "auto_aggregate_cases",
    "cluster_alerts",
    "dedup_signature",
]
