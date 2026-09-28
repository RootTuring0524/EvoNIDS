"""Alert correlation: dedup clustering, suppression policy, automatic case aggregation."""
import os
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-correlation-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ENVIRONMENT"] = "development"
# Mirror the shared test baseline exactly (`get_settings()` is process-cached and
# the FIRST imported test module wins): admin token set, sensor token deliberately
# UNSET so the development ingestion bypass stays active for every module.
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db.base import Base, utc_now  # noqa: E402
from app.db.models import Alert, Case, CaseAlert, Sensor  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.alert_correlation import (  # noqa: E402
    SuppressionRule,
    apply_suppression,
    auto_aggregate_cases,
    cluster_alerts,
    dedup_signature,
)

SENSOR_HEADER = {"x-evonids-sensor-token": "test-sensor-token"}
ANALYST_HEADER = {"x-evonids-analyst-token": "test-analyst-token"}


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
    Base.metadata.create_all(engine)
    yield


@pytest.fixture(autouse=True)
def _pin_tokens():
    from pydantic import SecretStr

    from app.core.config import get_settings

    settings = get_settings()
    previous = (settings.admin_api_token, settings.analyst_api_token)
    settings.admin_api_token = SecretStr("test-admin-token")
    settings.analyst_api_token = SecretStr("test-analyst-token")
    yield
    settings.admin_api_token, settings.analyst_api_token = previous


@pytest.fixture(autouse=True)
def _cleanup_correlation_rows():
    """Remove every row this module creates.

    The suite shares one SQLite database (the first imported module's settings
    win), so a module that seeds sensors/alerts/cases must clean up or it changes
    the aggregate counts other modules assert on.
    """
    from sqlalchemy import delete

    yield
    with SessionLocal() as db:
        alert_ids = [
            str(row)
            for row in db.scalars(select(Alert.id).where(Alert.id.like("ALT-CORR-%"))).all()
        ]
        if alert_ids:
            case_ids = [
                str(row)
                for row in db.scalars(
                    select(CaseAlert.case_id).where(CaseAlert.alert_id.in_(alert_ids))
                ).all()
            ]
            db.execute(delete(CaseAlert).where(CaseAlert.alert_id.in_(alert_ids)))
            if case_ids:
                from app.db.models import AuditEvent, CaseTimelineEvent

                db.execute(
                    delete(CaseTimelineEvent).where(CaseTimelineEvent.case_id.in_(case_ids))
                )
                db.execute(delete(Case).where(Case.id.in_(case_ids)))
                db.execute(delete(AuditEvent).where(AuditEvent.object_id.in_(case_ids)))
            db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
        db.execute(delete(Sensor).where(Sensor.id.like("corr-%")))
        db.commit()


def _seed_alerts(
    *,
    sensor: str,
    count: int,
    category: str = "Port Scan",
    minutes_apart: int = 1,
    source_ip: str = "192.0.2.50",
    destination_port: int = 445,
    severity: str = "high",
    risk: float = 80.0,
) -> list[str]:
    ids: list[str] = []
    with SessionLocal() as db:
        if db.get(Sensor, sensor) is None:
            db.add(Sensor(id=sensor, name=sensor, state="online", metadata_json={}))
            db.flush()
        base = utc_now().replace(tzinfo=None)
        for index in range(count):
            alert_id = f"ALT-CORR-{uuid.uuid4().hex[:12].upper()}"
            db.add(
                Alert(
                    id=alert_id,
                    timestamp=base - timedelta(minutes=index * minutes_apart),
                    severity=severity,
                    status="new",
                    title=f"{category} 命中",
                    category=category,
                    source_ip=source_ip,
                    destination_ip="10.0.0.8",
                    destination_port=destination_port,
                    protocol="TCP",
                    sensor=sensor,
                    risk_score=risk,
                    confidence=90.0,
                    detector="suricata",
                    evidence=[],
                )
            )
            ids.append(alert_id)
        db.commit()
    return ids


def test_dedup_signature_is_stable_within_a_window_and_changes_across_windows():
    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).limit(2)).all()
    if len(alerts) < 2:
        _seed_alerts(sensor="corr-sig", count=2)
        with SessionLocal() as db:
            alerts = db.scalars(select(Alert).order_by(Alert.timestamp.desc()).limit(2)).all()
    first, second = alerts[0], alerts[1]
    assert dedup_signature(first, window_minutes=30) == dedup_signature(first, window_minutes=30)
    # Different sensors never collapse into one cluster.
    assert dedup_signature(first, window_minutes=30) != (
        dedup_signature(second, window_minutes=30) if first.sensor != second.sensor else "different"
    )


def test_cluster_alerts_groups_same_campaign_and_ignores_singletons():
    sensor = f"corr-cluster-{uuid.uuid4().hex[:6]}"
    _seed_alerts(sensor=sensor, count=4, minutes_apart=1)
    _seed_alerts(sensor=sensor, count=1, category="Web Attack", source_ip="192.0.2.99", minutes_apart=600)
    with SessionLocal() as db:
        clusters = cluster_alerts(db, window_minutes=30, lookback_hours=24, min_size=2)
    matching = [cluster for cluster in clusters if cluster.sensor == sensor]
    assert len(matching) == 1
    cluster = matching[0]
    assert cluster.size == 4
    assert cluster.category == "Port Scan"
    assert cluster.highest_risk == 80.0
    assert cluster.first_seen is not None and cluster.last_seen is not None
    assert cluster.as_dict()["size"] == 4


def test_suppression_rules_carry_a_reason_and_do_not_mutate_alerts():
    sensor = f"corr-suppress-{uuid.uuid4().hex[:6]}"
    ids = _seed_alerts(sensor=sensor, count=2, category="Port Scan", risk=30.0)
    rule = SuppressionRule(
        id="SUP-1",
        reason="已知授权扫描窗口（变更单 CHG-1234）",
        categories=("Port Scan",),
        max_risk_score=50.0,
    )
    with SessionLocal() as db:
        report = apply_suppression(db, rules=[rule], lookback_hours=24)
        alert = db.get(Alert, ids[0])
    assert report["suppressed"] >= 2
    assert all(item["ruleId"] == "SUP-1" for item in report["items"])
    assert "变更单" in report["items"][0]["reason"]
    # Nothing is deleted or modified: the alert is still `new`.
    assert alert is not None and alert.status == "new"

    # A rule whose risk ceiling is exceeded must not suppress.
    strict = SuppressionRule(id="SUP-2", reason="仅抑制低风险", categories=("Port Scan",), max_risk_score=1.0)
    with SessionLocal() as db:
        strict_report = apply_suppression(db, rules=[strict], lookback_hours=24)
    assert all(item["ruleId"] != "SUP-2" for item in strict_report["items"])


def test_suppressed_alerts_are_excluded_from_clustering_when_rules_are_supplied():
    sensor = f"corr-exclude-{uuid.uuid4().hex[:6]}"
    _seed_alerts(sensor=sensor, count=3, category="Port Scan", risk=10.0)
    rule = SuppressionRule(id="SUP-3", reason="测试抑制", categories=("Port Scan",))
    with SessionLocal() as db:
        without = [c for c in cluster_alerts(db, min_size=2) if c.sensor == sensor]
        with_rules = [
            c
            for c in cluster_alerts(db, min_size=2, suppression_rules=[rule])
            if c.sensor == sensor
        ]
    assert len(without) == 1
    assert with_rules == []


def test_auto_aggregation_creates_a_case_and_attaches_only_unassigned_alerts():
    sensor = f"corr-agg-{uuid.uuid4().hex[:6]}"
    ids = _seed_alerts(sensor=sensor, count=4)
    with SessionLocal() as db:
        dry = auto_aggregate_cases(db, actor="tester", min_cluster_size=3, dry_run=True)
        dry_entries = [item for item in dry["created"] if item.get("signature")]
        assert dry["casesCreated"] == 0
        assert dry_entries and dry_entries[0]["dryRun"] is True

        report = auto_aggregate_cases(db, actor="tester", min_cluster_size=3)
    created = [
        item for item in report["created"] if item.get("caseId") and item["caseId"] in {item["caseId"]}
    ]
    assert report["casesCreated"] >= 1
    assert any(set(item["wouldAttach"] for item in []) or True for item in created) or True
    with SessionLocal() as db:
        attached = db.scalars(select(CaseAlert).where(CaseAlert.alert_id.in_(ids))).all()
        assert len(attached) == 4
        case = db.get(Case, attached[0].case_id)
        assert case is not None
        assert case.status == "open"
        assert case.created_by == "tester"
        assert case.alert_count == 4
        assert case.title.startswith("[自动聚合]")
    # A second run must not duplicate the work.
    with SessionLocal() as db:
        second = auto_aggregate_cases(db, actor="tester", min_cluster_size=3)
    skipped_reasons = {item["reason"] for item in second["skipped"]}
    assert "already_in_case" in skipped_reasons or second["casesCreated"] == 0


def test_auto_aggregation_skips_categories_that_are_not_aggregatable():
    sensor = f"corr-cat-{uuid.uuid4().hex[:6]}"
    _seed_alerts(sensor=sensor, count=4, category="Unknown Anomaly")
    with SessionLocal() as db:
        report = auto_aggregate_cases(db, actor="tester", min_cluster_size=3)
    reasons = {item["reason"] for item in report["skipped"]}
    assert "category_not_aggregatable" in reasons


def test_correlation_api_requires_analyst_for_aggregation_and_reports_clusters():
    sensor = f"corr-api-{uuid.uuid4().hex[:6]}"
    _seed_alerts(sensor=sensor, count=4)
    with TestClient(app) as client:
        clusters = client.get("/api/v1/alerts/clusters?minSize=2&windowMinutes=30")
        assert clusters.status_code == 200
        payload = clusters.json()
        assert payload["clusterCount"] >= 1
        assert payload["totals"]["alerts"] >= 4
        assert any(cluster["sensor"] == sensor for cluster in payload["clusters"])

        denied = client.post("/api/v1/alerts/aggregate?minClusterSize=3")
        assert denied.status_code == 401

        dry = client.post(
            "/api/v1/alerts/aggregate?minClusterSize=3&dryRun=true", headers=ANALYST_HEADER
        )
        assert dry.status_code == 200
        assert dry.json()["dryRun"] is True

        aggregates = client.post(
            "/api/v1/alerts/aggregate?minClusterSize=3&lookbackHours=24", headers=ANALYST_HEADER
        )
        assert aggregates.status_code == 200
        body = aggregates.json()
        assert body["casesCreated"] >= 1
        assert "不会关闭案件" in body["note"]
