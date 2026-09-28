"""Rule governance: sandbox honesty, deployment gating, canary promote and rollback."""
import json
import os
import tempfile
import uuid
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-rule-governance-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_SENSOR_INGEST_TOKEN"] = "test-sensor-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db.models import AuditEvent, Rule, RuleDeployment, RuleIRVersion, RuleSandboxRun  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services.rule_deployment import (  # noqa: E402
    compile_rule_ir,
    create_sensor_group,
    deploy_rule,
    promote_deployment,
    rollback_deployment,
)
from app.services.rule_sandbox import (  # noqa: E402
    ReplayOutcome,
    UnavailableExecutor,
    evaluate_replay,
    validate_rule,
)

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
    from app.db.base import Base
    from app.db.session import engine

    Base.metadata.create_all(engine)
    yield


@pytest.fixture(autouse=True)
def _pin_admin_token():
    from pydantic import SecretStr

    from app.core.config import get_settings

    settings = get_settings()
    previous = settings.admin_api_token
    settings.admin_api_token = SecretStr("test-admin-token")
    yield
    settings.admin_api_token = previous

IR_DOCUMENT = {
    "header": {
        "action": "alert",
        "protocol": "tcp",
        "source": "$HOME_NET",
        "sourcePort": "any",
        "direction": "->",
        "destination": "$EXTERNAL_NET",
        "destinationPort": "any",
    },
    "contents": [{"pattern": "ET SCAN", "nocase": True}],
    "flow": "to_server",
    "meta": {
        "sid": 1_000_500,
        "rev": 1,
        "msg": "测试用端口扫描规则",
        "classtype": "attempted-recon",
        "mitreTechniques": ["T1046"],
    },
}


class FakeSuricata:
    """Deterministic stand-in for the Suricata binary (tests only)."""

    def __init__(self, *, syntax_ok=True, malicious_alert_flows=(), normal_alert_flows=(), available=True):
        self.syntax_ok = syntax_ok
        self.malicious_alert_flows = tuple(malicious_alert_flows)
        self.normal_alert_flows = tuple(normal_alert_flows)
        self.available = available
        self.replays: list[str] = []

    def version(self):
        return "Suricata 7.0.0 (fake)" if self.available else None

    def check_syntax(self, rule_text):
        return self.syntax_ok, "fake syntax output"

    def replay(self, pcap_path, rule_text, *, workdir):
        self.replays.append(pcap_path)
        flows = self.normal_alert_flows if "normal" in pcap_path else self.malicious_alert_flows
        lines = [
            json.dumps(
                {
                    "event_type": "alert",
                    "flow_id": flow_id,
                    "alert": {"signature_id": 1_000_500, "signature": "test"},
                }
            )
            for flow_id in flows
        ]
        (Path(workdir) / "eve.json").write_text("\n".join(lines), encoding="utf-8")
        return ReplayOutcome(exit_code=0, alerts=tuple(json.loads(line) for line in lines), stdout="", stderr="", duration_ms=12.5)


@pytest.fixture
def corpus(tmp_path):
    """A temporary replay corpus with the two labelled captures the sandbox needs."""
    root = tmp_path / "replay-corpus"
    root.mkdir(parents=True, exist_ok=True)
    normal = root / "normal.pcap"
    malicious = root / "malicious.pcap"
    normal.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    malicious.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    return root


def _captures(corpus):
    return str(corpus / "normal.pcap"), str(corpus / "malicious.pcap")


def _seed_rule(actor: str = "tester") -> tuple[str, str]:
    rule_id = f"RULE-TEST-{uuid.uuid4().hex[:8].upper()}"
    with SessionLocal() as db:
        db.add(
            Rule(
                id=rule_id,
                name="测试规则",
                stage="confirmed",
                source="analyst",
                severity="medium",
                author="tester",
                revision=1,
                content="",
                rationale="test",
            )
        )
        db.commit()
        version = compile_rule_ir(db, rule_id=rule_id, ir_payload=IR_DOCUMENT, actor=actor)
    return rule_id, version.id


def test_replay_metrics_are_computed_from_real_alert_output():
    malicious = ReplayOutcome(
        exit_code=0,
        alerts=(
            {"flow_id": "1", "alert": {"signature_id": 1_000_500}},
            {"flow_id": "2", "alert": {"signature_id": 1_000_500}},
        ),
        stdout="",
        stderr="",
        duration_ms=10.0,
    )
    normal = ReplayOutcome(
        exit_code=0,
        alerts=({"flow_id": "9", "alert": {"signature_id": 1_000_500}},),
        stdout="",
        stderr="",
        duration_ms=20.0,
    )
    metrics = evaluate_replay(malicious=malicious, normal=normal, sid=1_000_500, malicious_flows=4, normal_flows=1000)
    assert metrics.true_positives == 2
    assert metrics.false_negatives == 2
    assert metrics.recall == 0.5
    assert metrics.false_positives == 1
    assert metrics.false_positives_per_million == 1000.0
    assert metrics.precision == round(2 / 3, 6)
    assert metrics.replay_seconds == 0.03
    assert metrics.as_dict()["measured"]["recall"] is True


def test_unavailable_suricata_is_recorded_as_blocked_without_metrics(corpus):
    rule_id, version_id = _seed_rule()
    with SessionLocal() as db:
        run = validate_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            normal_pcap=_captures(corpus)[0],
            malicious_pcap=_captures(corpus)[1],
            executor=UnavailableExecutor("suricata binary not found on PATH"),
            corpus_root=corpus,
        )
        assert run.status == "blocked"
        assert run.suricata_available is False
        assert run.passed is False
        assert run.metrics == {}
        assert "suricata" in (run.blocked_reason or "").lower() or "not f" in (run.blocked_reason or "").lower()
        assert run.checks[0]["passed"] is False


def test_syntax_failure_short_circuits_validation(corpus):
    rule_id, version_id = _seed_rule()
    with SessionLocal() as db:
        run = validate_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            normal_pcap=_captures(corpus)[0],
            malicious_pcap=_captures(corpus)[1],
            executor=FakeSuricata(syntax_ok=False),
            corpus_root=corpus,
        )
        assert run.status == "failed"
        assert run.syntax_passed is False
        assert run.passed is False
        assert run.metrics == {}


def test_missing_pcaps_produce_partial_run_and_no_metrics(corpus):
    rule_id, version_id = _seed_rule()
    with SessionLocal() as db:
        run = validate_rule(db, rule_id=rule_id, version_id=version_id, executor=FakeSuricata(),
            corpus_root=corpus)
        assert run.status == "partial"
        assert run.syntax_passed is True
        assert run.metrics == {}
        assert run.passed is False


def test_full_replay_passes_only_when_thresholds_are_met(corpus):
    rule_id, version_id = _seed_rule()
    good = FakeSuricata(malicious_alert_flows=("1", "2", "3", "4"), normal_alert_flows=())
    with SessionLocal() as db:
        passed = validate_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            normal_pcap=_captures(corpus)[0],
            malicious_pcap=_captures(corpus)[1],
            malicious_flows=4,
            normal_flows=1_000_000,
            executor=good,
            corpus_root=corpus,
        )
        assert passed.status == "validated"
        assert passed.passed is True
        assert passed.metrics["recall"] == 1.0
        assert passed.metrics["falsePositivesPerMillion"] == 0.0

        weak = FakeSuricata(malicious_alert_flows=("1",), normal_alert_flows=("7", "8"))
        failed = validate_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            normal_pcap=_captures(corpus)[0],
            malicious_pcap=_captures(corpus)[1],
            malicious_flows=10,
            normal_flows=1000,
            executor=weak,
            corpus_root=corpus,
        )
        assert failed.status == "validation_failed"
        assert failed.passed is False
        assert failed.metrics["recall"] == 0.1
        assert failed.metrics["falsePositivesPerMillion"] == 2000.0


def test_deployment_requires_a_passed_sandbox_run_and_production_group_for_full_deploy(corpus):
    rule_id, version_id = _seed_rule()
    with SessionLocal() as db:
        canary_group = create_sensor_group(
            db, name="canary", sensor_ids=[], stage="canary", actor="tester"
        )
        prod_group = create_sensor_group(
            db, name="prod", sensor_ids=[], stage="production", actor="tester"
        )
        with pytest.raises(Exception) as error:
            deploy_rule(db, rule_id=rule_id, version_id=version_id, sensor_group_id=canary_group.id, actor="tester")
        assert "sandbox" in str(error.value).lower()

        validate_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            normal_pcap=_captures(corpus)[0],
            malicious_pcap=_captures(corpus)[1],
            malicious_flows=4,
            normal_flows=1000,
            executor=FakeSuricata(malicious_alert_flows=("1", "2", "3", "4")),
            corpus_root=corpus,
        )
        canary = deploy_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            sensor_group_id=canary_group.id,
            actor="tester",
        )
        assert canary.state == "canary"
        rule = db.get(Rule, rule_id)
        assert rule is not None and rule.stage == "canary"

        with pytest.raises(Exception) as error:
            deploy_rule(
                db,
                rule_id=rule_id,
                version_id=version_id,
                sensor_group_id=canary_group.id,
                actor="tester",
                state="deployed",
            )
        assert "production" in str(error.value).lower()

        with pytest.raises(Exception) as error:
            promote_deployment(db, deployment_id=canary.id, actor="tester")
        assert "production" in str(error.value).lower()

        promoted = promote_deployment(
            db, deployment_id=canary.id, actor="tester", target_group_id=prod_group.id
        )
        assert promoted.state == "deployed"
        assert promoted.sensor_group_id == prod_group.id
        assert promoted.promoted_at is not None
        db.refresh(canary)
        assert canary.state == "deployed"

        with pytest.raises(Exception) as error:
            rollback_deployment(db, deployment_id=canary.id, actor="tester", reason="too short")
        assert "reason" in str(error.value).lower()

        rolled = rollback_deployment(
            db,
            deployment_id=promoted.id,
            actor="tester",
            reason="生产误报率升高，按 Runbook 回滚。",
        )
        assert rolled.state == "rolled_back"
        assert rolled.rollback_reason is not None
        assert db.get(Rule, rule_id).stage == "rolled_back"  # type: ignore[union-attr]
        actions = {row.action for row in db.scalars(select(AuditEvent).where(AuditEvent.object_id == rule_id)).all()}
        assert {"rule.compiled", "rule.canary", "rule.promoted", "rule.rolled_back"} <= actions


def test_governance_api_compiles_validates_and_reports_capability():
    rule_id, _ = _seed_rule()
    with TestClient(app) as client:
        capability = client.get("/api/v1/rule-governance/sandbox-capability")
        assert capability.status_code == 200
        body = capability.json()
        assert set(body) >= {"suricataAvailable", "binary", "executorVersion", "note"}
        # The payload also reports the replay corpus inventory and what resource
        # measurement this host can actually do (both honest, never guessed).
        assert "corpus" in body and "resources" in body
        # On this host Suricata is not installed; the note must say so.
        if body["suricataAvailable"] is False:
            assert "未安装" in body["note"]

        assert client.post(f"/api/v1/rule-governance/rules/{rule_id}/compile", json={"ir": IR_DOCUMENT}).status_code == 401

        compiled = client.post(
            f"/api/v1/rule-governance/rules/{rule_id}/compile",
            json={"ir": IR_DOCUMENT},
            headers=ADMIN_HEADER,
        )
        assert compiled.status_code == 201
        payload = compiled.json()
        assert payload["sid"] == 1_000_500
        assert payload["suricataText"].startswith("alert tcp")
        assert payload["version"] >= 1

        bad = client.post(
            f"/api/v1/rule-governance/rules/{rule_id}/compile",
            json={"ir": {**IR_DOCUMENT, "meta": {**IR_DOCUMENT["meta"], "sid": 42}}},
            headers=ADMIN_HEADER,
        )
        assert bad.status_code == 422
        assert bad.json()["error"] == "validation_error"

        versions = client.get(f"/api/v1/rule-governance/rules/{rule_id}/versions").json()
        assert len(versions) >= 2
        version_id = versions[0]["id"]

        sandbox = client.post(
            f"/api/v1/rule-governance/rules/{rule_id}/versions/{version_id}/sandbox",
            json={},
            headers=ADMIN_HEADER,
        )
        assert sandbox.status_code == 201
        run = sandbox.json()
        assert run["suricataAvailable"] is False
        assert run["status"] == "blocked"
        assert run["metrics"] == {}
        assert run["passed"] is False

        runs = client.get(f"/api/v1/rule-governance/rules/{rule_id}/sandbox-runs").json()
        assert len(runs) >= 1

        deployments = client.get(f"/api/v1/rule-governance/rules/{rule_id}/deployments").json()
        assert deployments["items"] == []


def test_sensor_group_api_validates_membership_and_records_audit():
    with TestClient(app) as client:
        denied = client.post(
            "/api/v1/rule-governance/sensor-groups",
            json={"name": "x", "sensorIds": []},
        )
        assert denied.status_code == 401

        created = client.post(
            "/api/v1/rule-governance/sensor-groups",
            json={"name": f"canary-{uuid.uuid4().hex[:6]}", "sensorIds": [], "stage": "canary"},
            headers=ADMIN_HEADER,
        )
        assert created.status_code == 201
        assert created.json()["stage"] == "canary"

        unknown = client.post(
            "/api/v1/rule-governance/sensor-groups",
            json={"name": "bad", "sensorIds": ["sensor-does-not-exist"], "stage": "canary"},
            headers=ADMIN_HEADER,
        )
        assert unknown.status_code == 422

        listing = client.get("/api/v1/rule-governance/sensor-groups").json()
        assert any(item["id"] == created.json()["id"] for item in listing["items"])

    with SessionLocal() as db:
        audits = db.scalars(select(AuditEvent).where(AuditEvent.action == "sensor_group.created")).all()
        assert audits


def test_deployment_records_previous_version_for_rollback_chain(corpus):
    rule_id, version_id = _seed_rule()
    with SessionLocal() as db:
        group = create_sensor_group(db, name="prod2", sensor_ids=[], stage="production", actor="tester")
        validate_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            normal_pcap=_captures(corpus)[0],
            malicious_pcap=_captures(corpus)[1],
            malicious_flows=2,
            normal_flows=100,
            executor=FakeSuricata(malicious_alert_flows=("1", "2")),
            corpus_root=corpus,
        )
        first = deploy_rule(
            db,
            rule_id=rule_id,
            version_id=version_id,
            sensor_group_id=group.id,
            actor="tester",
            state="deployed",
        )
        assert first.previous_version_id is None

        second_version = compile_rule_ir(
            db,
            rule_id=rule_id,
            ir_payload={**IR_DOCUMENT, "meta": {**IR_DOCUMENT["meta"], "rev": 2}},
            actor="tester",
            sid=1_000_500,
        )
        validate_rule(
            db,
            rule_id=rule_id,
            version_id=second_version.id,
            normal_pcap=_captures(corpus)[0],
            malicious_pcap=_captures(corpus)[1],
            malicious_flows=2,
            normal_flows=100,
            executor=FakeSuricata(malicious_alert_flows=("1", "2")),
            corpus_root=corpus,
        )
        second = deploy_rule(
            db,
            rule_id=rule_id,
            version_id=second_version.id,
            sensor_group_id=group.id,
            actor="tester",
            state="deployed",
        )
        assert second.previous_version_id == version_id
        rollback_deployment(
            db, deployment_id=second.id, actor="tester", reason="回滚到上一版本以验证链路。"
        )
        rule = db.get(Rule, rule_id)
        assert rule is not None
        assert rule.active_version_id == version_id
        assert db.scalars(select(RuleDeployment)).all()
        assert db.scalars(select(RuleIRVersion)).all()
        assert db.scalars(select(RuleSandboxRun)).all()
