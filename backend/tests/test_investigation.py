"""AI investigation: claim validation, tool whitelist, degradation, API surface."""
import json
import os
import tempfile
import time
import uuid
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-investigation-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_SENSOR_INGEST_TOKEN"] = "test-sensor-token"
os.environ["EVONIDS_ANALYST_API_TOKEN"] = "test-analyst-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db.models import Alert, EvidenceRecord, InvestigationClaim, InvestigationRun, ToolExecution  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services.agent_tools import build_registry, execute_tool, redact_text  # noqa: E402
from app.services.investigation import (  # noqa: E402
    InvestigationRequest,
    create_run,
    execute_run,
    parse_model_output,
    validate_claims,
)
from app.services.llm_gateway import LLMConfig, LLMGateway, MockProvider  # noqa: E402

SENSOR_HEADER = {"x-evonids-sensor-token": "test-sensor-token"}
ANALYST_HEADER = {"x-evonids-analyst-token": "test-analyst-token"}
ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
    """Service-level tests run without the app lifespan, so create the schema."""
    from app.db.base import Base
    from app.db.session import engine

    Base.metadata.create_all(engine)
    yield


@pytest.fixture(autouse=True)
def _pin_tokens():
    """Pin credentials on the cached settings object.

    ``get_settings()`` is process-cached and the first imported test module wins,
    so this module cannot rely on its own environment variables being visible.
    """
    from pydantic import SecretStr

    from app.core.config import get_settings

    settings = get_settings()
    previous = (settings.admin_api_token, settings.sensor_ingest_token, settings.analyst_api_token)
    settings.admin_api_token = SecretStr("test-admin-token")
    settings.sensor_ingest_token = SecretStr("test-sensor-token")
    settings.analyst_api_token = SecretStr("test-analyst-token")
    yield
    settings.admin_api_token, settings.sensor_ingest_token, settings.analyst_api_token = previous


def _eve_alert(flow_id: int, sensor: str) -> str:
    return "\n".join(
        [
            json.dumps(
                {
                    "timestamp": "2026-09-09T10:00:00+00:00",
                    "flow_id": flow_id,
                    "event_type": "flow",
                    "src_ip": "192.0.2.10",
                    "src_port": 45000,
                    "dest_ip": "10.0.0.8",
                    "dest_port": 445,
                    "proto": "TCP",
                    "flow": {"pkts_toserver": 5, "pkts_toclient": 2, "bytes_toserver": 300, "bytes_toclient": 90, "age": 2},
                }
            ),
            json.dumps(
                {
                    "timestamp": "2026-09-09T10:00:01+00:00",
                    "flow_id": flow_id,
                    "event_type": "alert",
                    "src_ip": "192.0.2.10",
                    "src_port": 45000,
                    "dest_ip": "10.0.0.8",
                    "dest_port": 445,
                    "proto": "TCP",
                    "alert": {"signature_id": 2001219, "signature": "ET SCAN port scan", "severity": 2},
                }
            ),
        ]
    )


def _seed_alert(client: TestClient) -> tuple[str, str]:
    sensor = f"inv-sensor-{uuid.uuid4().hex[:6]}"
    flow_id = abs(hash(sensor)) % 10**9
    response = client.post(
        f"/api/v1/ingestion/eve?sensorId={sensor}",
        content=_eve_alert(flow_id, sensor),
        headers={**SENSOR_HEADER, "content-type": "application/x-ndjson"},
    )
    assert response.status_code == 200
    with SessionLocal() as db:
        alert = db.scalar(select(Alert).where(Alert.sensor == sensor))
        assert alert is not None
        return alert.id, alert.flow_id or ""


def _seed_run(alert_id: str) -> str:
    """Create a run already in ``running`` so the background worker ignores it."""
    from app.db.base import utc_now

    run_id = f"INV-TEST-{uuid.uuid4().hex[:10].upper()}"
    with SessionLocal() as db:
        db.add(
            InvestigationRun(
                id=run_id,
                alert_id=alert_id,
                requested_by="test",
                state="running",
                mode="pending",
                prompt_template_version="investigation-prompt-v1",
                tool_registry_version="tools-v1",
                max_tool_calls=6,
                budget_usd=0.25,
                input_evidence_ids=[],
                retrieval={},
                summary="",
                uncertainty=1.0,
                degraded_reasons=[],
                started_at=utc_now(),
            )
        )
        db.commit()
    return run_id


def _gateway(response: str | None = None, *, provider: str = "mock") -> LLMGateway:
    if provider == "disabled":
        from app.services.llm_gateway import DisabledProvider

        return LLMGateway(LLMConfig(provider="disabled"), DisabledProvider())
    return LLMGateway(
        LLMConfig(provider="mock", model="mock-model"), MockProvider(response=response)
    )


# ------------------------------------------------------------------ parsing
def test_parse_model_output_accepts_plain_json_code_fences_and_embedded_json():
    assert parse_model_output('{"summary": "x"}')["summary"] == "x"
    assert parse_model_output('```json\n{"summary": "x"}\n```')["summary"] == "x"
    assert parse_model_output('前言 {"summary": "x"} 结尾')["summary"] == "x"
    with pytest.raises(ValueError):
        parse_model_output("")
    with pytest.raises(ValueError):
        parse_model_output("not json at all")
    with pytest.raises(ValueError):
        parse_model_output("[1, 2, 3]")


def test_validate_claims_rejects_uncited_and_out_of_scope_claims():
    payload = {
        "claims": [
            {
                "claim_type": "observation",
                "statement": "该流量命中了 ET SCAN 端口扫描签名。",
                "evidence_ids": ["EVD-OK"],
                "confidence": 1.4,
                "uncertainty": -0.2,
                "mitre_techniques": ["T1046", "not-a-technique", "t1595.001"],
            },
            {
                "claim_type": "observation",
                "statement": "没有引用证据的结论。",
                "evidence_ids": [],
            },
            {
                "claim_type": "guess",
                "statement": "未知结论类型必须被拒绝。",
                "evidence_ids": ["EVD-OK"],
            },
            {
                "claim_type": "inference",
                "statement": "引用了范围外证据。",
                "evidence_ids": ["EVD-NOT-ALLOWED"],
            },
            "not-a-dict",
        ]
    }
    accepted, reasons = validate_claims(payload, allowed_evidence_ids=["EVD-OK"])
    assert len(accepted) == 1
    assert accepted[0]["confidence"] == 1.0
    assert accepted[0]["uncertainty"] == 0.0
    assert accepted[0]["mitre_techniques"] == ["T1046", "T1595.001"]
    assert any("missing_evidence_ids" in reason for reason in reasons)
    assert any("unknown_claim_type" in reason for reason in reasons)
    assert any("evidence_outside_whitelist" in reason for reason in reasons)
    assert any("not_an_object" in reason for reason in reasons)


def test_redact_text_masks_credentials_and_bounds_length():
    assert "[redacted-key]" in redact_text("token sk-abcdefghijklmnop123456")
    assert "password=[redacted]" in redact_text("password=hunter2")
    assert "[redacted-private-key]" in redact_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
    long = redact_text("a" * 1000, limit=100)
    assert len(long) < 200 and "truncated" in long


# -------------------------------------------------------------------- tools
def test_tool_registry_rejects_unknown_tools_and_arguments():
    registry = build_registry()
    with SessionLocal() as db:
        unknown = execute_tool(db, registry, "run_shell", {"cmd": "rm -rf /"})
        assert unknown.state == "rejected"
        assert "whitelist" in (unknown.error or "")

        bad_args = execute_tool(db, registry, "get_alert", {"alertId": "x", "force": True})
        assert bad_args.state == "rejected"
        assert "unsupported arguments" in (bad_args.error or "")

        wrong_type = execute_tool(db, registry, "get_alert", {"alertId": 123})
        assert wrong_type.state == "rejected"


def test_evidence_tool_respects_the_investigation_whitelist():
    registry = build_registry()
    with TestClient(app) as client:
        _seed_alert(client)
    with SessionLocal() as db:
        row = db.scalars(select(EvidenceRecord)).first()
        assert row is not None
        allowed = execute_tool(db, registry, "get_evidence", {"evidenceId": row.id}, allowed_evidence_ids=[row.id])
        assert allowed.state == "completed"
        assert allowed.output["found"] is True
        denied = execute_tool(
            db, registry, "get_evidence", {"evidenceId": row.id}, allowed_evidence_ids=["EVD-OTHER"]
        )
        assert denied.state == "rejected"
        assert "whitelist" in (denied.error or "")


def test_knowledge_tool_returns_a_retrieval_snapshot():
    registry = build_registry()
    with SessionLocal() as db:
        result = execute_tool(db, registry, "search_knowledge", {"query": "port scan", "topK": 2})
        assert result.state == "completed"
        assert result.output["query"] == "port scan"
        assert "knowledgeVersion" in result.output


# ------------------------------------------------------------------ service
def test_execute_run_without_provider_degrades_and_claims_nothing():
    with TestClient(app) as client:
        alert_id, _ = _seed_alert(client)
    run_id = _seed_run(alert_id)
    with SessionLocal() as db:
        run = execute_run(db, run_id, gateway=_gateway(provider="disabled"))
        assert run.state == "degraded"
        assert "llm_provider_not_configured" in run.degraded_reasons
        assert "未生成任何推断结论" in run.summary
        claims = db.scalars(select(InvestigationClaim).where(InvestigationClaim.run_id == run_id)).all()
        assert claims == []
        tools = db.scalars(select(ToolExecution).where(ToolExecution.run_id == run_id)).all()
        assert {tool.tool_name for tool in tools} >= {"get_alert", "list_alert_evidence", "search_knowledge"}


def test_mock_provider_refusing_insufficient_evidence_ends_in_insufficient_state():
    with TestClient(app) as client:
        alert_id, _ = _seed_alert(client)
    run_id = _seed_run(alert_id)
    with SessionLocal() as db:
        run = execute_run(db, run_id, gateway=_gateway())
        assert run.state == "insufficient_evidence"
        assert run.uncertainty >= 0.5
        assert "MOCK PROVIDER" in run.summary


def test_valid_claims_are_persisted_with_their_evidence_and_mitre_ids():
    with TestClient(app) as client:
        alert_id, flow_id = _seed_alert(client)
    with SessionLocal() as db:
        evidence_id = db.scalar(
            select(EvidenceRecord.id).where(EvidenceRecord.source_ref_id.in_([flow_id, alert_id]))
        )
        assert evidence_id is not None
    response = json.dumps(
        {
            "summary": "该告警与端口扫描特征一致。",
            "insufficient_evidence": False,
            "uncertainty": 0.2,
            "claims": [
                {
                    "claim_type": "observation",
                    "statement": "Suricata 对同一流量命中了端口扫描签名。",
                    "evidence_ids": [evidence_id],
                    "confidence": 0.9,
                    "uncertainty": 0.1,
                    "mitre_techniques": ["T1046"],
                }
            ],
        },
        ensure_ascii=False,
    )
    run_id = _seed_run(alert_id)
    with SessionLocal() as db:
        run = execute_run(db, run_id, gateway=_gateway(response))
        assert run.state == "succeeded"
        assert run.uncertainty == 0.2
        claims = db.scalars(select(InvestigationClaim).where(InvestigationClaim.run_id == run_id)).all()
        assert len(claims) == 1
        assert claims[0].verified is True
        assert claims[0].evidence_ids == [evidence_id]
        assert claims[0].mitre_techniques == ["T1046"]
        assert run.prompt_tokens >= 0 and run.completion_tokens >= 0


def test_claims_citing_unknown_evidence_are_stored_rejected_and_run_is_insufficient():
    with TestClient(app) as client:
        alert_id, _ = _seed_alert(client)
    response = json.dumps(
        {
            "summary": "看起来像攻击。",
            "insufficient_evidence": False,
            "uncertainty": 0.1,
            "claims": [
                {
                    "claim_type": "inference",
                    "statement": "攻击者来自内部主机。",
                    "evidence_ids": ["EVD-DOES-NOT-EXIST"],
                    "confidence": 0.95,
                }
            ],
        },
        ensure_ascii=False,
    )
    run_id = _seed_run(alert_id)
    with SessionLocal() as db:
        run = execute_run(db, run_id, gateway=_gateway(response))
        assert run.state == "insufficient_evidence"
        claims = db.scalars(select(InvestigationClaim).where(InvestigationClaim.run_id == run_id)).all()
        assert len(claims) == 1
        assert claims[0].verified is False
        assert "evidence_outside_whitelist" in (claims[0].rejection_reason or "")
        assert any("claim_rejected" in reason for reason in run.degraded_reasons)


def test_run_detail_exposes_claims_tools_and_retrieval_snapshot():
    with TestClient(app) as client:
        alert_id, _ = _seed_alert(client)
    run_id = _seed_run(alert_id)
    with SessionLocal() as db:
        execute_run(db, run_id, gateway=_gateway())
    with TestClient(app) as client:
        detail = client.get(f"/api/v1/investigations/{run_id}")
        assert detail.status_code == 200
        payload = detail.json()
        assert payload["run"]["id"] == run_id
        assert payload["run"]["promptTemplateVersion"] == "investigation-prompt-v1"
        assert payload["run"]["toolRegistryVersion"] == "tools-v1"
        assert payload["run"]["retrieval"]["embeddingModel"]
        assert payload["run"]["knowledgeVersion"].startswith("knowledge-")
        assert isinstance(payload["claims"], list)
        assert {tool["toolName"] for tool in payload["tools"]} >= {"get_alert", "search_knowledge"}
        assert payload["feedback"] == []


# ---------------------------------------------------------------------- API
def test_investigation_api_requires_analyst_auth_and_queues_work():
    with TestClient(app) as client:
        alert_id, _ = _seed_alert(client)
        denied = client.post("/api/v1/investigations", json={"alertId": alert_id})
        assert denied.status_code == 401

        # An admin credential is a superset of the analyst scope: the console holds
        # a single server-side admin token, so admin must be able to start an
        # investigation (the resolved principal keeps its real scope for audit).
        admin_started = client.post(
            "/api/v1/investigations", json={"alertId": alert_id}, headers=ADMIN_HEADER
        )
        assert admin_started.status_code == 202

        queued = client.post(
            "/api/v1/investigations", json={"alertId": alert_id, "maxToolCalls": 3}, headers=ANALYST_HEADER
        )
        assert queued.status_code == 202
        run_id = queued.json()["id"]
        assert queued.json()["state"] in {"queued", "running"}

        listing = client.get(f"/api/v1/investigations?alertId={alert_id}").json()
        assert listing["total"] >= 1

        deadline = time.time() + 20
        state = "queued"
        while time.time() < deadline:
            state = client.get(f"/api/v1/investigations/{run_id}").json()["run"]["state"]
            if state not in {"queued", "running"}:
                break
            time.sleep(0.2)
        assert state in {"succeeded", "insufficient_evidence", "degraded", "failed"}

        missing = client.get("/api/v1/investigations/INV-DOES-NOT-EXIST")
        assert missing.status_code == 404
        assert missing.json()["error"] == "not_found"


def test_feedback_endpoint_records_human_labels_and_audits_them():
    with TestClient(app) as client:
        alert_id, _ = _seed_alert(client)
        queued = client.post("/api/v1/investigations", json={"alertId": alert_id}, headers=ANALYST_HEADER)
        run_id = queued.json()["id"]
        feedback = client.post(
            f"/api/v1/investigations/{run_id}/feedback",
            json={
                "objectType": "investigation_run",
                "objectId": run_id,
                "verdict": "agree",
                "label": "malicious",
                "comment": "人工复核确认端口扫描。",
            },
            headers=ANALYST_HEADER,
        )
        assert feedback.status_code == 201
        assert feedback.json()["verdict"] == "agree"

        mismatched = client.post(
            f"/api/v1/investigations/{run_id}/feedback",
            json={"objectType": "investigation_run", "objectId": "INV-OTHER", "verdict": "disagree"},
            headers=ANALYST_HEADER,
        )
        assert mismatched.status_code == 400

        detail = client.get(f"/api/v1/investigations/{run_id}").json()
        assert any(item["label"] == "malicious" for item in detail["feedback"])


def test_llm_status_and_probe_are_admin_only(monkeypatch):
    from app.core.config import get_settings
    from app.services.llm_gateway import reset_gateway

    # Settings are process-cached and another test module may have imported the
    # app first, so pin the provider explicitly and rebuild the gateway.
    monkeypatch.setattr(get_settings(), "llm_provider", "mock")
    monkeypatch.setattr(get_settings(), "llm_model", "mock-model")
    reset_gateway()
    with TestClient(app) as client:
        assert client.get("/api/v1/llm/status").status_code == 401
        status = client.get("/api/v1/llm/status", headers=ADMIN_HEADER)
        assert status.status_code == 200
        payload = status.json()
        assert payload["provider"] == "mock"
        assert payload["circuit"]["state"] in {"open", "closed"}
        assert payload["budget"]["dailyBudgetUsd"] > 0

        probe = client.post("/api/v1/llm/probe", headers=ADMIN_HEADER)
        assert probe.status_code == 200
        assert probe.json()["models"] == ["mock-model"]
        assert probe.json()["configuredModelExists"] is True
    reset_gateway()


def test_create_run_is_idempotent_while_a_run_is_pending():
    with TestClient(app) as client:
        alert_id, _ = _seed_alert(client)
    with SessionLocal() as db:
        first = create_run(db, InvestigationRequest(alert_id=alert_id, case_id=None, requested_by="t"))
        second = create_run(db, InvestigationRequest(alert_id=alert_id, case_id=None, requested_by="t"))
        assert first.id == second.id
        first.state = "succeeded"
        db.commit()
        third = create_run(db, InvestigationRequest(alert_id=alert_id, case_id=None, requested_by="t"))
        assert third.id != first.id


def test_flow_without_alert_is_rejected_with_404():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/investigations", json={"alertId": "ALT-DOES-NOT-EXIST"}, headers=ANALYST_HEADER
        )
        assert response.status_code == 404
        assert response.json()["error"] == "not_found"
