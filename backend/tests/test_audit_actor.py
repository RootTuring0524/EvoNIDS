"""Audit-actor normalization: client-supplied actor values are ignored; the
server-side resolved principal (env:admin / apikey:*) is recorded instead."""
import os
import tempfile
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-audit-actor-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}

EVE_ALERT = (
    '{"timestamp":"2026-09-07T10:00:01+08:00","flow_id":8001,"event_type":"alert",'
    '"src_ip":"192.0.2.10","src_port":51000,"dest_ip":"10.0.0.8","dest_port":80,'
    '"proto":"TCP","alert":{"signature_id":2200451,"signature":"ET SCAN port scan",'
    '"severity":2}}\n'
)


def _import_one_alert(client) -> str:
    imported = client.post(
        "/api/v1/ingestion/eve?sensorId=lab-core-01",
        content=EVE_ALERT,
        headers={"content-type": "application/x-ndjson"},
    )
    assert imported.status_code == 200
    alerts = client.get("/api/v1/alerts").json()["items"]
    return alerts[0]["id"]


def _audit_items(client, *, object_type: str, search: str):
    response = client.get(
        f"/api/v1/audit?objectType={object_type}&search={search}",
        headers=ADMIN_HEADER,
    )
    assert response.status_code == 200
    return response.json()["items"]


def test_alert_patch_audit_actor_is_principal_not_client_value():
    with TestClient(app) as client:
        alert_id = _import_one_alert(client)
        patched = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"owner": "alice", "actor": "spoofed-actor", "note": "assignment"},
            headers=ADMIN_HEADER,
        )
        assert patched.status_code == 200
        items = _audit_items(client, object_type="alert", search="alert.update")
        assert any(item["actor"] == "env:admin" for item in items)
        assert not any(item["actor"] == "spoofed-actor" for item in items)


def test_rag_evidence_audit_actor_is_principal_not_query_value():
    with TestClient(app) as client:
        payload = {
            "id": "AUD-ACTOR-EV-1",
            "title": "Audit actor test evidence",
            "sourceType": "协议知识",
            "sourceId": "PROTO-TCP-1",
            "trust": "high",
            "excerpt": "TCP handshake semantics used only for this test.",
            "purpose": "Test that evidence writes record the authenticated principal.",
            "publishedAt": "2026-09-07T00:00:00+08:00",
        }
        created = client.post(
            "/api/v1/rag/evidence?actor=spoofed-actor",
            json=payload,
            headers=ADMIN_HEADER,
        )
        assert created.status_code == 201
        items = _audit_items(client, object_type="knowledge_evidence", search="knowledge.created")
        matching = [item for item in items if item["objectId"] == "AUD-ACTOR-EV-1"]
        assert matching and matching[0]["actor"] == "env:admin"


def test_rule_transition_audit_actor_is_principal():
    with TestClient(app) as client:
        alert_id = _import_one_alert(client)
        evidence = client.post(
            "/api/v1/rag/evidence",
            json={
                "id": "AUD-ACTOR-EV-2",
                "title": "Port scan knowledge",
                "sourceType": "协议知识",
                "sourceId": "PROTO-TCP-2",
                "trust": "high",
                "excerpt": "Port scans are reconnaissance.",
                "purpose": "Rule evidence fixture.",
                "publishedAt": "2026-09-07T00:00:00+08:00",
            },
            headers=ADMIN_HEADER,
        )
        assert evidence.status_code == 201
        candidate = client.post(
            "/api/v1/rules",
            json={
                "source": "analyst",
                "sourceAlertId": alert_id,
                "rationale": "Port scan rule for audit actor regression.",
                "structured": {
                    "rule_id": "RULE-AUDIT-ACTOR-1",
                    "rule_name": "Audit actor port scan",
                    "description": "Many destination ports from one source.",
                    "attack_type": "Port Scan",
                    "severity": "high",
                    "attack_stage": "reconnaissance",
                    "mitre_technique_ids": ["T1046"],
                    "conditions": [
                        {
                            "field": "destination_port_count_60s",
                            "operator": ">",
                            "value": 50,
                        }
                    ],
                    "evidence_ids": ["AUD-ACTOR-EV-2"],
                    "generated_by": "analyst",
                    "version": 1,
                    "parent_rule_id": None,
                },
                "author": "analyst-alice",
                "actor": "spoofed-actor",
            },
            headers=ADMIN_HEADER,
        )
        assert candidate.status_code == 201
        items = _audit_items(client, object_type="rule", search="rule.candidate")
        matching = [item for item in items if item["objectId"] == "RULE-AUDIT-ACTOR-1"]
        assert matching and matching[0]["actor"] == "env:admin"
        assert not any(item["actor"] == "spoofed-actor" for item in matching)
