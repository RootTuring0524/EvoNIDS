"""Rule governance additions: corpus guard, structured bridge, regression, monitoring."""
import os
import tempfile
import uuid
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-rule-governance2-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.models import Rule  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.replay_corpus import CorpusPathError, corpus_summary, validate_capture_path  # noqa: E402
from app.services.rule_bridge import assess_conditions, structured_to_ir  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}

STRUCTURED = {
    "rule_id": "RULE-BRIDGE-1",
    "rule_name": "SMB 端口扫描",
    "description": "检测对 445 的端口扫描",
    "attack_type": "Port Scan",
    "severity": "high",
    "attack_stage": "recon",
    "mitre_technique_ids": ["T1046"],
    "generated_by": "agent",
    "version": 1,
    "evidence_ids": ["EVD-1"],
    "conditions": [
        {"field": "dst_port", "operator": "==", "value": 445},
        {"field": "protocol", "operator": "==", "value": "TCP"},
        {"field": "destination_port_count_60s", "operator": ">=", "value": 20},
        {"field": "syn_ratio", "operator": ">", "value": 0.8},
        {"field": "flow_duration", "operator": ">", "value": 10},
    ],
}


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
    Base.metadata.create_all(engine)
    yield


@pytest.fixture()
def corpus(tmp_path):
    root = tmp_path / "replay-corpus"
    root.mkdir(parents=True, exist_ok=True)
    (root / "normal.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 32)
    (root / "malicious.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 32)
    return root


def _seed_rule() -> str:
    rule_id = f"RULE-BRIDGE-{uuid.uuid4().hex[:8].upper()}"
    with SessionLocal() as db:
        db.add(
            Rule(
                id=rule_id,
                name="桥接测试规则",
                stage="confirmed",
                source="agent",
                severity="high",
                author="tester",
                revision=1,
                content="",
                rationale="test",
            )
        )
        db.commit()
    return rule_id


# ---------------------------------------------------------------- corpus guard
def test_capture_path_must_live_inside_the_corpus(tmp_path, corpus):
    inside = validate_capture_path(str(corpus / "normal.pcap"), corpus_root=corpus)
    assert inside is not None and inside.size_bytes > 0
    relative = validate_capture_path("normal.pcap", corpus_root=corpus)
    assert relative is not None

    outside = tmp_path / "secrets.pcap"
    outside.write_bytes(b"\x00" * 16)
    with pytest.raises(CorpusPathError) as error:
        validate_capture_path(str(outside), corpus_root=corpus)
    assert "corpus root" in str(error.value)

    with pytest.raises(CorpusPathError):
        validate_capture_path(str(corpus / ".." / "secrets.pcap"), corpus_root=corpus)
    with pytest.raises(CorpusPathError):
        validate_capture_path(str(corpus / "normal.txt"), corpus_root=corpus)
    assert validate_capture_path(None, corpus_root=corpus) is None


def test_corpus_summary_reports_what_exists(tmp_path):
    empty = corpus_summary(tmp_path / "nothing")
    assert empty["exists"] is False
    assert "不存在" in str(empty["note"])

    root = tmp_path / "corpus"
    root.mkdir()
    (root / "a.pcap").write_bytes(b"x")
    summary = corpus_summary(root)
    assert summary["exists"] is True
    assert summary["captures"] == ["a.pcap"]


def test_sandbox_api_rejects_a_capture_outside_the_corpus(corpus, monkeypatch):
    monkeypatch.setattr(get_settings(), "replay_corpus_root", str(corpus))
    rule_id = _seed_rule()
    with TestClient(app) as client:
        compiled = client.post(
            f"/api/v1/rule-governance/rules/{rule_id}/compile",
            json={
                "ir": {
                    "header": {
                        "action": "alert",
                        "protocol": "tcp",
                        "source": "$HOME_NET",
                        "sourcePort": "any",
                        "direction": "->",
                        "destination": "$EXTERNAL_NET",
                        "destinationPort": "445",
                    },
                    "contents": [{"pattern": "SMB", "nocase": True}],
                    "meta": {"sid": 1_000_900, "rev": 1, "msg": "corpus guard test"},
                }
            },
            headers=ADMIN_HEADER,
        )
        assert compiled.status_code == 201
        version_id = compiled.json()["id"]

        outside = client.post(
            f"/api/v1/rule-governance/rules/{rule_id}/versions/{version_id}/sandbox",
            json={"normalPcap": str(corpus.parent / "secrets.pcap"), "maliciousPcap": "malicious.pcap"},
            headers=ADMIN_HEADER,
        )
        assert outside.status_code == 201
        body = outside.json()
        assert body["status"] == "blocked"
        assert "corpus root" in (body["blockedReason"] or "")
        assert body["metrics"] == {}


# ---------------------------------------------------------------- structured bridge
def test_conditions_are_classified_as_supported_approximate_and_unsupported():
    supported, approximate, unsupported = assess_conditions(STRUCTURED["conditions"])
    assert [item.condition["field"] for item in supported] == [
        "dst_port",
        "protocol",
        "destination_port_count_60s",
    ]
    assert [item.condition["field"] for item in approximate] == ["syn_ratio"]
    assert [item.condition["field"] for item in unsupported] == ["flow_duration"]
    assert "没有对应匹配项" in unsupported[0].reason


def test_bridge_refuses_a_lossy_conversion_until_it_is_acknowledged():
    refused = structured_to_ir(STRUCTURED, sid=1_000_901)
    assert refused.compilable is False
    assert refused.ir_document is None
    assert "无法精确编译" in refused.notes[-1]

    accepted = structured_to_ir(STRUCTURED, sid=1_000_901, accept_partial=True)
    assert accepted.compilable is True
    assert accepted.suricata_text is not None
    assert "sid:1000901" in accepted.suricata_text
    assert "flags:S" in accepted.suricata_text
    assert "detection_filter: track by_src" in accepted.suricata_text
    assert "445" in accepted.suricata_text
    # The dropped conditions are recorded on the rule itself, not just in the response.
    metadata = accepted.ir_document["meta"]["metadata"]
    assert metadata["partial_conversion"] == "true"
    assert int(metadata["dropped_conditions"]) == 2


def test_bridge_refuses_when_nothing_maps_to_a_detection_option():
    result = structured_to_ir(
        {
            "rule_name": "只有流统计",
            "attack_type": "Unknown",
            "conditions": [{"field": "flow_duration", "operator": ">", "value": 5}],
        },
        sid=1_000_902,
        accept_partial=True,
    )
    assert result.compilable is False
    assert "没有任何条件可以映射" in result.notes[0]


def test_bridge_api_returns_the_dropped_conditions():
    rule_id = _seed_rule()
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/rule-governance/rules/{rule_id}/from-structured",
            json={"structured": STRUCTURED, "acceptPartial": True},
            headers=ADMIN_HEADER,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["compilable"] is True
        assert payload["droppedCount"] == 2
        assert [item["condition"]["field"] for item in payload["unsupported"]] == ["flow_duration"]
        assert payload["suricataText"].startswith("alert tcp")

        missing = client.post(
            "/api/v1/rule-governance/rules/RULE-DOES-NOT-EXIST/from-structured",
            json={"structured": STRUCTURED},
            headers=ADMIN_HEADER,
        )
        assert missing.status_code == 404

        denied = client.post(
            f"/api/v1/rule-governance/rules/{rule_id}/from-structured",
            json={"structured": STRUCTURED},
        )
        assert denied.status_code == 401


# ---------------------------------------------------------------- monitoring
def test_monitoring_endpoint_404s_for_an_unknown_deployment():
    with TestClient(app) as client:
        response = client.get("/api/v1/rule-governance/deployments/RDEP-NOPE/monitoring")
        assert response.status_code == 404
        assert response.json()["error"] == "not_found"


def test_corpus_endpoint_reports_the_configured_root(monkeypatch, tmp_path):
    root = tmp_path / "corpus-api"
    root.mkdir()
    monkeypatch.setattr(get_settings(), "replay_corpus_root", str(root))
    with TestClient(app) as client:
        payload = client.get("/api/v1/rule-governance/corpus").json()
    assert payload["exists"] is True
    assert payload["captures"] == []


def test_sandbox_regression_field_is_accepted():
    """The request schema must carry the regression reference through."""
    from app.schemas.api import RuleSandboxRequest

    request = RuleSandboxRequest.model_validate(
        {"normalPcap": "normal.pcap", "regressionVersionId": "RIRV-1"}
    )
    assert request.regression_version_id == "RIRV-1"
