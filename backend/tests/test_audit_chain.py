"""Audit hash chain: tamper detection, offline export verification."""
import json
import os
import tempfile
import uuid
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-audit-chain-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select, update  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.models import AuditEvent  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.audit_chain import (  # noqa: E402
    GENESIS_HASH,
    append_event,
    canonical_payload,
    chain_stats,
    content_hash,
    export_events,
    verify_chain,
    verify_export,
)

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
    Base.metadata.create_all(engine)
    yield


def _workspace() -> str:
    return f"ws-{uuid.uuid4().hex[:8]}"


def _append(db, workspace: str, count: int) -> list[str]:
    ids = []
    for index in range(count):
        event_id = f"AUD-CHAIN-{uuid.uuid4().hex[:10].upper()}"
        append_event(
            db,
            event_id=event_id,
            actor=f"tester-{index}",
            action="case.update",
            object_type="case",
            object_id=f"CASE-{index}",
            outcome="completed",
            note=f"第 {index} 条记录",
            workspace_id=workspace,
        )
        ids.append(event_id)
    db.commit()
    return ids


def test_appended_events_form_a_valid_chain():
    workspace = _workspace()
    with SessionLocal() as db:
        ids = _append(db, workspace, 5)
        verification = verify_chain(db, workspace_id=workspace)
        first = db.get(AuditEvent, ids[0])
        stats = chain_stats(db, workspace_id=workspace)
    assert verification.valid is True
    assert verification.chained == 5
    assert verification.checked == 5
    assert verification.breaks == []
    assert first is not None
    assert first.sequence == 1
    assert first.prev_hash == GENESIS_HASH
    assert stats["chainedEvents"] == 5
    assert stats["unchainedEvents"] == 0


def test_editing_a_row_breaks_the_chain():
    workspace = _workspace()
    with SessionLocal() as db:
        ids = _append(db, workspace, 3)
    with SessionLocal() as db:
        db.execute(update(AuditEvent).where(AuditEvent.id == ids[1]).values(actor="attacker"))
        db.commit()
    with SessionLocal() as db:
        verification = verify_chain(db, workspace_id=workspace)
    assert verification.valid is False
    reasons = {item.reason for item in verification.breaks}
    assert "content_hash_mismatch" in reasons
    assert verification.breaks[0].event_id == ids[1]


def test_deleting_a_row_is_detected_as_a_sequence_gap():
    workspace = _workspace()
    with SessionLocal() as db:
        ids = _append(db, workspace, 3)
    with SessionLocal() as db:
        db.delete(db.get(AuditEvent, ids[1]))
        db.commit()
    with SessionLocal() as db:
        verification = verify_chain(db, workspace_id=workspace)
    assert verification.valid is False
    assert any(item.reason == "sequence_gap" for item in verification.breaks)
    assert any(item.reason == "previous_hash_mismatch" for item in verification.breaks)


def test_unchained_legacy_rows_are_reported_not_silently_trusted():
    """Rows that predate the migration keep NULL chain columns and are counted."""
    from sqlalchemy import insert

    from app.db.base import utc_now

    workspace = _workspace()
    with SessionLocal() as db:
        _append(db, workspace, 2)
        # Written through Core, bypassing the ORM listener: this is exactly what a
        # pre-migration row looks like in the table.
        db.execute(
            insert(AuditEvent.__table__).values(
                id=f"AUD-LEGACY-{uuid.uuid4().hex[:8].upper()}",
                created_at=utc_now(),
                actor="legacy",
                action="sensor.update",
                object_type="sensor",
                object_id="sensor-legacy",
                outcome="completed",
                request_id=None,
                before_state=None,
                after_state=None,
                note=None,
                workspace_id=workspace,
                sequence=None,
                prev_hash=None,
                content_hash=None,
            )
        )
        db.commit()
        verification = verify_chain(db, workspace_id=workspace)
    assert verification.unchained == 1
    assert verification.chained == 2
    assert verification.valid is True  # legacy rows are excluded from the chain check


def test_workspaces_have_independent_chains():
    first, second = _workspace(), _workspace()
    with SessionLocal() as db:
        _append(db, first, 2)
        _append(db, second, 3)
        first_check = verify_chain(db, workspace_id=first)
        second_check = verify_chain(db, workspace_id=second)
    assert first_check.chained == 2
    assert second_check.chained == 3
    assert first_check.head_hash != second_check.head_hash


def test_canonical_payload_is_independent_of_key_order():
    payload_a = canonical_payload(
        event_id="AUD-1",
        created_at=__import__("datetime").datetime(2026, 9, 10, 10, 0, 0),
        actor="a",
        action="x",
        object_type="case",
        object_id="CASE-1",
        outcome="completed",
        request_id=None,
        before_state={"b": 1, "a": 2},
        after_state=None,
        note=None,
        workspace_id="default",
        sequence=1,
    )
    payload_b = canonical_payload(
        event_id="AUD-1",
        created_at=__import__("datetime").datetime(2026, 9, 10, 10, 0, 0),
        actor="a",
        action="x",
        object_type="case",
        object_id="CASE-1",
        outcome="completed",
        request_id=None,
        before_state={"a": 2, "b": 1},
        after_state=None,
        note=None,
        workspace_id="default",
        sequence=1,
    )
    assert payload_a == payload_b
    assert content_hash(GENESIS_HASH, payload_a) == content_hash(GENESIS_HASH, payload_b)


def test_export_can_be_verified_offline_and_detects_tampering():
    workspace = _workspace()
    with SessionLocal() as db:
        _append(db, workspace, 4)
        document = export_events(db, workspace_id=workspace)
    assert document["count"] == 4
    assert document["verification"]["valid"] is True

    # Round-trip through JSON exactly as an auditor would.
    restored = json.loads(json.dumps(document))
    assert verify_export(restored)["valid"] is True

    restored["events"][1]["note"] = "被篡改的备注"
    result = verify_export(restored)
    assert result["valid"] is False
    assert result["breaks"][0]["reason"] == "content_hash_mismatch"

    removed = json.loads(json.dumps(document))
    removed["events"].pop(2)
    assert verify_export(removed)["valid"] is False


def test_export_verifier_rejects_a_malformed_document():
    assert verify_export({})["valid"] is False
    assert verify_export({"events": "not-a-list"})["valid"] is False
    assert verify_export({"events": [{"id": "x"}]})["valid"] is True  # unchained rows are skipped
    broken = {"events": [{"id": "x", "sequence": 1, "contentHash": "deadbeef", "createdAt": "nope"}]}
    assert verify_export(broken)["valid"] is False


def test_integrity_and_export_endpoints():
    workspace = _workspace()
    with SessionLocal() as db:
        _append(db, workspace, 3)
    with TestClient(app) as client:
        integrity = client.get(f"/api/v1/audit/integrity?workspaceId={workspace}")
        assert integrity.status_code == 200
        body = integrity.json()
        assert body["verification"]["valid"] is True
        assert body["stats"]["chainedEvents"] == 3

        denied = client.get(f"/api/v1/audit/export?workspaceId={workspace}")
        assert denied.status_code == 401

        exported = client.get(f"/api/v1/audit/export?workspaceId={workspace}", headers=ADMIN_HEADER)
        assert exported.status_code == 200
        document = exported.json()
        assert document["count"] == 3

        verified = client.post("/api/v1/audit/verify", json=document, headers=ADMIN_HEADER)
        assert verified.status_code == 200
        assert verified.json()["valid"] is True

        tampered = json.loads(json.dumps(document))
        tampered["events"][0]["actor"] = "attacker"
        broken = client.post("/api/v1/audit/verify", json=tampered, headers=ADMIN_HEADER)
        assert broken.json()["valid"] is False

        bad_body = client.post("/api/v1/audit/verify", json={"nope": True}, headers=ADMIN_HEADER)
        assert bad_body.status_code == 422

def test_direct_audit_writes_are_chained_by_the_mapper_listener():
    """Services construct AuditEvent(...) directly; the mapper must chain them."""
    from app.db.base import utc_now

    workspace = _workspace()
    with SessionLocal() as db:
        db.add(
            AuditEvent(
                id=f"AUD-DIRECT-{uuid.uuid4().hex[:8].upper()}",
                created_at=utc_now(),
                actor="direct-writer",
                action="sensor.update",
                object_type="sensor",
                object_id="sensor-1",
                outcome="completed",
                request_id=None,
                before_state=None,
                after_state={"state": "online"},
                note=None,
                workspace_id=workspace,
            )
        )
        db.commit()
        verification = verify_chain(db, workspace_id=workspace)
    assert verification.chained == 1
    assert verification.valid is True
    with SessionLocal() as db:
        rows = db.scalars(select(AuditEvent).where(AuditEvent.workspace_id == workspace)).all()
    assert rows[0].sequence == 1
    assert rows[0].prev_hash == GENESIS_HASH
    assert rows[0].content_hash
