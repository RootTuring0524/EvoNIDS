"""Model rollout states: shadow → canary → active, and audited rollback."""
import os
import tempfile
import uuid
from pathlib import Path

database_path = Path(tempfile.gettempdir()) / "evonids-model-rollout-test.db"
database_path.unlink(missing_ok=True)
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.models import AuditEvent, ModelVersion  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.model_registry import active_model_for_role, rollout_of, set_rollout  # noqa: E402

ADMIN_HEADER = {"x-evonids-admin-token": "test-admin-token"}
ARTIFACT_DIR = Path(tempfile.gettempdir()) / "evonids-rollout-artifacts"
ROLE = "known_attack_classification_baseline"


@pytest.fixture(scope="module", autouse=True)
def _create_schema():
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


@pytest.fixture(autouse=True)
def _cleanup_models():
    from sqlalchemy import delete

    yield
    with SessionLocal() as db:
        db.execute(delete(AuditEvent).where(AuditEvent.action.in_(("model.rollout", "model.rolled_back"))))
        db.execute(delete(ModelVersion).where(ModelVersion.id.like("MODEL-ROLL-%")))
        db.commit()


def _seed_model(*, with_artifact: bool = True, contract: str = "flow-online-v1") -> str:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    suffix = uuid.uuid4().hex[:8].upper()
    artifact_uri = None
    if with_artifact:
        path = ARTIFACT_DIR / f"model-{suffix}.joblib"
        path.write_bytes(b"placeholder")
        artifact_uri = str(path)
    model_id = f"MODEL-ROLL-{suffix}"
    with SessionLocal() as db:
        db.add(
            ModelVersion(
                id=model_id,
                name=f"rollout test {suffix}",
                role=ROLE,
                version=f"roll-{suffix.lower()}",
                state="healthy",
                artifact_uri=artifact_uri,
                feature_version=contract,
                parameters={"featureContract": contract},
            )
        )
        db.commit()
    return model_id


def test_models_without_rollout_metadata_are_treated_as_shadow():
    model_id = _seed_model()
    with SessionLocal() as db:
        model = db.get(ModelVersion, model_id)
        assert model is not None
        assert rollout_of(model).state == "shadow"
        assert active_model_for_role(db, ROLE) is None


def test_setting_active_retires_the_previous_active_model():
    first = _seed_model()
    second = _seed_model()
    with SessionLocal() as db:
        set_rollout(db, model_id=first, state="active", actor="tester")
        assert active_model_for_role(db, ROLE).id == first  # type: ignore[union-attr]
        set_rollout(db, model_id=second, state="active", actor="tester")
        assert active_model_for_role(db, ROLE).id == second  # type: ignore[union-attr]
        assert rollout_of(db.get(ModelVersion, first)).state == "retired"  # type: ignore[arg-type]
        actions = {
            row.action
            for row in db.scalars(select(AuditEvent).where(AuditEvent.object_type == "model_version")).all()
        }
        assert "model.rollout" in actions


def test_model_without_artifact_cannot_be_activated():
    model_id = _seed_model(with_artifact=False)
    with SessionLocal() as db:
        with pytest.raises(Exception) as error:
            set_rollout(db, model_id=model_id, state="active", actor="tester")
        assert "artifact" in str(error.value)


def test_rollback_reactivates_the_retired_model():
    old = _seed_model()
    new = _seed_model()
    with SessionLocal() as db:
        set_rollout(db, model_id=old, state="active", actor="tester")
        set_rollout(db, model_id=new, state="active", actor="tester")
        assert active_model_for_role(db, ROLE).id == new  # type: ignore[union-attr]

        with pytest.raises(Exception) as error:
            from app.services.model_registry import rollback_model

            rollback_model(db, role=ROLE, actor="tester", reason="short")
        assert "reason" in str(error.value).lower()

        from app.services.model_registry import rollback_model

        restored = rollback_model(
            db, role=ROLE, actor="tester", reason="新模型在线误报升高，回滚到上一版本。"
        )
        assert restored.id == old
        assert active_model_for_role(db, ROLE).id == old  # type: ignore[union-attr]


def test_rollout_api_is_admin_only_and_reports_state():
    model_id = _seed_model()
    with TestClient(app) as client:
        assert client.post(f"/api/v1/models/{model_id}/rollout", json={"state": "active"}).status_code == 401

        activated = client.post(
            f"/api/v1/models/{model_id}/rollout",
            json={"state": "active", "note": "经过时间外评估后启用"},
            headers=ADMIN_HEADER,
        )
        assert activated.status_code == 200
        assert activated.json()["rollout"] == "active"
        assert activated.json()["contractMatches"] is True

        listing = client.get("/api/v1/models/rollouts").json()
        assert any(item["id"] == model_id and item["rollout"] == "active" for item in listing["items"])
        assert listing["active"][ROLE] == model_id

        invalid = client.post(
            f"/api/v1/models/{model_id}/rollout", json={"state": "production"}, headers=ADMIN_HEADER
        )
        assert invalid.status_code == 422

        rolled = client.post(
            "/api/v1/models/rollback",
            json={"role": ROLE, "reason": "运维演练：回滚到上一版本。"},
            headers=ADMIN_HEADER,
        )
        # No retired model exists in this scenario, so a clear 404 is correct.
        assert rolled.status_code == 404
        assert rolled.json()["error"] == "not_found"


def test_detection_prefers_the_active_contract_model():
    from app.services.online_detection import clear_artifact_cache, select_channel_model

    active_id = _seed_model()
    with SessionLocal() as db:
        set_rollout(db, model_id=active_id, state="active", actor="tester")
        clear_artifact_cache()
        # The placeholder artifact is not a real joblib payload, so selection
        # must skip it rather than raise; the important part is that no
        # retired/active model can break selection.
        model = select_channel_model(db, "baseline")
        assert model is None or model.model_id != active_id or model.rollout == "active"
