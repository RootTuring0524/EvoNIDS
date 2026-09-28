"""Hashed, scoped API keys for machine identities.

Keys are stored as salted SHA-256 digests (``sha256$<salt>$<digest>``); the raw
secret is returned exactly once at creation. Environment-variable tokens
(``EVONIDS_ADMIN_API_TOKEN`` / ``EVONIDS_SENSOR_INGEST_TOKEN`` /
``EVONIDS_ANALYST_API_TOKEN``) remain supported as the legacy bootstrap path and
are matched in constant time by ``app.api.security`` without touching the
database.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import ApiKey, AuditEvent
from app.schemas.api import ApiKeyCreate

KEY_SCOPES = ("admin", "sensor", "analyst")
DIGEST_SCHEME = "sha256"
LAST_USED_REFRESH_SECONDS = 300


@dataclass(slots=True)
class ApiKeyPrincipal:
    """Resolved identity of the caller of a protected endpoint."""

    kind: str  # "env" | "db"
    scope: str
    key_id: str | None = None
    name: str | None = None

    @property
    def display(self) -> str:
        if self.kind == "env":
            return f"env:{self.scope}"
        return f"apikey:{self.name or self.key_id}"

    @property
    def roles(self) -> list[str]:
        """RBAC roles implied by the key scope (see app.services.rbac.SCOPE_ROLES).

        A machine key is a role held by a non-human identity, so the authorization
        matrix in ``app.services.rbac`` applies to it unchanged: an admin key is
        an admin role, and a sensor key cannot read the console even though the
        key is valid.
        """
        from app.services.rbac import roles_for_scope

        return roles_for_scope(self.scope)

    @property
    def workspace_id(self) -> str:
        """Workspace this machine identity is bound to.

        Bound by the key *name* - ``acme-01-sensor`` belongs to ``acme-01`` - so an
        operator can place a collector in a tenant without a schema change. A name
        with no ``-`` prefix (``e2e sensor``, ``integration``) keeps the configured
        default workspace, which is exactly the historical single-tenant
        behaviour.
        """
        return machine_workspace(self.name)


# Role names a key name may end with: "tenant-b-analyst" -> tenant "tenant-b".
_NAME_ROLE_SUFFIXES = ("admin", "analyst", "sensor", "reviewer", "viewer")


def machine_workspace(name: str | None) -> str:
    """Derive the workspace of a machine identity from its key name."""
    from app.services.rbac import default_workspace, normalise_workspace

    if isinstance(name, str) and "-" in name:
        prefix, _, suffix = name.rpartition("-")
        if prefix.strip() and suffix.strip().lower() in _NAME_ROLE_SUFFIXES:
            return normalise_workspace(prefix.strip(), fallback=default_workspace())
    return default_workspace()


def new_key_id() -> str:
    return f"AK-{uuid.uuid4().hex.upper()[:12]}"


def generate_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}:{secret}".encode("utf-8")).hexdigest()
    return f"{DIGEST_SCHEME}${salt}${digest}"


def verify_secret(secret: str, stored: str) -> bool:
    try:
        scheme, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != DIGEST_SCHEME:
        return False
    candidate = hashlib.sha256(f"{salt}:{secret}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, digest)


def public_prefix(secret: str) -> str:
    """Public identifier derived from the secret (never the stored digest)."""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return "evn_" + digest[:10]


def _audit(
    db: Session,
    *,
    action: str,
    object_id: str,
    outcome: str,
    actor: str,
    request_id: str | None,
    note: str,
    after_state: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=actor,
            action=action,
            object_type="api_key",
            object_id=object_id,
            outcome=outcome,
            request_id=request_id,
            before_state=None,
            after_state=after_state,
            note=note,
        )
    )


def create_api_key(
    db: Session,
    payload: ApiKeyCreate,
    *,
    actor: str,
    request_id: str | None,
) -> tuple[ApiKey, str]:
    secret = generate_secret()
    row = ApiKey(
        id=new_key_id(),
        name=payload.name.strip(),
        scope=payload.scope,
        key_hash=hash_secret(secret),
        prefix=public_prefix(secret),
        enabled=True,
        created_by=actor,
        last_used_at=None,
    )
    db.add(row)
    _audit(
        db,
        action="apikey.created",
        object_id=row.id,
        outcome="completed",
        actor=actor,
        request_id=request_id,
        after_state={"scope": row.scope, "prefix": row.prefix, "name": row.name},
        note="A scoped machine API key was created; the raw secret is only returned once.",
    )
    db.commit()
    db.refresh(row)
    return row, secret


def list_api_keys(db: Session) -> list[ApiKey]:
    return list(
        db.scalars(select(ApiKey).order_by(ApiKey.created_at.desc(), ApiKey.id.desc())).all()
    )


def revoke_api_key(db: Session, key_id: str, *, actor: str, request_id: str | None) -> ApiKey | None:
    row = db.get(ApiKey, key_id)
    if row is None:
        return None
    if row.enabled:
        row.enabled = False
        row.updated_at = utc_now()
        _audit(
            db,
            action="apikey.revoked",
            object_id=row.id,
            outcome="completed",
            actor=actor,
            request_id=request_id,
            after_state={"scope": row.scope, "prefix": row.prefix, "enabled": False},
            note="A machine API key was revoked; the secret no longer authenticates.",
        )
        db.commit()
    return row


def authenticate_api_key(db: Session, secret: str, *, scope: str) -> ApiKey | None:
    """Return the matching enabled key for the scope, or None.

    The enabled key set is expected to stay small; every candidate is verified
    in constant time. ``last_used_at`` refreshes at most every five minutes to
    avoid a write per request.
    """
    candidates = db.scalars(select(ApiKey).where(ApiKey.enabled.is_(True))).all()
    for row in candidates:
        if row.scope != scope:
            continue
        if not verify_secret(secret, row.key_hash):
            continue
        now = utc_now()
        if row.last_used_at is None or (now - row.last_used_at).total_seconds() > LAST_USED_REFRESH_SECONDS:
            row.last_used_at = now
            db.commit()
        return row
    return None


def enabled_key_count(db: Session, *, scope: str) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(ApiKey)
            .where(ApiKey.scope == scope, ApiKey.enabled.is_(True))
        )
        or 0
    )
