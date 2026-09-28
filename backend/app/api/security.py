"""Authentication and authorization dependencies.

Callers present one of three credential kinds:

1. a verified **OIDC/OAuth2 access token** (``Authorization: Bearer <jwt>``),
   checked against a JWKS document by ``app.services.oidc`` when
   ``EVONIDS_OIDC_ENABLED`` is on;
2. a legacy environment-variable token (matched in constant time, no database
   access);
3. a hashed, scoped API key stored in the database.

Every successful resolution attaches a principal to ``request.state.principal``
so downstream code and audit records can name the exact identity. Authorization
is a second, separate step: ``require_permission`` / ``require_role`` consult the
matrix in ``app.services.rbac`` and deny by default, while
``require_admin_token`` / ``require_analyst_token`` / ``require_sensor_token``
keep their historical behaviour so existing integrations do not break.

Development keeps the existing friction-free sensor bypass; a ``production`` boot
is refused earlier by config validation (see
``app.core.config.validate_production_settings``).
"""
from __future__ import annotations

import logging
import secrets

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings, secret_configured
from app.db.session import get_db
from app.services.api_keys import ApiKeyPrincipal, authenticate_api_key, enabled_key_count
from app.services.oidc import OidcPrincipal, looks_like_jwt, verify_bearer_token
from app.services.rbac import (
    check_requirements,
    has_permission,
    has_role,
    parse_requirements,
    principal_roles,
    workspace_scope,
)

logger = logging.getLogger("evonids.security")

SCOPE_HEADERS = {
    "admin": "x-evonids-admin-token",
    "sensor": "x-evonids-sensor-token",
    "analyst": "x-evonids-analyst-token",
}

_WHOLE_SCOPE_GRANTS: dict[str, tuple[str, ...]] = {
    "admin": ("admin",),
    "analyst": ("analyst", "admin"),
    "sensor": ("sensor",),
}


def _env_token(scope: str):
    settings = get_settings()
    if scope == "admin":
        return settings.admin_api_token
    if scope == "sensor":
        return settings.sensor_ingest_token
    return settings.analyst_api_token


def _supplied_credential(request: Request, *, scope: str) -> str:
    """Read the scoped header, falling back to a standard Bearer token.

    The collector and external integrations use ``Authorization: Bearer``; the
    console BFF uses the scoped header. Both must resolve to the same identity,
    otherwise a collector that works in tests fails against a real deployment.
    """
    supplied = request.headers.get(SCOPE_HEADERS[scope], "")
    if supplied:
        return supplied
    return _bearer_credential(request)


def _bearer_credential(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return ""


def _any_credential_supplied(request: Request) -> str:
    for header in ("authorization", *SCOPE_HEADERS.values()):
        value = request.headers.get(header, "")
        if value.strip():
            return value.strip()
    return ""


class _PrincipalCache:
    """Per-request memo for the OIDC/credential resolution.

    Verifying the same JWT once per dependency would re-run a signature check
    several times for one request; the cache keeps that at exactly one while
    preserving the failure (``None``) so a bad token is never accepted later.
    """

    def __init__(self) -> None:
        self.token: str | None = None
        self.principal: OidcPrincipal | None = None
        self.resolved = False


def _request_cache(request: Request) -> _PrincipalCache:
    cache = getattr(request.state, "_principal_cache", None)
    if cache is None:
        cache = _PrincipalCache()
        request.state._principal_cache = cache
    return cache


def _oidc_principal(token: str, request: Request | None = None):
    """Verify ``token`` as a JWT; ``None`` when OIDC is off or verification fails.

    Fail closed: a token that cannot be verified yields no principal, and the
    caller then has to satisfy the requirement some other way (or be rejected).
    The failure reason is logged without the token itself.
    """
    settings = get_settings()
    if not settings.oidc_enabled or not looks_like_jwt(token):
        return None
    cache = _request_cache(request) if request is not None else None
    if cache is not None and cache.resolved and cache.token == token:
        return cache.principal
    resolved_principal: OidcPrincipal | None = verify_bearer_token(token, settings=settings)
    if resolved_principal is None:
        logger.warning("rejected an unverifiable OIDC bearer token")
    if cache is not None:
        cache.token = token
        cache.principal = resolved_principal
        cache.resolved = True
    return resolved_principal


def _scope_accepted(principal, scope: str) -> bool:
    """Scope check for an OIDC principal.

    A database API key is issued for exactly one scope, so presenting it in
    another scope's header cannot succeed. The same must hold for a JWT: a token
    whose roles cover ``viewer`` must not become an administrator by moving to
    the admin header, and a sensor token must not reach the console. An admin
    role still implies analyst, matching the historical analyst dependency.
    """
    roles = principal_roles(principal)
    return any(role in roles for role in _WHOLE_SCOPE_GRANTS[scope])


def _resolve_principal(db: Session, request: Request, *, scope: str):
    supplied = _supplied_credential(request, scope=scope)
    if not supplied:
        return None
    env = _env_token(scope)
    if env is not None and secret_configured(env) and secrets.compare_digest(
        supplied, env.get_secret_value()
    ):
        return ApiKeyPrincipal(kind="env", scope=scope)
    # A JWT can never equal a database API key (keys are URL-safe tokens without
    # dots), so trying OIDC first is unambiguous. A token that claims to be a JWT
    # but cannot be verified is not retried as an API key: that would let an
    # unverifiable token be interpreted as a different credential family.
    if looks_like_jwt(supplied):
        principal = _oidc_principal(supplied, request)
        if principal is not None and _scope_accepted(principal, scope):
            return principal
        return None
    row = authenticate_api_key(db, supplied, scope=scope)
    if row is not None:
        return ApiKeyPrincipal(kind="db", scope=scope, key_id=row.id, name=row.name)
    return None


def _resolve_any_credential(db: Session, request: Request):
    """Resolve any credential family for a scope-agnostic requirement.

    Order is fixed and explicit: a scoped header first (admin, sensor, analyst),
    then the Bearer credential, which itself resolves as an environment token,
    an OIDC token, or a database API key. The resolved principal keeps its real
    scope, so an audit record still shows whether the caller was an admin or an
    analyst.
    """
    for scope in ("admin", "sensor", "analyst"):
        if request.headers.get(SCOPE_HEADERS[scope], ""):
            principal = _resolve_principal(db, request, scope=scope)
            if principal is not None:
                return principal
    bearer = _bearer_credential(request)
    if bearer:
        for scope in ("admin", "analyst", "sensor"):
            principal = _resolve_principal(db, request, scope=scope)
            if principal is not None:
                return principal
        # Scope-agnostic requirements (``require_permission``) do not pick a
        # credential family through a scope header, so the role matrix decides.
        # Verifying the JWT once here is enough; a viewer token still cannot
        # deploy a rule because it lacks the permission, not because of the path.
        if looks_like_jwt(bearer):
            return _oidc_principal(bearer, request)
    return None


def _scope_granted(principal, scope: str) -> bool:
    """Does this principal satisfy a *whole-scope* operation (the legacy path)?"""
    if principal is None:
        return False
    roles = principal_roles(principal)
    return any(role in roles for role in _WHOLE_SCOPE_GRANTS[scope])


def _no_credential_of_scope(db: Session, *, scope: str) -> bool:
    env = _env_token(scope)
    if env is not None and secret_configured(env):
        return False
    return enabled_key_count(db, scope=scope) == 0


def _attach(request: Request, principal):
    request.state.principal = principal
    return principal


def require_admin_token(
    request: Request,
    db: Session = Depends(get_db),
):
    principal = _resolve_principal(db, request, scope="admin")
    if principal is not None:
        return _attach(request, principal)
    if _no_credential_of_scope(db, scope="admin"):
        raise HTTPException(
            status_code=503,
            detail=(
                "Administrative writes are disabled until EVONIDS_ADMIN_API_TOKEN "
                "or an enabled admin API key is configured"
            ),
        )
    raise HTTPException(status_code=401, detail="Invalid administrative credential")


def require_sensor_token(
    request: Request,
    db: Session = Depends(get_db),
):
    settings = get_settings()
    env = settings.sensor_ingest_token
    if not secret_configured(env) and settings.environment.lower() == "development":
        # Development-only bypass preserved from v0.1: ingestion works without a
        # configured sensor credential so local demos stay friction-free.
        return _attach(request, ApiKeyPrincipal(kind="env", scope="sensor"))
    principal = _resolve_principal(db, request, scope="sensor")
    if principal is not None:
        return _attach(request, principal)
    if _no_credential_of_scope(db, scope="sensor"):
        raise HTTPException(
            status_code=503,
            detail=(
                "Sensor ingestion is disabled until EVONIDS_SENSOR_INGEST_TOKEN "
                "or an enabled sensor API key is configured"
            ),
        )
    raise HTTPException(status_code=401, detail="Invalid sensor credential")


def require_analyst_token(
    request: Request,
    db: Session = Depends(get_db),
):
    """Analyst-scoped operations.

    An admin credential is accepted as well: the console holds a single
    server-side admin token, and RBAC-wise an administrator is a superset of an
    analyst. The resolved principal keeps its real scope, so audit records still
    show whether the caller was an admin or an analyst.
    """
    principal = _resolve_principal(db, request, scope="analyst")
    if principal is not None:
        return _attach(request, principal)
    admin = _resolve_principal(db, request, scope="admin")
    if admin is not None:
        return _attach(request, admin)
    if _no_credential_of_scope(db, scope="analyst"):
        raise HTTPException(
            status_code=503,
            detail="Analyst operations are disabled until an enabled analyst API key is configured",
        )
    raise HTTPException(status_code=401, detail="Invalid analyst credential")


# --------------------------------------------------------------- authorization


def _forbidden(request: Request, unmet: str, *, prefix: str) -> HTTPException:
    """Denial response that does not become a credential oracle.

    A denial is ``403`` only when a credential was actually supplied and
    understood; with no credential at all the answer stays ``401``, matching the
    historical behaviour of these endpoints.
    """
    if _any_credential_supplied(request):
        return HTTPException(
            status_code=403,
            detail=f"This credential does not grant {prefix} {unmet}",
        )
    return HTTPException(status_code=401, detail="Authentication is required for this operation")


def _enforce(request: Request, db: Session, specs: tuple[str, ...], *, prefix: str):
    principal = getattr(request.state, "principal", None)
    if principal is None:
        principal = _attach(request, _resolve_any_credential(db, request))
    if principal is None:
        raise _forbidden(request, specs[0], prefix=prefix)
    unmet = check_requirements(principal, parse_requirements(specs))
    if unmet is not None:
        raise _forbidden(request, unmet, prefix=prefix)
    return principal


def require_permission(*permissions: str):
    """Dependency factory: allow only a principal holding one of ``permissions``.

    ``Depends(require_permission("rule:deploy"))`` is the enforced form of the
    matrix in ``app.services.rbac``; nothing passes without a verified principal
    and an explicit grant.
    """
    if not permissions:
        raise ValueError("require_permission needs at least one permission")

    def dependency(request: Request, db: Session = Depends(get_db)):
        return _enforce(request, db, tuple(permissions), prefix="permission")

    return dependency


def require_role(*roles: str):
    """Dependency factory: allow only a principal holding one of ``roles``."""
    if not roles:
        raise ValueError("require_role needs at least one role")

    def dependency(request: Request, db: Session = Depends(get_db)):
        return _enforce(request, db, tuple(roles), prefix="role")

    return dependency


def enforce_permission(request: Request, principal, permission: str) -> None:
    """Imperative form of ``require_permission`` for payload-dependent decisions.

    Used where the required permission depends on the request body (for example a
    case PATCH that only closes a case when ``status`` says so). Raises the same
    403/401 envelope as the dependency form.
    """
    if not has_permission(principal, permission):
        raise _forbidden(request, permission, prefix="permission")


def principal_for(request: Request, db: Session = Depends(get_db)):
    """Authenticate the caller (any credential kind) and attach the principal.

    Unlike ``require_permission`` this does not authorize anything by itself; it
    is used by endpoints whose payload is identical for every authenticated role
    (for example ``GET /auth/me``).
    """
    principal = getattr(request.state, "principal", None)
    if principal is None:
        principal = _resolve_any_credential(db, request)
    if principal is None:
        raise HTTPException(status_code=401, detail="Authentication is required for this operation")
    return _attach(request, principal)


def optional_principal(request: Request, db: Session = Depends(get_db)):
    """Resolve the caller when credentials are present, else ``None``.

    Used by read endpoints so that a credential which is present but insufficient
    is still denied (a viewer token cannot escalate by simply omitting a scope
    header), while an unauthenticated request keeps working unless
    ``EVONIDS_RBAC_STRICT_READS`` is on.
    """
    if not _any_credential_supplied(request):
        return None
    principal = _resolve_any_credential(db, request)
    if principal is None:
        raise HTTPException(status_code=401, detail="The supplied credential could not be verified")
    return _attach(request, principal)


def require_reader(permission: str):
    """Dependency factory for read endpoints.

    Reads behave as before (open unless configured strict) but a *present*
    credential is always checked, so an authenticated caller with the wrong role
    is denied instead of silently ignored.
    """

    def dependency(request: Request, db: Session = Depends(get_db)):
        strict = bool(getattr(get_settings(), "rbac_strict_reads", False))
        principal = getattr(request.state, "principal", None)
        if principal is None and _any_credential_supplied(request):
            principal = _resolve_any_credential(db, request)
            if principal is None:
                raise HTTPException(
                    status_code=401, detail="The supplied credential could not be verified"
                )
            _attach(request, principal)
        if principal is None:
            if strict:
                raise HTTPException(
                    status_code=401, detail="Authentication is required for this operation"
                )
            return None
        if not has_permission(principal, permission):
            raise _forbidden(request, permission, prefix="permission")
        return principal

    return dependency


def request_actor(request: Request, fallback: str = "unauthenticated") -> str:
    """Audit actor for request-scoped operations: the authenticated principal.

    Callers never supply this value. The audit actor is derived server-side from
    the resolved identity (``env:admin``, ``apikey:<name>``, ``oidc:<sub>``, ...)
    so audit records cannot be falsified by whoever sent the request. When no
    principal resolved (endpoints that are only protected by the console login),
    the honest fallback ``unauthenticated`` is recorded.
    """
    principal = getattr(request.state, "principal", None)
    return getattr(principal, "display", None) or fallback


def request_workspace(request: Request) -> str:
    """Workspace of the authenticated principal, for row stamping and filtering.

    Reads ``request.state.principal`` only. Client-supplied workspace ids in a
    body, query string or header are never consulted (see
    ``app.services.rbac.effective_workspace``).
    """
    return workspace_scope(getattr(request.state, "principal", None))


def request_roles(request: Request) -> list[str]:
    return principal_roles(getattr(request.state, "principal", None))


def request_is_reviewer(request: Request) -> bool:
    return has_role(getattr(request.state, "principal", None), "reviewer")
