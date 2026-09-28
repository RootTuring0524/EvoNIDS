"""Role-based access control and tenant/workspace isolation.

Two independent decisions live here, both deliberately data-driven so they can be
reviewed in one place instead of being scattered across route decorators:

1. **Authorization** - a role is a *named set of permissions*
   (``ROLE_PERMISSIONS``), and nothing is granted unless a permission appears in
   that set ("deny by default"). ``app.api.security.require_permission`` is the
   only place a request is allowed through on the strength of a role.

2. **Tenant isolation** - a verified principal belongs to exactly one workspace
   and every tenant-scoped row carries that workspace. Reads filter on it, writes
   stamp it, and the value always comes from the principal - never from the
   request body or query string (see ``effective_workspace``).

Roles
-----
``admin``     - deploy rules, manage API keys, everything below.
``reviewer``  - confirm/reject rules and close cases (four-eyes separation from
                whoever authored a candidate rule).
``analyst``   - start investigations, write feedback and case notes, triage.
``sensor``    - ingestion only; a collector credential must not read the console.
``viewer``    - read-only, plus its own identity.

Machine API keys keep their historical scopes (``admin``/``analyst``/``sensor``,
ADR-0003). ``permissions_for`` turns a principal's scopes *and* roles into one
effective permission set, so an existing admin token keeps working while an OIDC
token is judged purely on the roles its provider issued.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

DEFAULT_WORKSPACE = "default"
ROLE_NONE = "none"
ROLE_VIEWER = "viewer"

DOMAIN_ROLES = ("admin", "reviewer", "analyst", "sensor", "viewer")

PERMISSION_ALERT_READ = "alert:read"
PERMISSION_ALERT_UPDATE = "alert:update"
PERMISSION_CASE_READ = "case:read"
PERMISSION_CASE_CREATE = "case:create"
PERMISSION_CASE_NOTE = "case:note"
PERMISSION_CASE_CLOSE = "case:close"
PERMISSION_EVIDENCE_READ = "evidence:read"
PERMISSION_EVIDENCE_RAW = "evidence:raw"
PERMISSION_INVESTIGATION_READ = "investigation:read"
PERMISSION_INVESTIGATION_START = "investigation:start"
PERMISSION_INVESTIGATION_FEEDBACK = "investigation:feedback"
PERMISSION_RULE_READ = "rule:read"
PERMISSION_RULE_CANDIDATE = "rule:candidate"
PERMISSION_RULE_VALIDATE = "rule:validate"
PERMISSION_RULE_REVIEW = "rule:review"
PERMISSION_RULE_DEPLOY = "rule:deploy"
PERMISSION_INGEST_WRITE = "ingest:write"

PERMISSIONS: frozenset[str] = frozenset(
    {
        PERMISSION_ALERT_READ,
        PERMISSION_ALERT_UPDATE,
        PERMISSION_CASE_READ,
        PERMISSION_CASE_CREATE,
        PERMISSION_CASE_NOTE,
        PERMISSION_CASE_CLOSE,
        PERMISSION_EVIDENCE_READ,
        PERMISSION_EVIDENCE_RAW,
        PERMISSION_INVESTIGATION_READ,
        PERMISSION_INVESTIGATION_START,
        PERMISSION_INVESTIGATION_FEEDBACK,
        PERMISSION_RULE_READ,
        PERMISSION_RULE_CANDIDATE,
        PERMISSION_RULE_VALIDATE,
        PERMISSION_RULE_REVIEW,
        PERMISSION_RULE_DEPLOY,
        PERMISSION_INGEST_WRITE,
    }
)

# Read permissions are granted to every authenticated role, including viewer and
# sensor: a sensor credential still needs to be able to read its own ingestion
# diagnostics, and reads never change state.
READ_PERMISSIONS: tuple[str, ...] = (
    PERMISSION_ALERT_READ,
    PERMISSION_CASE_READ,
    PERMISSION_EVIDENCE_READ,
    PERMISSION_INVESTIGATION_READ,
    PERMISSION_RULE_READ,
)

# The permission matrix. Every entry is explicit; there is no wildcard and no
# implicit inheritance, so a missing permission is a denial.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": PERMISSIONS,
    "reviewer": frozenset(
        {
            *READ_PERMISSIONS,
            PERMISSION_EVIDENCE_RAW,
            PERMISSION_RULE_VALIDATE,
            PERMISSION_RULE_REVIEW,
            PERMISSION_CASE_NOTE,
            PERMISSION_CASE_CLOSE,
            PERMISSION_INVESTIGATION_FEEDBACK,
        }
    ),
    "analyst": frozenset(
        {
            *READ_PERMISSIONS,
            PERMISSION_ALERT_UPDATE,
            PERMISSION_EVIDENCE_RAW,
            PERMISSION_RULE_CANDIDATE,
            PERMISSION_CASE_CREATE,
            PERMISSION_CASE_NOTE,
            PERMISSION_INVESTIGATION_START,
            PERMISSION_INVESTIGATION_FEEDBACK,
        }
    ),
    "sensor": frozenset(
        {
            *READ_PERMISSIONS,
            PERMISSION_INGEST_WRITE,
        }
    ),
    "viewer": frozenset(READ_PERMISSIONS),
}

# Scopes carried by API keys / environment tokens map onto the same role names so
# that both identity families are authorised by one matrix.
SCOPE_ROLES: dict[str, str] = {
    "admin": "admin",
    "analyst": "analyst",
    "sensor": "sensor",
}


@dataclass(frozen=True, slots=True)
class Requirement:
    """One ``require_permission``/``require_role`` argument, parsed."""

    kind: str  # "permission" | "role" | "authenticated"
    value: str = ""

    @property
    def description(self) -> str:
        if self.kind == "authenticated":
            return "an authenticated principal"
        return f"{self.kind} {self.value!r}"


def parse_requirement(spec: str) -> Requirement:
    """Parse a requirement string.

    ``"rule:deploy"`` is a permission requirement (contains ``:``),
    ``"reviewer"`` is a role requirement, and ``"authenticated"`` only requires
    that some verified principal resolved.
    """
    text = str(spec).strip()
    if not text:
        raise ValueError("requirement must not be empty")
    if ":" in text:
        return Requirement(kind="permission", value=text)
    if text == "authenticated":
        return Requirement(kind="authenticated")
    return Requirement(kind="role", value=text)


def parse_requirements(specs: Sequence[str]) -> tuple[Requirement, ...]:
    return tuple(parse_requirement(spec) for spec in specs)


def role_permissions(role: str) -> frozenset[str]:
    """Permissions granted by one role; unknown roles grant nothing."""
    return ROLE_PERMISSIONS.get(role, frozenset())


def roles_for_scope(scope: str) -> list[str]:
    role = SCOPE_ROLES.get(str(scope))
    return [role] if role else []


def principal_roles(principal: Any) -> list[str]:
    """Roles of a principal, derived from scopes when it carries no explicit roles."""
    if principal is None:
        return []
    roles = list(getattr(principal, "roles", None) or [])
    for scope in getattr(principal, "scopes", None) or []:
        for role in roles_for_scope(str(scope)):
            if role not in roles:
                roles.append(role)
    scope = getattr(principal, "scope", None)
    if isinstance(scope, str):
        for role in roles_for_scope(scope):
            if role not in roles:
                roles.append(role)
    return roles


def principal_permissions(principal: Any) -> frozenset[str]:
    """Effective permission set: the union of every role the principal holds."""
    permissions: set[str] = set()
    for role in principal_roles(principal):
        permissions |= role_permissions(role)
    return frozenset(permissions)


# Backwards/forwards-friendly alias used by callers that build a set from raw
# role and scope lists (for example a settings-driven policy test).
def permissions_for(
    *, roles: Iterable[str] = (), scopes: Iterable[str] = ()
) -> frozenset[str]:
    permissions: set[str] = set()
    for role in roles:
        permissions |= role_permissions(str(role))
    for scope in scopes:
        for role in roles_for_scope(str(scope)):
            permissions |= role_permissions(role)
    return frozenset(permissions)


def has_permission(principal: Any, permission: str) -> bool:
    return permission in principal_permissions(principal)


def has_role(principal: Any, role: str) -> bool:
    return role in principal_roles(principal)


def check_requirements(principal: Any, requirements: Sequence[Requirement]) -> str | None:
    """Return the first unmet requirement's description, or ``None`` when allowed.

    Used by the FastAPI dependency and directly unit-testable, so the decision
    logic (and the resulting HTTP status) is verified without a route.
    """
    if principal is None:
        return "an authenticated principal"
    if not requirements:
        return None
    roles = principal_roles(principal)
    permissions = principal_permissions(principal)
    for requirement in requirements:
        if requirement.kind == "authenticated":
            continue
        if requirement.kind == "permission":
            if requirement.value in permissions:
                return None
        elif requirement.value in roles:
            return None
    return " or ".join(requirement.description for requirement in requirements)


# -------------------------------------------------------- workspace isolation


def normalise_workspace(value: Any, *, fallback: str = DEFAULT_WORKSPACE) -> str:
    """Canonical workspace id: trimmed, lower-cased, bounded, never empty."""
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if cleaned:
            return cleaned[:64]
    return fallback


def default_workspace() -> str:
    """The configured default workspace (``EVONIDS_DEFAULT_WORKSPACE``).

    Imported lazily so this module stays importable without settings (unit tests
    import the permission matrix directly).
    """
    try:
        from app.core.config import get_settings

        return normalise_workspace(getattr(get_settings(), "default_workspace", DEFAULT_WORKSPACE))
    except Exception:  # noqa: BLE001 - configuration must not break authorization
        return DEFAULT_WORKSPACE


def workspace_scope(principal: Any) -> str:
    """The single workspace an authenticated principal may see.

    The value is taken from the principal only - never from the request - so a
    caller cannot read another tenant's rows by changing a header, a query
    parameter or a JSON field. Unauthenticated callers fall back to the
    configured default workspace (which is where pre-existing rows live, see
    migration ``20260909_0014``), and ``workspace_filter`` still keeps every
    other tenant out of reach.
    """
    if principal is None:
        return default_workspace()
    explicit = getattr(principal, "workspace_id", None)
    if isinstance(explicit, str) and explicit.strip():
        return normalise_workspace(explicit, fallback=default_workspace())
    return default_workspace()


def effective_workspace(principal: Any, supplied: Any = None) -> str:
    """Resolve the workspace for a write, ignoring any client-supplied value.

    ``supplied`` exists purely so callers can pass what a client sent and get the
    same answer as when they pass ``None``: it is never used. That makes the
    "clients cannot choose their tenant" property explicit and testable.
    """
    del supplied
    return workspace_scope(principal)


def workspace_filter(model: Any, principal: Any) -> tuple[Any, ...]:
    """SQLAlchemy filter clause pinning ``model`` to the principal's workspace."""
    return (model.workspace_id == workspace_scope(principal),)


def workspace_of_row(row: Any) -> str:
    return normalise_workspace(getattr(row, "workspace_id", None))


def same_workspace(principal: Any, row: Any) -> bool:
    return workspace_of_row(row) == workspace_scope(principal)


@dataclass(slots=True)
class WorkspaceContext:
    """Small value object routes pass around: who, which tenant, what may they do."""

    principal: Any
    workspace_id: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    roles: list[str] = field(default_factory=list)

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def workspace_context(principal: Any) -> WorkspaceContext:
    return WorkspaceContext(
        principal=principal,
        workspace_id=workspace_scope(principal),
        permissions=principal_permissions(principal),
        roles=principal_roles(principal),
    )


def summary(principal: Any) -> dict[str, Any]:
    """Non-sensitive description of a principal, for ``GET /auth/me``.

    Only leaf fields are read (identity, roles, permission names); no Cordis/ORM
    object is serialised.
    """
    return {
        "display": getattr(principal, "display", None),
        "kind": getattr(principal, "kind", None),
        "roles": principal_roles(principal),
        "permissions": sorted(principal_permissions(principal)),
        "workspaceId": workspace_scope(principal),
    }


# A mapping view of the matrix, convenient for docs and tests.
def permission_matrix() -> Mapping[str, frozenset[str]]:
    return {role: ROLE_PERMISSIONS[role] for role in DOMAIN_ROLES}
