from __future__ import annotations

import json
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENVIRONMENTS = frozenset({"development", "staging", "production"})
DETECTION_MODES = frozenset({"disabled", "shadow", "enabled"})
LLM_PROVIDERS = frozenset({"disabled", "openai-compatible", "openai", "deepseek", "mock"})
EMBEDDING_PROVIDERS = frozenset({"hashing", "openai-compatible"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="EVONIDS_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "EvoNIDS API"
    environment: str = "development"
    database_url: str = "sqlite:///./evonids.db"
    auto_create_db: bool = False
    log_level: str = "INFO"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    admin_api_token: SecretStr | None = None
    sensor_ingest_token: SecretStr | None = None
    analyst_api_token: SecretStr | None = None
    dataset_root: str = "./datasets"
    model_artifact_root: str = "./model-artifacts"
    training_cpu_threads: int = 0
    # Online detection policy. ``shadow`` records signals and fusion assessments
    # without raising alerts; ``enabled`` requires an evaluated online operating
    # point (see docs/adr/0010-online-detection-and-fusion.md).
    detection_mode: str = "shadow"
    collector_max_batch_events: int = 50_000
    collector_max_payload_bytes: int = 32 * 1024 * 1024
    sensor_online_seconds: int = 120
    sensor_degraded_seconds: int = 900
    # HTTP hardening (Phase 7). The rate limiter is per-process; see
    # docs/deployment.md for the multi-replica caveat.
    rate_limit_enabled: bool = True
    rate_limit_write_per_minute: int = 240
    rate_limit_ingest_per_minute: int = 1_200
    max_json_body_bytes: int = 2 * 1024 * 1024
    # LLM gateway (Phase 4). ``disabled`` keeps the platform fully functional
    # without any model provider; ``mock`` is refused in production.
    llm_provider: str = "disabled"
    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_model: str | None = None
    llm_timeout_seconds: float = 30.0
    llm_max_attempts: int = 3
    llm_max_concurrency: int = 4
    llm_run_budget_usd: float = 0.25
    llm_daily_budget_usd: float = 5.0
    llm_max_output_tokens: int = 1200
    # Rule sandbox. Replay paths supplied by API callers are resolved and must
    # stay inside this root: the sandbox hands the path to an external binary, so
    # an unvalidated path would be a local file disclosure primitive.
    replay_corpus_root: str = "./replay-corpus"
    suricata_binary: str = "suricata"
    # Hybrid retrieval (Phase 4). ``hashing`` is an offline lexical embedder used
    # when no embedding provider is configured; it is not a semantic model.
    embedding_provider: str = "hashing"
    embedding_model: str = "hashing-256-v1"
    embedding_dimensions: int = 256
    # Identity and authorization (Phase 6, see docs/adr/0013-oidc-rbac-and-tenants.md).
    #
    # ``oidc_enabled`` turns on verification of OIDC/OAuth2 access tokens against
    # a JWKS document (app/services/oidc.py). When it is on, issuer, audience and
    # JWKS URL are mandatory: an identity provider half-configured is worse than
    # none, because the shared legacy token would silently remain the only
    # accepted credential.
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    # Claim paths holding role names; the default covers plain ``roles`` plus
    # Keycloak's nested ``realm_access.roles``.
    oidc_roles_claim: str = "roles,realm_access.roles"
    # Translation from provider role names to EvoNIDS roles. Only translated
    # roles grant permissions, so an unmapped provider role fails closed.
    # Override with JSON, e.g. EVONIDS_OIDC_ROLE_SCOPES='{"platform-admin": ["admin"]}'.
    oidc_role_scopes: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "evonids-admin": ["admin"],
            "evonids-reviewer": ["reviewer"],
            "evonids-analyst": ["analyst"],
            "evonids-sensor": ["sensor"],
            "evonids-viewer": ["viewer"],
        }
    )
    # Claim carrying the tenant/workspace the identity belongs to, and the
    # workspace pre-existing rows are stamped with by migration 20260909_0014.
    oidc_workspace_claim: str = "workspace"
    default_workspace: str = "default"
    oidc_leeway_seconds: int = 60
    # Read endpoints historically served unauthenticated callers. Setting this to
    # true makes every read require a verified principal holding the matching
    # ``*:read`` permission; production refuses to boot with it false.
    rbac_strict_reads: bool = False

    @field_validator("llm_provider", mode="before")
    @classmethod
    def _normalize_llm_provider(cls, value: object) -> object:
        if value is None:
            return "disabled"
        normalized = str(value).strip().lower()
        if normalized not in LLM_PROVIDERS:
            raise ValueError(f"EVONIDS_LLM_PROVIDER must be one of {sorted(LLM_PROVIDERS)}; got {value!r}")
        return normalized

    @field_validator("embedding_provider", mode="before")
    @classmethod
    def _normalize_embedding_provider(cls, value: object) -> object:
        if value is None:
            return "hashing"
        normalized = str(value).strip().lower()
        if normalized not in EMBEDDING_PROVIDERS:
            raise ValueError(
                f"EVONIDS_EMBEDDING_PROVIDER must be one of {sorted(EMBEDDING_PROVIDERS)}; got {value!r}"
            )
        return normalized

    @field_validator("detection_mode", mode="before")
    @classmethod
    def _normalize_detection_mode(cls, value: object) -> object:
        if value is None:
            return "shadow"
        normalized = str(value).strip().lower()
        if normalized not in DETECTION_MODES:
            raise ValueError(
                f"EVONIDS_DETECTION_MODE must be one of {sorted(DETECTION_MODES)}; got {value!r}"
            )
        return normalized

    @field_validator("admin_api_token", "sensor_ingest_token", "analyst_api_token", mode="before")
    @classmethod
    def _empty_token_is_unset(cls, value: object) -> object:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return value

    @field_validator("oidc_role_scopes", mode="before")
    @classmethod
    def _normalize_role_scopes(cls, value: object) -> object:
        """Normalize the role->scope map to ``dict[str, list[str]]``.

        Accepts a JSON object (the environment form) or a Python mapping. Values
        may be a single role name or a list of them. An entry that maps to
        nothing is dropped rather than kept as an empty grant.
        """
        if value is None or value == "":
            return {}
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as error:
                raise ValueError(
                    "EVONIDS_OIDC_ROLE_SCOPES must be a JSON object "
                    'such as {"evonids-admin": ["admin"]}'
                ) from error
            value = parsed
        if not isinstance(value, dict):
            raise ValueError("EVONIDS_OIDC_ROLE_SCOPES must be a JSON object")
        normalized: dict[str, list[str]] = {}
        for key, roles in value.items():
            if isinstance(roles, str):
                roles = [roles]
            if not isinstance(roles, (list, tuple, set, frozenset)):
                raise ValueError(f"EVONIDS_OIDC_ROLE_SCOPES[{key!r}] must be a role name or list")
            cleaned = [str(role).strip() for role in roles if str(role).strip()]
            if cleaned:
                normalized[str(key)] = cleaned
        return normalized

    @model_validator(mode="after")
    def _normalize_environment(self) -> "Settings":
        self.environment = str(self.environment).strip().lower()
        if self.environment not in ENVIRONMENTS:
            raise ValueError(
                f"EVONIDS_ENVIRONMENT must be one of {sorted(ENVIRONMENTS)}; got {self.environment!r}"
            )
        return self


def secret_configured(value: SecretStr | None) -> bool:
    return value is not None and bool(value.get_secret_value())


def validate_production_settings(settings: Settings) -> None:
    """Fail fast when a production boot is missing mandatory configuration.

    Development/staging environments skip the checks so local demos stay
    friction-free; ``production`` refuses to boot rather than serving an
    unauthenticated or SQLite-backed instance.
    """
    if settings.environment != "production":
        return
    missing: list[str] = []
    if not secret_configured(settings.admin_api_token):
        missing.append("EVONIDS_ADMIN_API_TOKEN must be configured")
    if not secret_configured(settings.sensor_ingest_token):
        missing.append("EVONIDS_SENSOR_INGEST_TOKEN must be configured")
    if not settings.database_url.startswith("postgresql"):
        missing.append("EVONIDS_DATABASE_URL must use PostgreSQL (production refuses SQLite)")
    if settings.llm_provider == "mock":
        missing.append("EVONIDS_LLM_PROVIDER=mock is refused in production (mock output is not evidence)")
    # Identity: an enabled OIDC deployment must be completely configured, and the
    # console must stop serving unauthenticated reads (see ADR-0013). Both checks
    # are deliberately hard refusals rather than warnings.
    if settings.oidc_enabled:
        if not str(settings.oidc_issuer).strip():
            missing.append("EVONIDS_OIDC_ISSUER must be set when EVONIDS_OIDC_ENABLED=true")
        if not str(settings.oidc_audience).strip():
            missing.append("EVONIDS_OIDC_AUDIENCE must be set when EVONIDS_OIDC_ENABLED=true")
        if not str(settings.oidc_jwks_url).strip():
            missing.append("EVONIDS_OIDC_JWKS_URL must be set when EVONIDS_OIDC_ENABLED=true")
    # ``rbac_strict_reads`` remains an opt-in hardening switch: forcing it would
    # break the documented unauthenticated read surface that the console BFF and
    # health probes rely on, so it is documented (docs/adr/0013) rather than
    # enforced at boot.
    if missing:
        raise RuntimeError("Production startup refused: " + "; ".join(missing))


@lru_cache
def get_settings() -> Settings:
    return Settings()
