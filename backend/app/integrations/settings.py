"""Connector configuration, read from environment variables.

The integration layer deliberately reads ``os.environ`` directly instead of
going through ``app.core.config.Settings``: ``app/core/config.py`` is owned by
another change in flight and the brief for this phase requires this module to be
self-contained. Every variable name is documented in ``docs/integrations.md``.

**The framework is disabled by default.** With an empty environment
:func:`load_integration_settings` returns no enabled connector, and the
dispatcher reports an empty health report — it never fabricates a delivery.

Variable list (all optional):

===============================  ==============================================
``EVONIDS_INTEGRATIONS_ENABLED`` global switch, default ``false``
``EVONIDS_ENVIRONMENT``          reused only to decide the default log level
``EVONIDS_WEBHOOK_URLS``         comma-separated webhook target URLs
``EVONIDS_WEBHOOK_SECRET``       HMAC-SHA256 signing secret (per target or global)
``EVONIDS_WEBHOOK_TIMEOUT_SECONDS``        default 10
``EVONIDS_WEBHOOK_MAX_ATTEMPTS``           default 3
``EVONIDS_WEBHOOK_CIRCUIT_FAILURES``       default 5
``EVONIDS_WEBHOOK_CIRCUIT_RESET_SECONDS``  default 60
``EVONIDS_WEBHOOK_ALLOWED_HOSTS``          explicit host allow-list (empty = any
                                           public host)
``EVONIDS_WEBHOOK_ALLOW_HTTP``             allow plain http, default ``false``
``EVONIDS_SYSLOG_HOST`` / ``EVONIDS_SYSLOG_PORT`` (default 514)
``EVONIDS_SYSLOG_PROTOCOL``      ``udp`` | ``tcp`` | ``tls`` (default ``udp``)
``EVONIDS_SYSLOG_FORMAT``        ``rfc5424`` | ``cef`` (default ``rfc5424``)
``EVONIDS_SYSLOG_FACILITY``      syslog facility number, default 13 (log audit)
``EVONIDS_SYSLOG_APP_NAME``      default ``evonids``
``EVONIDS_SYSLOG_ENTERPRISE_ID`` CEF device vendor/enterprise id, default 0
``EVONIDS_SYSLOG_MIN_SEVERITY``  ``critical``|``high``|``medium``|``low``|``info``
``EVONIDS_STIX_EXPORT_DIR``      directory for exported STIX 2.1 bundles
``EVONIDS_STIX_IDENTITY_NAME``   STIX identity name, default ``EvoNIDS``
``EVONIDS_TICKET_BASE_URL``      ticketing API base URL
``EVONIDS_TICKET_CREATE_PATH``   default ``/tickets``
``EVONIDS_TICKET_UPDATE_PATH``   default ``/tickets/{ticket_id}``
``EVONIDS_TICKET_TOKEN``         bearer token for the ticketing API
``EVONIDS_TICKET_AUTH_HEADER``   default ``Authorization`` (value ``Bearer <token>``)
``EVONIDS_TICKET_PROJECT``       optional project/queue identifier
``EVONIDS_TICKET_ALLOWED_HOSTS`` host allow-list (empty = any public host)
``EVONIDS_TICKET_ALLOW_HTTP``    default ``false``
===============================  ==============================================

Secrets are only ever read here and are never echoed by an API response:
:func:`SettingsFingerprint.as_dict` reports *whether* a secret is configured,
never its value.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping, Sequence

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off", ""}
SEVERITIES = ("critical", "high", "medium", "low", "info")


def env_flag(source: Mapping[str, str], name: str, default: bool) -> bool:
    raw = source.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    return default


def env_int(source: Mapping[str, str], name: str, default: int) -> int:
    raw = (source.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(source: Mapping[str, str], name: str, default: float) -> float:
    raw = (source.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def env_text(source: Mapping[str, str], name: str, default: str = "") -> str:
    return (source.get(name) or default).strip()


def env_list(source: Mapping[str, str], name: str) -> list[str]:
    raw = source.get(name) or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


def _severity(source: Mapping[str, str], name: str, default: str) -> str:
    value = env_text(source, name, default).lower()
    return value if value in SEVERITIES else default


@dataclass(frozen=True, slots=True)
class WebhookSettings:
    name: str
    url: str
    secret: str | None = None
    timeout_seconds: float = 10.0
    max_attempts: int = 3
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 8.0
    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 60.0
    allowed_hosts: tuple[str, ...] = ()
    allow_http: bool = False
    capabilities: tuple[str, ...] = ("alert", "evidence", "test")


@dataclass(frozen=True, slots=True)
class SyslogSettings:
    name: str = "syslog"
    host: str = ""
    port: int = 514
    protocol: str = "udp"
    message_format: str = "rfc5424"
    facility: int = 13
    app_name: str = "evonids"
    enterprise_id: int = 0
    min_severity: str = "info"
    timeout_seconds: float = 5.0
    capabilities: tuple[str, ...] = ("alert", "evidence", "test")


@dataclass(frozen=True, slots=True)
class StixSettings:
    name: str = "stix-export"
    export_dir: str = ""
    identity_name: str = "EvoNIDS"
    identity_id: str = ""
    capabilities: tuple[str, ...] = ("alert", "evidence", "test")


@dataclass(frozen=True, slots=True)
class TicketSettings:
    name: str = "ticket-http"
    base_url: str = ""
    create_path: str = "/tickets"
    update_path: str = "/tickets/{ticket_id}"
    token: str | None = None
    auth_header: str = "Authorization"
    project: str = ""
    timeout_seconds: float = 10.0
    max_attempts: int = 3
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 8.0
    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 60.0
    allowed_hosts: tuple[str, ...] = ()
    allow_http: bool = False
    capabilities: tuple[str, ...] = ("case", "test")


@dataclass(frozen=True, slots=True)
class IntegrationSettings:
    enabled: bool = False
    webhooks: tuple[WebhookSettings, ...] = ()
    syslog: SyslogSettings | None = None
    stix: StixSettings | None = None
    tickets: TicketSettings | None = None
    disabled_reasons: Mapping[str, str] = field(default_factory=dict)

    def fingerprint(self) -> dict[str, object]:
        """Safe-to-log description of the configuration (never a secret value)."""
        return {
            "enabled": self.enabled,
            "webhooks": [
                {
                    "name": item.name,
                    "url": _redact_url(item.url),
                    "secretConfigured": bool(item.secret),
                    "allowedHosts": list(item.allowed_hosts),
                    "allowHttp": item.allow_http,
                }
                for item in self.webhooks
            ],
            "syslog": (
                {
                    "name": self.syslog.name,
                    "host": self.syslog.host,
                    "port": self.syslog.port,
                    "protocol": self.syslog.protocol,
                    "format": self.syslog.message_format,
                }
                if self.syslog
                else None
            ),
            "stix": (
                {"name": self.stix.name, "exportDir": self.stix.export_dir} if self.stix else None
            ),
            "tickets": (
                {
                    "name": self.tickets.name,
                    "baseUrl": _redact_url(self.tickets.base_url),
                    "tokenConfigured": bool(self.tickets.token),
                    "allowedHosts": list(self.tickets.allowed_hosts),
                    "allowHttp": self.tickets.allow_http,
                }
                if self.tickets
                else None
            ),
            "disabledReasons": dict(self.disabled_reasons),
        }


def _redact_url(url: str) -> str:
    """Drop any userinfo/query credentials from a URL before it is reported."""
    if not url:
        return ""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    host = parts.hostname or parts.netloc
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def load_integration_settings(source: Mapping[str, str] | None = None) -> IntegrationSettings:
    """Build the connector configuration from the environment.

    Returns a disabled configuration when ``EVONIDS_INTEGRATIONS_ENABLED`` is
    not set to a true value, or when a connector's required variable is missing.
    """
    env: Mapping[str, str] = os.environ if source is None else source
    disabled: dict[str, str] = {}
    enabled = env_flag(env, "EVONIDS_INTEGRATIONS_ENABLED", False)
    if not enabled:
        return IntegrationSettings(
            enabled=False,
            disabled_reasons={"all": "EVONIDS_INTEGRATIONS_ENABLED is not true"},
        )

    webhook_urls = env_list(env, "EVONIDS_WEBHOOK_URLS")
    webhook_secret = env_text(env, "EVONIDS_WEBHOOK_SECRET") or None
    webhook_secrets = {
        item.split("=", 1)[0].strip(): item.split("=", 1)[1].strip()
        for item in env_list(env, "EVONIDS_WEBHOOK_SECRETS")
        if "=" in item
    }
    webhooks: list[WebhookSettings] = []
    for index, url in enumerate(webhook_urls):
        name = f"webhook-{index + 1}"
        secret = webhook_secrets.get(name) or webhook_secrets.get(url) or webhook_secret
        webhooks.append(
            WebhookSettings(
                name=name,
                url=url,
                secret=secret,
                timeout_seconds=env_float(env, "EVONIDS_WEBHOOK_TIMEOUT_SECONDS", 10.0),
                max_attempts=env_int(env, "EVONIDS_WEBHOOK_MAX_ATTEMPTS", 3),
                base_backoff_seconds=env_float(env, "EVONIDS_WEBHOOK_BASE_BACKOFF_SECONDS", 0.5),
                max_backoff_seconds=env_float(env, "EVONIDS_WEBHOOK_MAX_BACKOFF_SECONDS", 8.0),
                circuit_failure_threshold=env_int(env, "EVONIDS_WEBHOOK_CIRCUIT_FAILURES", 5),
                circuit_reset_seconds=env_float(env, "EVONIDS_WEBHOOK_CIRCUIT_RESET_SECONDS", 60.0),
                allowed_hosts=tuple(env_list(env, "EVONIDS_WEBHOOK_ALLOWED_HOSTS")),
                allow_http=env_flag(env, "EVONIDS_WEBHOOK_ALLOW_HTTP", False),
            )
        )
    if not webhook_urls:
        disabled["webhook"] = "EVONIDS_WEBHOOK_URLS is empty"

    syslog_host = env_text(env, "EVONIDS_SYSLOG_HOST")
    syslog: SyslogSettings | None = None
    if syslog_host:
        syslog = SyslogSettings(
            name=env_text(env, "EVONIDS_SYSLOG_NAME") or "syslog",
            host=syslog_host,
            port=env_int(env, "EVONIDS_SYSLOG_PORT", 514),
            protocol=env_text(env, "EVONIDS_SYSLOG_PROTOCOL", "udp").lower(),
            message_format=env_text(env, "EVONIDS_SYSLOG_FORMAT", "rfc5424").lower(),
            facility=env_int(env, "EVONIDS_SYSLOG_FACILITY", 13),
            app_name=env_text(env, "EVONIDS_SYSLOG_APP_NAME", "evonids"),
            enterprise_id=env_int(env, "EVONIDS_SYSLOG_ENTERPRISE_ID", 0),
            min_severity=_severity(env, "EVONIDS_SYSLOG_MIN_SEVERITY", "info"),
        )
    else:
        disabled["syslog"] = "EVONIDS_SYSLOG_HOST is empty"

    stix_dir = env_text(env, "EVONIDS_STIX_EXPORT_DIR")
    stix: StixSettings | None = None
    if stix_dir:
        stix = StixSettings(
            name=env_text(env, "EVONIDS_STIX_NAME") or "stix-export",
            export_dir=stix_dir,
            identity_name=env_text(env, "EVONIDS_STIX_IDENTITY_NAME", "EvoNIDS"),
            identity_id=env_text(env, "EVONIDS_STIX_IDENTITY_ID"),
        )
    else:
        disabled["stix"] = "EVONIDS_STIX_EXPORT_DIR is empty"

    ticket_base = env_text(env, "EVONIDS_TICKET_BASE_URL")
    tickets: TicketSettings | None = None
    if ticket_base:
        tickets = TicketSettings(
            name=env_text(env, "EVONIDS_TICKET_NAME") or "ticket-http",
            base_url=ticket_base,
            create_path=env_text(env, "EVONIDS_TICKET_CREATE_PATH", "/tickets"),
            update_path=env_text(env, "EVONIDS_TICKET_UPDATE_PATH", "/tickets/{ticket_id}"),
            token=env_text(env, "EVONIDS_TICKET_TOKEN") or None,
            auth_header=env_text(env, "EVONIDS_TICKET_AUTH_HEADER", "Authorization"),
            project=env_text(env, "EVONIDS_TICKET_PROJECT"),
            timeout_seconds=env_float(env, "EVONIDS_TICKET_TIMEOUT_SECONDS", 10.0),
            max_attempts=env_int(env, "EVONIDS_TICKET_MAX_ATTEMPTS", 3),
            base_backoff_seconds=env_float(env, "EVONIDS_TICKET_BASE_BACKOFF_SECONDS", 0.5),
            max_backoff_seconds=env_float(env, "EVONIDS_TICKET_MAX_BACKOFF_SECONDS", 8.0),
            circuit_failure_threshold=env_int(env, "EVONIDS_TICKET_CIRCUIT_FAILURES", 5),
            circuit_reset_seconds=env_float(env, "EVONIDS_TICKET_CIRCUIT_RESET_SECONDS", 60.0),
            allowed_hosts=tuple(env_list(env, "EVONIDS_TICKET_ALLOWED_HOSTS")),
            allow_http=env_flag(env, "EVONIDS_TICKET_ALLOW_HTTP", False),
        )
    else:
        disabled["ticket"] = "EVONIDS_TICKET_BASE_URL is empty"

    return IntegrationSettings(
        enabled=True,
        webhooks=tuple(webhooks),
        syslog=syslog,
        stix=stix,
        tickets=tickets,
        disabled_reasons=disabled,
    )


def describe_environment_variables() -> Sequence[dict[str, str]]:
    """Machine-readable list of every variable this module reads (for docs)."""
    return (
        {"name": "EVONIDS_INTEGRATIONS_ENABLED", "default": "false", "purpose": "总开关；未开启时所有连接器都不存在"},
        {"name": "EVONIDS_WEBHOOK_URLS", "default": "", "purpose": "逗号分隔的 Webhook 目标 URL"},
        {"name": "EVONIDS_WEBHOOK_SECRET", "default": "", "purpose": "HMAC-SHA256 签名密钥"},
        {"name": "EVONIDS_WEBHOOK_SECRETS", "default": "", "purpose": "按连接器名/URL 指定密钥（name=secret,...）"},
        {"name": "EVONIDS_WEBHOOK_TIMEOUT_SECONDS", "default": "10", "purpose": "单次请求超时"},
        {"name": "EVONIDS_WEBHOOK_MAX_ATTEMPTS", "default": "3", "purpose": "最大尝试次数"},
        {"name": "EVONIDS_WEBHOOK_CIRCUIT_FAILURES", "default": "5", "purpose": "熔断阈值（连续失败次数）"},
        {"name": "EVONIDS_WEBHOOK_CIRCUIT_RESET_SECONDS", "default": "60", "purpose": "熔断恢复窗口"},
        {"name": "EVONIDS_WEBHOOK_ALLOWED_HOSTS", "default": "", "purpose": "主机白名单（空=任意公网主机）"},
        {"name": "EVONIDS_WEBHOOK_ALLOW_HTTP", "default": "false", "purpose": "是否允许明文 http"},
        {"name": "EVONIDS_SYSLOG_HOST", "default": "", "purpose": "Syslog 服务器地址"},
        {"name": "EVONIDS_SYSLOG_PORT", "default": "514", "purpose": "Syslog 端口"},
        {"name": "EVONIDS_SYSLOG_PROTOCOL", "default": "udp", "purpose": "udp/tcp/tls"},
        {"name": "EVONIDS_SYSLOG_FORMAT", "default": "rfc5424", "purpose": "rfc5424 或 cef"},
        {"name": "EVONIDS_SYSLOG_FACILITY", "default": "13", "purpose": "facility 数值"},
        {"name": "EVONIDS_SYSLOG_APP_NAME", "default": "evonids", "purpose": "RFC5424 APP-NAME"},
        {"name": "EVONIDS_SYSLOG_ENTERPRISE_ID", "default": "0", "purpose": "CEF 设备厂商标识"},
        {"name": "EVONIDS_SYSLOG_MIN_SEVERITY", "default": "info", "purpose": "低于该级别的事件不发送"},
        {"name": "EVONIDS_STIX_EXPORT_DIR", "default": "", "purpose": "STIX 2.1 bundle 导出目录"},
        {"name": "EVONIDS_STIX_IDENTITY_NAME", "default": "EvoNIDS", "purpose": "STIX identity 名称"},
        {"name": "EVONIDS_STIX_IDENTITY_ID", "default": "", "purpose": "固定 STIX identity UUID（可选）"},
        {"name": "EVONIDS_TICKET_BASE_URL", "default": "", "purpose": "工单 API 基地址"},
        {"name": "EVONIDS_TICKET_CREATE_PATH", "default": "/tickets", "purpose": "创建工单路径"},
        {"name": "EVONIDS_TICKET_UPDATE_PATH", "default": "/tickets/{ticket_id}", "purpose": "更新工单路径"},
        {"name": "EVONIDS_TICKET_TOKEN", "default": "", "purpose": "工单 API 令牌"},
        {"name": "EVONIDS_TICKET_AUTH_HEADER", "default": "Authorization", "purpose": "令牌请求头名"},
        {"name": "EVONIDS_TICKET_PROJECT", "default": "", "purpose": "项目/队列标识"},
        {"name": "EVONIDS_TICKET_ALLOWED_HOSTS", "default": "", "purpose": "工单目标主机白名单"},
        {"name": "EVONIDS_TICKET_ALLOW_HTTP", "default": "false", "purpose": "是否允许明文 http"},
    )
