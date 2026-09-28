"""Whitelisted, read-only tools an investigation may call.

There is no generic "fetch URL" / "read file" / "run command" tool, and there
never will be: the model can only name a tool from this registry, every argument
is validated against a declared schema, every call is persisted, and every result
is a bounded, redacted JSON document. Tool calls cannot mutate state.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Alert, Entity, EvidenceRecord, Flow
from app.services.knowledge_retrieval import EmbeddingProvider, retrieval_snapshot
from app.services.online_detection import assessments_for_flow, signals_for_flow

TOOL_REGISTRY_VERSION = "tools-v1"
MAX_RESULT_ITEMS = 20
MAX_TEXT_CHARS = 600

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:sk|pk)-[A-Za-z0-9]{16,}\b"), "[redacted-key]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "[redacted-jwt]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"), r"\1=[redacted]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[redacted-private-key]"),
)


def redact_text(value: str, *, limit: int = MAX_TEXT_CHARS) -> str:
    """Mask credential-shaped content and bound the length of tool output."""
    redacted = value
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) > limit:
        return redacted[:limit] + f"...[truncated {len(redacted) - limit} chars]"
    return redacted


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    required_args: tuple[str, ...]
    optional_args: tuple[str, ...]
    handler: Callable[..., dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool: str
    state: str
    output: dict[str, Any]
    duration_ms: float
    error: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)


def _require(args: dict[str, Any], name: str, kind: type) -> Any:
    value = args.get(name)
    if value is None:
        raise ValueError(f"missing required argument: {name}")
    if kind is str and not isinstance(value, str):
        raise ValueError(f"argument {name} must be a string")
    if kind is int and (isinstance(value, bool) or not isinstance(value, int)):
        raise ValueError(f"argument {name} must be an integer")
    if kind is str and len(value) > 128:
        raise ValueError(f"argument {name} is too long")
    return value


def _optional_int(args: dict[str, Any], name: str, *, default: int, low: int, high: int) -> int:
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"argument {name} must be an integer")
    return max(low, min(high, value))


def _evidence_tool(db: Session, args: dict[str, Any]) -> dict[str, Any]:
    evidence_id = _require(args, "evidenceId", str)
    row = db.get(EvidenceRecord, evidence_id)
    if row is None:
        return {"found": False, "evidenceId": evidence_id}
    return {
        "found": True,
        "evidenceId": row.id,
        "sensorId": row.sensor_id,
        "eventType": row.event_type,
        "externalId": row.external_id,
        "observedAt": row.observed_at.isoformat(),
        "receivedAt": row.received_at.isoformat(),
        "contentSha256": row.content_sha256,
        "integrity": row.integrity,
        "dataMissing": row.data_missing,
        "parserVersion": row.parser_version,
        "fields": _redact_mapping(row.fields),
    }


def _alert_evidence_tool(db: Session, args: dict[str, Any]) -> dict[str, Any]:
    alert_id = _require(args, "alertId", str)
    limit = _optional_int(args, "limit", default=10, low=1, high=MAX_RESULT_ITEMS)
    alert = db.get(Alert, alert_id)
    if alert is None:
        return {"found": False, "alertId": alert_id, "items": []}
    query = select(EvidenceRecord).where(EvidenceRecord.sensor_id == alert.sensor).limit(limit)
    if alert.flow_id:
        query = select(EvidenceRecord).where(
            EvidenceRecord.source_ref_id.in_([alert.flow_id, alert.id])
        ).limit(limit)
    rows = list(db.scalars(query).all())
    return {
        "found": True,
        "alertId": alert_id,
        "items": [
            {
                "evidenceId": row.id,
                "eventType": row.event_type,
                "observedAt": row.observed_at.isoformat(),
                "contentSha256": row.content_sha256,
                "dataMissing": row.data_missing,
            }
            for row in rows
        ],
    }


def _flow_tool(db: Session, args: dict[str, Any]) -> dict[str, Any]:
    flow_id = _require(args, "flowId", str)
    flow = db.get(Flow, flow_id)
    if flow is None:
        return {"found": False, "flowId": flow_id}
    return {
        "found": True,
        "flowId": flow.id,
        "sensorId": flow.sensor_id,
        "time": flow.time.isoformat(),
        "source": flow.source,
        "destination": flow.destination,
        "sourcePort": flow.source_port,
        "destinationPort": flow.destination_port,
        "protocol": flow.protocol,
        "service": flow.service,
        "packets": flow.packets,
        "bytes": flow.bytes,
        "durationMs": flow.duration_ms,
        "verdict": flow.verdict,
        "anomalyScore": flow.anomaly_score,
        "featureVersion": flow.feature_version,
        "features": _redact_mapping(flow.features),
    }


def _detection_signals_tool(db: Session, args: dict[str, Any]) -> dict[str, Any]:
    flow_id = _require(args, "flowId", str)
    signals = signals_for_flow(db, flow_id)[:MAX_RESULT_ITEMS]
    assessments = assessments_for_flow(db, flow_id)[:2]
    return {
        "flowId": flow_id,
        "signals": [
            {
                "signalId": signal.id,
                "channel": signal.channel,
                "channelVersion": signal.channel_version,
                "modelId": signal.model_id,
                "rawScore": signal.raw_score,
                "calibratedScore": signal.calibrated_score,
                "threshold": signal.threshold,
                "decision": signal.decision,
                "degraded": signal.degraded,
                "degradedReason": signal.degraded_reason,
                "imputedFeatureCount": len(signal.imputed_features or []),
            }
            for signal in signals
        ],
        "assessments": [
            {
                "assessmentId": item.id,
                "decision": item.decision,
                "finalScore": item.final_score,
                "uncertainty": item.uncertainty,
                "mode": item.mode,
                "explanation": redact_text(item.explanation, limit=400),
                "weights": item.weights,
                "degradedReasons": item.degraded_reasons,
            }
            for item in assessments
        ],
    }


def _alert_tool(db: Session, args: dict[str, Any]) -> dict[str, Any]:
    alert_id = _require(args, "alertId", str)
    alert = db.get(Alert, alert_id)
    if alert is None:
        return {"found": False, "alertId": alert_id}
    return {
        "found": True,
        "alertId": alert.id,
        "title": redact_text(alert.title, limit=200),
        "severity": alert.severity,
        "status": alert.status,
        "category": alert.category,
        "timestamp": alert.timestamp.isoformat(),
        "sensor": alert.sensor,
        "sourceIp": alert.source_ip,
        "destinationIp": alert.destination_ip,
        "destinationPort": alert.destination_port,
        "protocol": alert.protocol,
        "riskScore": alert.risk_score,
        "detector": alert.detector,
        "flowId": alert.flow_id,
        "evidence": [redact_text(item, limit=200) for item in (alert.evidence or [])],
    }


def _entity_tool(db: Session, args: dict[str, Any]) -> dict[str, Any]:
    value = _require(args, "value", str)
    row = db.scalar(select(Entity).where(Entity.value == value))
    if row is None:
        return {"found": False, "value": value}
    return {
        "found": True,
        "entityId": row.id,
        "entityType": row.entity_type,
        "value": row.value,
        "firstSeenAt": row.first_seen_at.isoformat(),
        "lastSeenAt": row.last_seen_at.isoformat(),
        "eventCount": row.event_count,
        "sensorIds": row.sensor_ids,
    }


def _knowledge_tool_factory(provider: EmbeddingProvider | None, workspace_id: str) -> Callable[..., dict[str, Any]]:
    def _handler(db: Session, args: dict[str, Any]) -> dict[str, Any]:
        query = _require(args, "query", str)
        top_k = _optional_int(args, "topK", default=4, low=1, high=8)
        snapshot = retrieval_snapshot(
            db,
            query=query,
            top_k=top_k,
            workspace_id=workspace_id,
            embedding_provider=provider,
        )
        return snapshot.as_dict()

    return _handler


def build_registry(
    *, embedding_provider: EmbeddingProvider | None = None, workspace_id: str = "default"
) -> dict[str, ToolSpec]:
    return {
        "get_evidence": ToolSpec(
            name="get_evidence",
            description="按证据 ID 读取一条已登记证据的元数据与提取字段（只读）。",
            required_args=("evidenceId",),
            optional_args=(),
            handler=_evidence_tool,
        ),
        "list_alert_evidence": ToolSpec(
            name="list_alert_evidence",
            description="列出某告警关联的证据条目（只读，最多 20 条）。",
            required_args=("alertId",),
            optional_args=("limit",),
            handler=_alert_evidence_tool,
        ),
        "get_alert": ToolSpec(
            name="get_alert",
            description="读取告警的权威字段（只读）。",
            required_args=("alertId",),
            optional_args=(),
            handler=_alert_tool,
        ),
        "get_flow": ToolSpec(
            name="get_flow",
            description="读取流量记录与在线特征（只读）。",
            required_args=("flowId",),
            optional_args=(),
            handler=_flow_tool,
        ),
        "get_detection_signals": ToolSpec(
            name="get_detection_signals",
            description="读取某流量的双通道检测信号与风险融合评估（只读）。",
            required_args=("flowId",),
            optional_args=(),
            handler=_detection_signals_tool,
        ),
        "get_entity": ToolSpec(
            name="get_entity",
            description="按 IP/实体值读取实体画像（只读）。",
            required_args=("value",),
            optional_args=(),
            handler=_entity_tool,
        ),
        "search_knowledge": ToolSpec(
            name="search_knowledge",
            description="在已授权知识库中做混合检索，返回带来源与信任等级的条目（只读）。",
            required_args=("query",),
            optional_args=("topK",),
            handler=_knowledge_tool_factory(embedding_provider, workspace_id),
        ),
    }


def tool_catalogue(registry: dict[str, ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "description": spec.description,
            "requiredArgs": list(spec.required_args),
            "optionalArgs": list(spec.optional_args),
        }
        for spec in registry.values()
    ]


def execute_tool(
    db: Session,
    registry: dict[str, ToolSpec],
    name: str,
    arguments: dict[str, Any] | None,
    *,
    allowed_evidence_ids: Sequence[str] | None = None,
) -> ToolResult:
    """Validate and run one whitelisted tool; never raises into the caller."""
    started = time.perf_counter()
    args = dict(arguments or {})
    spec = registry.get(name)
    if spec is None:
        return ToolResult(
            tool=name,
            state="rejected",
            output={},
            duration_ms=0.0,
            error=f"tool {name!r} is not in the whitelist",
            arguments=_redact_mapping(args),
        )
    unknown = set(args) - set(spec.required_args) - set(spec.optional_args)
    if unknown:
        return ToolResult(
            tool=name,
            state="rejected",
            output={},
            duration_ms=0.0,
            error=f"unsupported arguments: {sorted(unknown)}",
            arguments=_redact_mapping(args),
        )
    if allowed_evidence_ids is not None and "evidenceId" in args:
        if args["evidenceId"] not in set(allowed_evidence_ids):
            return ToolResult(
                tool=name,
                state="rejected",
                output={},
                duration_ms=0.0,
                error="evidence id is outside the investigation's evidence whitelist",
                arguments=_redact_mapping(args),
            )
    try:
        output = spec.handler(db, args)
    except ValueError as error:
        return ToolResult(
            tool=name,
            state="rejected",
            output={},
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            error=str(error),
            arguments=_redact_mapping(args),
        )
    except Exception as error:  # noqa: BLE001 - a tool bug must not break the investigation
        return ToolResult(
            tool=name,
            state="failed",
            output={},
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            error=f"{type(error).__name__}: {error}"[:255],
            arguments=_redact_mapping(args),
        )
    return ToolResult(
        tool=name,
        state="completed",
        output=_redact_mapping(output),
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
        arguments=_redact_mapping(args),
    )


def _redact_mapping(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_mapping(item) for item in value[:MAX_RESULT_ITEMS]]
    if isinstance(value, dict):
        return {str(key): _redact_mapping(item) for key, item in list(value.items())[:40]}
    return value
