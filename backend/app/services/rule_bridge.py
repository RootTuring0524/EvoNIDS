"""Bridge from the legacy structured rule format to the normalized Rule IR.

The AI agent and analysts still produce ``StructuredRule`` documents whose
conditions reference EvoNIDS flow features (``app.domain.features``). Only a
subset of those features has a real Suricata equivalent, so this bridge is
explicitly lossy and says so:

* ``supported`` conditions are compiled into the IR header/threshold/flow;
* ``approximate`` conditions have a defensible but not exact Suricata form;
* ``unsupported`` conditions cannot be expressed in Suricata at all.

Compilation refuses to produce a rule silently: the caller must acknowledge the
dropped conditions (``accept_partial=True``), and the resulting IR records every
dropped condition in its metadata so the governance record shows exactly what
the compiled rule no longer detects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.domain.features import FEATURES
from app.domain.rule_ir import validate_rule_ir

PROTOCOL_NAMES = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
}
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# feature -> handling. "header" fields shape the rule header, "threshold" fields
# become a Suricata threshold/detection_filter expression.
HEADER_FIELDS = {
    "dst_port": "destinationPort",
    "destination_port": "destinationPort",
    "src_port": "sourcePort",
    "source_port": "sourcePort",
    "dst_ip": "destination",
    "destination_ip": "destination",
    "src_ip": "source",
    "source_ip": "source",
    "protocol": "protocol",
}
THRESHOLD_FIELDS = {
    # Suricata syntax is `track by_src` (underscore); the tuple holds the exact
    # tracking token plus the measurement window in seconds.
    "destination_port_count_60s": ("by_src", 60),
    "destination_ip_count_60s": ("by_src", 60),
    "flow_count_60s": ("by_src", 60),
}
APPROXIMATE_FIELDS = {"syn_ratio", "ack_ratio", "rst_ratio"}


@dataclass(slots=True)
class ConditionAssessment:
    condition: dict[str, Any]
    disposition: str  # supported | approximate | unsupported
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"condition": self.condition, "disposition": self.disposition, "reason": self.reason}


@dataclass(slots=True)
class BridgeResult:
    compilable: bool
    ir_document: dict[str, Any] | None = None
    suricata_text: str | None = None
    supported: list[ConditionAssessment] = field(default_factory=list)
    approximate: list[ConditionAssessment] = field(default_factory=list)
    unsupported: list[ConditionAssessment] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def dropped(self) -> list[ConditionAssessment]:
        return [*self.approximate, *self.unsupported]

    def as_dict(self) -> dict[str, Any]:
        return {
            "compilable": self.compilable,
            "irDocument": self.ir_document,
            "suricataText": self.suricata_text,
            "supported": [item.as_dict() for item in self.supported],
            "approximate": [item.as_dict() for item in self.approximate],
            "unsupported": [item.as_dict() for item in self.unsupported],
            "notes": self.notes,
            "droppedCount": len(self.dropped),
        }


def assess_conditions(conditions: list[dict[str, Any]]) -> tuple[list[ConditionAssessment], list[ConditionAssessment], list[ConditionAssessment]]:
    supported: list[ConditionAssessment] = []
    approximate: list[ConditionAssessment] = []
    unsupported: list[ConditionAssessment] = []
    for condition in conditions:
        field_name = str(condition.get("field", ""))
        operator = str(condition.get("operator", ""))
        value = condition.get("value")
        if field_name not in FEATURES:
            unsupported.append(
                ConditionAssessment(condition, "unsupported", f"字段 {field_name!r} 不在特征契约中")
            )
            continue
        if field_name in HEADER_FIELDS:
            if operator != "==":
                approximate.append(
                    ConditionAssessment(
                        condition,
                        "approximate",
                        f"{field_name} 只支持等值匹配；{operator} 无法在 Suricata 头部精确表达",
                    )
                )
            elif HEADER_FIELDS[field_name] == "protocol" and str(value).lower() not in PROTOCOL_NAMES:
                unsupported.append(
                    ConditionAssessment(condition, "unsupported", f"协议值 {value!r} 无法映射到 Suricata 协议名")
                )
            elif HEADER_FIELDS[field_name] in {"destination", "source"} and not _valid_network(value):
                unsupported.append(
                    ConditionAssessment(condition, "unsupported", f"地址值 {value!r} 不是 IP 或 CIDR")
                )
            else:
                supported.append(ConditionAssessment(condition, "supported", "映射到 Suricata 规则头部"))
            continue
        if field_name in THRESHOLD_FIELDS:
            if operator in {">", ">="} and isinstance(value, (int, float)):
                supported.append(
                    ConditionAssessment(
                        condition, "supported", "映射为 Suricata threshold/detection_filter"
                    )
                )
            else:
                unsupported.append(
                    ConditionAssessment(
                        condition,
                        "unsupported",
                        f"{field_name} 仅在 >/>= 数值条件下可映射为阈值表达式",
                    )
                )
            continue
        if field_name in APPROXIMATE_FIELDS:
            approximate.append(
                ConditionAssessment(
                    condition,
                    "approximate",
                    "TCP 标志比例只能近似为 flags 匹配，语义不完全等价",
                )
            )
            continue
        unsupported.append(
            ConditionAssessment(
                condition,
                "unsupported",
                f"{field_name} 是流统计特征，Suricata 规则语言没有对应匹配项",
            )
        )
    return supported, approximate, unsupported


def _valid_network(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if candidate.startswith("$") and re.match(r"^\$[A-Za-z_]+$", candidate):
        return True
    if candidate.lower() == "any":
        return True
    return bool(IP_PATTERN.match(candidate.split("/")[0]))


def structured_to_ir(
    structured: dict[str, Any],
    *,
    sid: int,
    msg: str | None = None,
    accept_partial: bool = False,
    severity_to_classtype: bool = True,
) -> BridgeResult:
    """Convert a structured rule document into Rule IR (or explain why not).

    ``structured`` is the JSON form of ``app.schemas.api.StructuredRule``.
    """
    conditions = structured.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        return BridgeResult(compilable=False, notes=["结构化规则没有任何条件，无法编译。"])

    supported, approximate, unsupported = assess_conditions(conditions)
    result = BridgeResult(
        compilable=False,
        supported=supported,
        approximate=approximate,
        unsupported=unsupported,
    )
    if not supported:
        result.notes.append("没有任何条件可以映射到 Suricata 匹配项，无法生成真实规则。")
        return result
    if result.dropped and not accept_partial:
        result.notes.append(
            f"有 {len(result.dropped)} 个条件无法精确编译；需要显式确认接受部分转换后才能生成规则。"
        )
        return result

    header = {
        "action": "alert",
        "protocol": "tcp",
        "source": "$HOME_NET",
        "sourcePort": "any",
        "direction": "->",
        "destination": "$EXTERNAL_NET",
        "destinationPort": "any",
    }
    threshold_parts: list[str] = []
    for assessment in supported:
        condition = assessment.condition
        field_name = str(condition["field"])
        value = condition["value"]
        if field_name in THRESHOLD_FIELDS:
            track, seconds = THRESHOLD_FIELDS[field_name]
            threshold_parts.append(
                f"detection_filter: track {track}, count {int(value)}, seconds {seconds}"
            )
            continue
        mapped = HEADER_FIELDS[field_name]
        if mapped == "protocol":
            header["protocol"] = PROTOCOL_NAMES[str(value).lower()]
        elif mapped in {"source", "destination"}:
            header[mapped] = str(value)
        else:
            header[mapped] = str(value)

    flag_tokens: list[str] = []
    if accept_partial:
        # Approximated TCP-flag ratios become a real Suricata detection option so
        # the compiled rule has something to match on; the approximation is
        # recorded in metadata and must still survive sandbox validation.
        for assessment in approximate:
            field_name = str(assessment.condition.get("field"))
            if field_name == "syn_ratio":
                flag_tokens.append("S")
            elif field_name == "rst_ratio":
                flag_tokens.append("R")
            elif field_name == "ack_ratio":
                flag_tokens.append("A")

    rule_name = str(structured.get("rule_name") or "EvoNIDS 候选规则")
    attack_type = str(structured.get("attack_type") or "unknown")
    mitre = [
        str(item).upper()
        for item in (structured.get("mitre_technique_ids") or [])
        if re.match(r"^T\d{4}(?:\.\d{3})?$", str(item).upper())
    ]
    metadata: dict[str, str] = {
        "source": str(structured.get("generated_by") or "structured-rule"),
        "attack_type": attack_type,
    }
    if result.dropped:
        metadata["dropped_conditions"] = str(len(result.dropped))
        metadata["partial_conversion"] = "true"
    if structured.get("evidence_ids"):
        metadata["evidence_count"] = str(len(structured["evidence_ids"]))

    document: dict[str, Any] = {
        "header": header,
        "contents": [],
        "meta": {
            "sid": sid,
            "rev": int(structured.get("version") or 1),
            "msg": (msg or f"{rule_name} [{attack_type}]")[:200],
            "classtype": _classtype_for(attack_type) if severity_to_classtype else None,
            "priority": _priority_for(str(structured.get("severity") or "medium")),
            "mitreTechniques": mitre,
            "metadata": metadata,
        },
        "threshold": threshold_parts[0] if threshold_parts else None,
        "flags": "".join(dict.fromkeys(flag_tokens)) or None,
    }
    if not threshold_parts and not flag_tokens:
        # A Suricata rule needs at least one detection option beyond the header.
        result.notes.append(
            "仅头部条件无法构成有效 Suricata 规则：需要一个检测选项"
            "（阈值、TCP 标志匹配或内容匹配）；请提供 contentPattern 或可映射的统计条件。"
        )
        return result

    from app.domain.rule_ir import parse_rule_ir

    try:
        ir = parse_rule_ir(document)
    except ValueError as error:
        result.notes.append(f"生成的 IR 未通过校验：{error}")
        return result
    validate_rule_ir(ir)
    result.compilable = True
    result.ir_document = ir.canonical()
    result.suricata_text = ir.compile()
    result.notes.append(
        "已生成 IR 与 Suricata 文本；这是从结构化条件转换而来的近似规则，"
        "必须经过真实沙箱回放才能部署。"
    )
    return result


def _classtype_for(attack_type: str) -> str:
    lowered = attack_type.lower()
    if "scan" in lowered or "recon" in lowered:
        return "attempted-recon"
    if "dos" in lowered or "flood" in lowered:
        return "attempted-dos"
    if "brute" in lowered or "password" in lowered:
        return "attempted-user"
    if "web" in lowered or "sql" in lowered or "xss" in lowered:
        return "web-application-attack"
    if "c2" in lowered or "botnet" in lowered or "c&c" in lowered:
        return "malware-cnc"
    return "misc-activity"


def _priority_for(severity: str) -> int:
    return {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity.lower(), 3)
