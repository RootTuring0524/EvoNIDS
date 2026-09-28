"""Normalized Rule IR and deterministic Suricata compilation.

The previous structured-condition format (``app.domain.rules``) can only be
evaluated by the in-process predicate replay, so its results could never be
called Suricata validation. This module defines a rule intermediate
representation that:

* validates every field before anything is compiled (no free-form rule text is
  ever accepted from a model or an analyst);
* compiles deterministically to Suricata rule syntax, with explicit escaping;
* carries the metadata a governance workflow needs (SID/revision range,
  classtype, priority, references, MITRE techniques, provenance).

Nothing here executes Suricata; execution lives in ``app.services.rule_sandbox``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

IR_VERSION = "rule-ir-v1"
LOCAL_SID_MIN = 1_000_000
LOCAL_SID_MAX = 1_999_999

ACTIONS = ("alert", "drop", "reject", "pass")
PROTOCOLS = ("tcp", "udp", "icmp", "ip", "http", "dns", "tls", "smb", "flow")
DIRECTIONS = ("->", "<>", "<-")
CLASSTYPES = (
    "attempted-recon",
    "attempted-admin",
    "attempted-user",
    "attempted-dos",
    "successful-admin",
    "successful-user",
    "trojan-activity",
    "policy-violation",
    "protocol-command-decode",
    "web-application-attack",
    "malware-cnc",
    "network-scan",
    "misc-activity",
    "not-suspicious",
)
_MODIFIERS = {
    "nocase",
    "fast_pattern",
    "http_uri",
    "http_header",
    "http_client_body",
    "http_method",
    "dns_query",
    "tls_sni",
    "startswith",
    "endswith",
}
_PCRE_FORBIDDEN = ("(?R)", "(?0)", "(?{", "(?(R)", "(?(DEFINE)", "\\K")
FORBIDDEN_PCRE_CONSTRUCTS: tuple[str, ...] = tuple(_PCRE_FORBIDDEN)
_MSG_PATTERN = re.compile(r"^[\x20-\x7e\u4e00-\u9fff]{1,200}$")
_REFERENCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{1,31},\s*\S{1,120}$", re.IGNORECASE)
_NET_PATTERN = re.compile(r"^(\$?[A-Za-z_]+|\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[0-9A-Fa-f:]{2,39}(?:/\d{1,3})?|any)$")
_PORT_PATTERN = re.compile(r"^(any|\d{1,5}(?::\d{1,5})?|\[\s*\d{1,5}(?:\s*,\s*\d{1,5})*\s*\])$")
_MITRE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class RuleIRError(ValueError):
    """Raised when a rule document cannot be accepted or compiled."""


@dataclass(frozen=True, slots=True)
class RuleHeader:
    action: Literal["alert", "drop", "reject", "pass"]
    protocol: str
    source: str
    source_port: str
    direction: str
    destination: str
    destination_port: str


@dataclass(frozen=True, slots=True)
class RuleContent:
    pattern: str
    nocase: bool = False
    depth: int | None = None
    distance: int | None = None
    within: int | None = None
    negate: bool = False
    modifiers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleMeta:
    sid: int
    rev: int
    msg: str
    classtype: str | None = None
    priority: int | None = None
    references: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuleIR:
    header: RuleHeader
    contents: tuple[RuleContent, ...]
    meta: RuleMeta
    flow: str | None = None
    pcre: str | None = None
    threshold: str | None = None
    app_protocol: str | None = None
    # TCP flag matcher: a real Suricata detection option that can stand alone,
    # used by the structured-rule bridge when a ratio condition is approximated.
    flags: str | None = None
    ir_version: str = IR_VERSION

    def canonical(self) -> dict[str, Any]:
        return {
            "irVersion": self.ir_version,
            "header": asdict(self.header),
            "contents": [asdict(item) for item in self.contents],
            "flow": self.flow,
            "pcre": self.pcre,
            "threshold": self.threshold,
            "flags": self.flags,
            "appProtocol": self.app_protocol,
            "meta": asdict(self.meta),
        }

    def digest(self) -> str:
        payload = json.dumps(self.canonical(), ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def compile(self) -> str:
        return compile_suricata(self)


def parse_rule_ir(payload: dict[str, Any]) -> RuleIR:
    """Build and validate a RuleIR from untrusted JSON (model or analyst input)."""
    if not isinstance(payload, dict):
        raise RuleIRError("rule document must be a JSON object")
    header_payload = payload.get("header")
    meta_payload = payload.get("meta")
    contents_payload = payload.get("contents")
    if not isinstance(header_payload, dict) or not isinstance(meta_payload, dict):
        raise RuleIRError("rule document requires 'header' and 'meta' objects")
    if not isinstance(contents_payload, list) or not contents_payload:
        # A rule may also be detection-option-only via pcre or a flag matcher;
        # both are real Suricata detection options. Full validation below decides.
        if not payload.get("pcre") and not payload.get("flags"):
            raise RuleIRError("rule document requires at least one content matcher")
    header = RuleHeader(
        action=str(header_payload.get("action", "alert")).lower(),  # type: ignore[arg-type]
        protocol=str(header_payload.get("protocol", "")).lower(),
        source=str(header_payload.get("source", "")),
        source_port=str(header_payload.get("sourcePort", "any")),
        direction=str(header_payload.get("direction", "->")),
        destination=str(header_payload.get("destination", "")),
        destination_port=str(header_payload.get("destinationPort", "any")),
    )
    raw_contents: list[Any] = contents_payload if isinstance(contents_payload, list) else []
    content_items: list[Any] = [item for item in raw_contents if isinstance(item, dict)]
    contents = tuple(
        RuleContent(
            pattern=str(item.get("pattern", "")),
            nocase=bool(item.get("nocase", False)),
            depth=_optional_int(item.get("depth"), "depth"),
            distance=_optional_int(item.get("distance"), "distance"),
            within=_optional_int(item.get("within"), "within"),
            negate=bool(item.get("negate", False)),
            modifiers=tuple(str(value).lower() for value in (item.get("modifiers") or [])),
        )
        for item in content_items
    )
    meta = RuleMeta(
        sid=int(meta_payload.get("sid", 0)),
        rev=int(meta_payload.get("rev", 1)),
        msg=str(meta_payload.get("msg", "")),
        classtype=(str(meta_payload["classtype"]) if meta_payload.get("classtype") else None),
        priority=_optional_int(meta_payload.get("priority"), "priority"),
        references=tuple(str(value) for value in (meta_payload.get("references") or [])),
        mitre_techniques=tuple(str(value).upper() for value in (meta_payload.get("mitreTechniques") or [])),
        metadata={str(key): str(value) for key, value in (meta_payload.get("metadata") or {}).items()},
    )
    ir = RuleIR(
        header=header,
        contents=contents,
        meta=meta,
        flow=(str(payload["flow"]) if payload.get("flow") else None),
        pcre=(str(payload["pcre"]) if payload.get("pcre") else None),
        threshold=(str(payload["threshold"]) if payload.get("threshold") else None),
        app_protocol=(str(payload["appProtocol"]).lower() if payload.get("appProtocol") else None),
        flags=(str(payload["flags"]).upper() if payload.get("flags") else None),
    )
    validate_rule_ir(ir)
    return ir


def _optional_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuleIRError(f"{name} must be an integer")
    if value < 0:
        raise RuleIRError(f"{name} must be >= 0")
    return value


def validate_rule_ir(ir: RuleIR) -> None:
    header = ir.header
    if header.action not in ACTIONS:
        raise RuleIRError(f"action must be one of {list(ACTIONS)}")
    if header.protocol not in PROTOCOLS:
        raise RuleIRError(f"protocol must be one of {list(PROTOCOLS)}")
    if header.direction not in DIRECTIONS:
        raise RuleIRError(f"direction must be one of {list(DIRECTIONS)}")
    for value, name in ((header.source, "source"), (header.destination, "destination")):
        if not _NET_PATTERN.match(value):
            raise RuleIRError(f"{name} must be a CIDR, a variable like $HOME_NET or 'any'")
    for value, name in (
        (header.source_port, "sourcePort"),
        (header.destination_port, "destinationPort"),
    ):
        if not _PORT_PATTERN.match(value):
            raise RuleIRError(f"{name} must be 'any', a port, a range or a bracketed list")

    meta = ir.meta
    if not LOCAL_SID_MIN <= meta.sid <= LOCAL_SID_MAX:
        raise RuleIRError(
            f"sid {meta.sid} is outside the local allocation range {LOCAL_SID_MIN}-{LOCAL_SID_MAX}"
        )
    if meta.rev < 1:
        raise RuleIRError("rev must be >= 1")
    if not _MSG_PATTERN.match(meta.msg):
        raise RuleIRError("msg must be 1-200 printable characters")
    if meta.classtype is not None and meta.classtype not in CLASSTYPES:
        raise RuleIRError(f"classtype must be one of {list(CLASSTYPES)}")
    if meta.priority is not None and not 1 <= meta.priority <= 255:
        raise RuleIRError("priority must be between 1 and 255")
    for reference in meta.references:
        if not _REFERENCE_PATTERN.match(reference):
            raise RuleIRError(f"reference {reference!r} must look like 'cve,CVE-2024-1234'")
    for technique in meta.mitre_techniques:
        if not _MITRE_PATTERN.match(technique):
            raise RuleIRError(f"mitre technique {technique!r} must look like T1046 or T1595.001")

    if not ir.contents and not ir.pcre and not ir.flags:
        raise RuleIRError("a rule needs at least one detection option (content, pcre or flags)")
    if ir.flags is not None and not re.match(r"^[FSPRAUIEC0-9*!]+$", ir.flags):
        raise RuleIRError("flags must be a Suricata flag expression such as S, SA, R or S*")
    for content in ir.contents:
        if not content.pattern:
            raise RuleIRError("content pattern cannot be empty")
        if len(content.pattern) > 512:
            raise RuleIRError("content pattern is longer than 512 bytes")
        if content.depth is not None and content.within is not None and content.within < content.depth:
            raise RuleIRError("within must be >= depth")
        for modifier in content.modifiers:
            if modifier not in _MODIFIERS:
                raise RuleIRError(f"content modifier {modifier!r} is not allowed")
    if ir.pcre is not None:
        if len(ir.pcre) > 512:
            raise RuleIRError("pcre is longer than 512 characters")
        for forbidden in FORBIDDEN_PCRE_CONSTRUCTS:
            if forbidden in ir.pcre:
                raise RuleIRError(f"pcre contains a forbidden construct: {forbidden}")
    if ir.flow is not None and not re.match(
        r"^(to_server|to_client|from_server|from_client|established|not_established|stateless)"
        r"(,\s*(to_server|to_client|from_server|from_client|established|not_established|stateless))*$",
        ir.flow,
    ):
        raise RuleIRError("flow must be a comma separated list of Suricata flow keywords")
    if ir.threshold is not None and not re.match(
        r"^(threshold|detection_filter):\s*"
        r"(type\s+[\w,]+\s*,\s*)?"
        r"track[ _]by_(src|dst|rule)\s*,\s*count\s+\d+\s*,\s*seconds\s+\d+\s*$",
        ir.threshold,
    ):
        raise RuleIRError("threshold must be a threshold:/detection_filter: expression")
    if ir.app_protocol is not None and not re.match(r"^[a-z0-9_-]{1,32}$", ir.app_protocol):
        raise RuleIRError("appProtocol must be a Suricata application protocol name")


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")


def compile_suricata(ir: RuleIR) -> str:
    """Compile the IR to a single Suricata rule line (deterministic)."""
    validate_rule_ir(ir)
    header = (
        f"{ir.header.action} {ir.header.protocol} {ir.header.source} {ir.header.source_port} "
        f"{ir.header.direction} {ir.header.destination} {ir.header.destination_port}"
    )
    options: list[str] = [f'msg:"{_escape(ir.meta.msg)}"']
    if ir.flow:
        options.append(f"flow:{ir.flow}")
    for content in ir.contents:
        prefix = "!" if content.negate else ""
        options.append(f'content:{prefix}"{_escape(content.pattern)}"')
        if content.nocase:
            options.append("nocase")
        if content.depth is not None:
            options.append(f"depth:{content.depth}")
        if content.distance is not None:
            options.append(f"distance:{content.distance}")
        if content.within is not None:
            options.append(f"within:{content.within}")
        options.extend(content.modifiers)
    if ir.flags:
        options.append(f"flags:{ir.flags}")
    if ir.pcre:
        options.append(f'pcre:"{_escape(ir.pcre)}"')
    if ir.threshold:
        options.append(ir.threshold)
    if ir.app_protocol:
        options.append(f"app-layer-protocol:{ir.app_protocol}")
    for reference in ir.meta.references:
        options.append(f"reference:{reference}")
    options.append(f"sid:{ir.meta.sid}")
    options.append(f"rev:{ir.meta.rev}")
    if ir.meta.classtype:
        options.append(f"classtype:{ir.meta.classtype}")
    if ir.meta.priority is not None:
        options.append(f"priority:{ir.meta.priority}")
    metadata_parts = [f"{key} {value}" for key, value in sorted(ir.meta.metadata.items())]
    for technique in ir.meta.mitre_techniques:
        metadata_parts.append(f"mitre_technique_id {technique}")
    if metadata_parts:
        options.append(f'metadata:{", ".join(metadata_parts)}')
    return f"{header} ({'; '.join(options)};)"


def next_revision(previous: RuleIR, *, msg: str | None = None) -> RuleIR:
    """Return the same rule with rev+1 (used when a candidate is repaired)."""
    return RuleIR(
        header=previous.header,
        contents=previous.contents,
        meta=RuleMeta(
            sid=previous.meta.sid,
            rev=previous.meta.rev + 1,
            msg=msg or previous.meta.msg,
            classtype=previous.meta.classtype,
            priority=previous.meta.priority,
            references=previous.meta.references,
            mitre_techniques=previous.meta.mitre_techniques,
            metadata=previous.meta.metadata,
        ),
        flow=previous.flow,
        pcre=previous.pcre,
        threshold=previous.threshold,
        app_protocol=previous.app_protocol,
        flags=previous.flags,
    )


def allocate_sid(db: Any) -> int:
    """Allocate the next free local SID (max existing + 1, never below 1000000)."""
    from sqlalchemy import func, select

    from app.db.models import RuleIRVersion

    highest = db.scalar(select(func.max(RuleIRVersion.sid)))
    if highest is None:
        return LOCAL_SID_MIN
    return min(int(highest) + 1, LOCAL_SID_MAX)
