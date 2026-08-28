from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO


SUPPORTED_EVENT_TYPES = {"alert", "flow", "dns", "http", "tls", "anomaly"}


@dataclass(frozen=True, slots=True)
class EveRecord:
    event_type: str
    timestamp: str
    flow_id: str
    community_id: str | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None
    payload: dict[str, Any]
    line_number: int


@dataclass(frozen=True, slots=True)
class EveParseFailure:
    line_number: int
    reason: str
    raw: str


def parse_eve_line(line: str, line_number: int = 1) -> EveRecord:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at line {line_number}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"EVE line {line_number} must contain a JSON object")

    event_type = str(payload.get("event_type", "unknown"))
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError(f"EVE line {line_number} is missing timestamp")

    raw_flow_id = payload.get("flow_id")
    flow_id = str(raw_flow_id) if raw_flow_id is not None else f"event:{line_number}"
    return EveRecord(
        event_type=event_type,
        timestamp=timestamp,
        flow_id=flow_id,
        community_id=payload.get("community_id"),
        source_ip=payload.get("src_ip"),
        source_port=_optional_int(payload.get("src_port")),
        destination_ip=payload.get("dest_ip"),
        destination_port=_optional_int(payload.get("dest_port")),
        protocol=payload.get("proto"),
        payload=payload,
        line_number=line_number,
    )


def iter_eve_stream(stream: TextIO, failures: list[EveParseFailure] | None = None) -> Iterator[EveRecord]:
    for line_number, raw in enumerate(stream, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            yield parse_eve_line(line, line_number)
        except ValueError as exc:
            if failures is None:
                raise
            failures.append(EveParseFailure(line_number, str(exc), line[:500]))


def iter_eve_file(path: str | Path, failures: list[EveParseFailure] | None = None) -> Iterator[EveRecord]:
    with Path(path).open("r", encoding="utf-8") as stream:
        yield from iter_eve_stream(stream, failures)


def flow_payload(record: EveRecord) -> dict[str, Any] | None:
    if record.event_type != "flow":
        return None
    flow = record.payload.get("flow")
    if not isinstance(flow, dict):
        return None
    to_server_packets = _optional_int(flow.get("pkts_toserver")) or 0
    to_client_packets = _optional_int(flow.get("pkts_toclient")) or 0
    to_server_bytes = _optional_int(flow.get("bytes_toserver")) or 0
    to_client_bytes = _optional_int(flow.get("bytes_toclient")) or 0
    age_seconds = _optional_int(flow.get("age")) or 0
    return {
        "external_id": record.flow_id,
        "timestamp": record.timestamp,
        "src_ip": record.source_ip,
        "src_port": record.source_port,
        "dst_ip": record.destination_ip,
        "dst_port": record.destination_port,
        "protocol": record.protocol or "unknown",
        "flow_duration": float(max(age_seconds, 0)),
        "forward_packet_count": max(to_server_packets, 0),
        "backward_packet_count": max(to_client_packets, 0),
        "forward_bytes": max(to_server_bytes, 0),
        "backward_bytes": max(to_client_bytes, 0),
    }


def _optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

