"""Canonical online flow-feature contract shared by ingestion, inference and training.

The contract exists to remove train/serve skew: the offline projection used for
training on the online contract and the online builder used during inference call
the same formulas in this module. Nothing here touches the database, the model
registry or the network, so it can be unit tested in isolation.

Two feature layers are deliberately separated:

``ONLINE_MODEL_FEATURES``
    Per-flow values that a Suricata EVE ``flow`` event can always produce (and
    that a CICIDS2017 flow row can be projected onto with identical formulas).
    Only these may be used as model input.

``ONLINE_CONTEXT_FEATURES``
    Sliding-window counters that require neighbouring flows. They are recorded
    with the vector for correlation, rule context and analyst display, but they
    are NOT model input, because the offline datasets used for training do not
    carry comparable windows. Feeding them to a model trained without them would
    be exactly the skew this module exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Mapping

ONLINE_FEATURE_VERSION = "flow-online-v1"
WINDOW_SECONDS = 60

FeatureKind = Literal["integer", "number"]
FeatureSource = Literal["eve_flow", "derived", "window"]

# Suricata/IANA protocol numbers used for the numeric protocol feature.
PROTOCOL_NUMBERS = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "icmpv6": 58,
    "ipv6-icmp": 58,
    "gre": 47,
    "esp": 50,
    "ah": 51,
}


@dataclass(frozen=True, slots=True)
class OnlineFeatureSpec:
    name: str
    kind: FeatureKind
    unit: str
    source: FeatureSource
    description: str
    layer: Literal["model", "context"] = "model"


_ONLINE_FEATURES: tuple[OnlineFeatureSpec, ...] = (
    OnlineFeatureSpec("source_port", "integer", "port", "eve_flow", "EVE src_port"),
    OnlineFeatureSpec("destination_port", "integer", "port", "eve_flow", "EVE dest_port"),
    OnlineFeatureSpec(
        "protocol_number",
        "integer",
        "number",
        "derived",
        "IANA protocol number derived from EVE proto",
    ),
    OnlineFeatureSpec("flow_duration_seconds", "number", "seconds", "eve_flow", "EVE flow.age"),
    OnlineFeatureSpec("forward_packet_count", "integer", "packets", "eve_flow", "EVE flow.pkts_toserver"),
    OnlineFeatureSpec("backward_packet_count", "integer", "packets", "eve_flow", "EVE flow.pkts_toclient"),
    OnlineFeatureSpec("forward_bytes", "integer", "bytes", "eve_flow", "EVE flow.bytes_toserver"),
    OnlineFeatureSpec("backward_bytes", "integer", "bytes", "eve_flow", "EVE flow.bytes_toclient"),
    OnlineFeatureSpec("packets_per_second", "number", "packets/second", "derived", "total packets / duration"),
    OnlineFeatureSpec("bytes_per_second", "number", "bytes/second", "derived", "total bytes / duration"),
    OnlineFeatureSpec(
        "average_packet_size",
        "number",
        "bytes",
        "derived",
        "total bytes / total packets",
    ),
    OnlineFeatureSpec(
        "forward_mean_packet_size",
        "number",
        "bytes",
        "derived",
        "forward bytes / forward packets",
    ),
    OnlineFeatureSpec(
        "backward_mean_packet_size",
        "number",
        "bytes",
        "derived",
        "backward bytes / backward packets",
    ),
    OnlineFeatureSpec(
        "packet_size_asymmetry",
        "number",
        "ratio",
        "derived",
        "|fwd mean - bwd mean| / max(fwd mean, bwd mean)",
    ),
    OnlineFeatureSpec("byte_ratio", "number", "ratio", "derived", "forward bytes / total bytes"),
    OnlineFeatureSpec("packet_ratio", "number", "ratio", "derived", "forward packets / total packets"),
    OnlineFeatureSpec(
        "destination_port_count_60s",
        "integer",
        "ports",
        "window",
        "distinct destination ports from the same source inside the window",
        layer="context",
    ),
    OnlineFeatureSpec(
        "destination_ip_count_60s",
        "integer",
        "addresses",
        "window",
        "distinct destination addresses from the same source inside the window",
        layer="context",
    ),
    OnlineFeatureSpec(
        "flow_count_60s",
        "integer",
        "flows",
        "window",
        "flows from the same source inside the window",
        layer="context",
    ),
    OnlineFeatureSpec(
        "source_port_count_60s",
        "integer",
        "ports",
        "window",
        "distinct source ports used by the same source inside the window",
        layer="context",
    ),
    OnlineFeatureSpec(
        "destination_port_ratio_60s",
        "number",
        "ratio",
        "derived",
        "distinct destination ports / flows in the window",
        layer="context",
    ),
)

ONLINE_FEATURES: dict[str, OnlineFeatureSpec] = {item.name: item for item in _ONLINE_FEATURES}
ONLINE_FEATURE_NAMES: tuple[str, ...] = tuple(item.name for item in _ONLINE_FEATURES)
ONLINE_MODEL_FEATURES: tuple[str, ...] = tuple(
    item.name for item in _ONLINE_FEATURES if item.layer == "model"
)
ONLINE_CONTEXT_FEATURES: tuple[str, ...] = tuple(
    item.name for item in _ONLINE_FEATURES if item.layer == "context"
)


@dataclass(frozen=True, slots=True)
class WindowCounts:
    """Sliding-window counters supplied by the caller (computed from stored flows)."""

    destination_port_count: int = 0
    destination_ip_count: int = 0
    flow_count: int = 0
    source_port_count: int = 0


@dataclass(frozen=True, slots=True)
class OnlineFeatureVector:
    flow_id: str
    sensor_id: str
    observed_at: datetime
    values: dict[str, float | int]
    missing_fields: tuple[str, ...]
    feature_version: str = ONLINE_FEATURE_VERSION
    window_seconds: int = WINDOW_SECONDS

    @property
    def model_values(self) -> dict[str, float | int]:
        return {name: self.values[name] for name in ONLINE_MODEL_FEATURES if name in self.values}

    @property
    def context_values(self) -> dict[str, float | int]:
        return {name: self.values[name] for name in ONLINE_CONTEXT_FEATURES if name in self.values}

    @property
    def data_missing(self) -> str:
        return "none" if not self.missing_fields else "partial"

    def as_record(self) -> dict[str, Any]:
        """JSON-serialisable record persisted on the flow row."""
        return {
            "featureVersion": self.feature_version,
            "windowSeconds": self.window_seconds,
            "modelFeatures": dict(self.model_values),
            "contextFeatures": dict(self.context_values),
            "missingFields": list(self.missing_fields),
        }


def build_online_features(
    flow: Mapping[str, Any],
    *,
    sensor_id: str,
    observed_at: datetime,
    window: WindowCounts | None = None,
    missing_fields: tuple[str, ...] = (),
) -> OnlineFeatureVector:
    """Build the online contract from a Suricata EVE flow payload.

    ``flow`` accepts the exact mapping produced by :func:`app.ingestion.eve.flow_payload`.
    Absent numeric fields degrade to 0 and are reported in ``missing_fields`` so the
    caller can persist an explicit data-completeness marker instead of silently
    pretending the value was observed.
    """
    counts = window or WindowCounts()
    missing = list(missing_fields)

    duration = _non_negative_float(flow.get("flow_duration"))
    forward_packets = _non_negative_int(flow.get("forward_packet_count"))
    backward_packets = _non_negative_int(flow.get("backward_packet_count"))
    forward_bytes = _non_negative_int(flow.get("forward_bytes"))
    backward_bytes = _non_negative_int(flow.get("backward_bytes"))
    if "flow_duration" not in flow:
        missing.append("flow_duration")
    if "forward_packet_count" not in flow:
        missing.append("forward_packet_count")
    if "backward_packet_count" not in flow:
        missing.append("backward_packet_count")
    if "forward_bytes" not in flow:
        missing.append("forward_bytes")
    if "backward_bytes" not in flow:
        missing.append("backward_bytes")

    total_packets = forward_packets + backward_packets
    total_bytes = forward_bytes + backward_bytes
    forward_mean = forward_bytes / forward_packets if forward_packets > 0 else 0.0
    backward_mean = backward_bytes / backward_packets if backward_packets > 0 else 0.0

    values: dict[str, float | int] = {
        "source_port": _non_negative_int(flow.get("src_port")),
        "destination_port": _non_negative_int(flow.get("dst_port")),
        "protocol_number": protocol_number(flow.get("protocol")),
        "flow_duration_seconds": round(duration, 6),
        "forward_packet_count": forward_packets,
        "backward_packet_count": backward_packets,
        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,
        "packets_per_second": _ratio(total_packets, duration),
        "bytes_per_second": _ratio(total_bytes, duration),
        "average_packet_size": _ratio(total_bytes, total_packets),
        "forward_mean_packet_size": round(forward_mean, 6),
        "backward_mean_packet_size": round(backward_mean, 6),
        "packet_size_asymmetry": _asymmetry(forward_mean, backward_mean),
        "byte_ratio": _ratio(forward_bytes, total_bytes),
        "packet_ratio": _ratio(forward_packets, total_packets),
        "destination_port_count_60s": max(counts.destination_port_count, 0),
        "destination_ip_count_60s": max(counts.destination_ip_count, 0),
        "flow_count_60s": max(counts.flow_count, 0),
        "source_port_count_60s": max(counts.source_port_count, 0),
        "destination_port_ratio_60s": _ratio(counts.destination_port_count, counts.flow_count),
    }
    return OnlineFeatureVector(
        flow_id=str(flow.get("external_id", "")),
        sensor_id=sensor_id,
        observed_at=observed_at,
        values=values,
        missing_fields=tuple(dict.fromkeys(missing)),
    )


def project_cicids_row(row: Mapping[str, Any]) -> dict[str, float | int]:
    """Project a CICIDS2017 PCAP-derived row onto the online model contract.

    Used by offline training so the fitted model sees exactly the features the
    online builder produces. Only ``ONLINE_MODEL_FEATURES`` are returned; window
    context is intentionally excluded (see the module docstring).
    """
    duration_us = _value(row, "duration_us")
    forward_packets = _value(row, "total_fwd_packets")
    backward_packets = _value(row, "total_bwd_packets")
    forward_bytes = _value(row, "total_fwd_bytes")
    backward_bytes = _value(row, "total_bwd_bytes")
    duration_seconds = duration_us / 1_000_000 if duration_us > 0 else 0.0
    total_packets = forward_packets + backward_packets
    total_bytes = forward_bytes + backward_bytes
    forward_mean = forward_bytes / forward_packets if forward_packets > 0 else 0.0
    backward_mean = backward_bytes / backward_packets if backward_packets > 0 else 0.0
    protocol = _value(row, "protocol")
    return {
        "source_port": int(_value(row, "source_port")),
        "destination_port": int(_value(row, "destination_port")),
        "protocol_number": int(protocol),
        "flow_duration_seconds": round(duration_seconds, 6),
        "forward_packet_count": int(forward_packets),
        "backward_packet_count": int(backward_packets),
        "forward_bytes": int(forward_bytes),
        "backward_bytes": int(backward_bytes),
        "packets_per_second": _ratio(total_packets, duration_seconds),
        "bytes_per_second": _ratio(total_bytes, duration_seconds),
        "average_packet_size": _ratio(total_bytes, total_packets),
        "forward_mean_packet_size": round(forward_mean, 6),
        "backward_mean_packet_size": round(backward_mean, 6),
        "packet_size_asymmetry": _asymmetry(forward_mean, backward_mean),
        "byte_ratio": _ratio(forward_bytes, total_bytes),
        "packet_ratio": _ratio(forward_packets, total_packets),
    }


def protocol_number(protocol: Any) -> int:
    if isinstance(protocol, bool) or protocol is None:
        return 0
    if isinstance(protocol, (int, float)):
        return int(protocol)
    return PROTOCOL_NUMBERS.get(str(protocol).strip().lower(), 0)


def _value(row: Mapping[str, Any], name: str) -> float:
    try:
        value = float(row.get(name, 0) or 0)
    except (TypeError, ValueError):
        return 0.0
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return value


def _non_negative_int(value: Any) -> int:
    try:
        numeric = int(float(value))
    except (TypeError, ValueError):
        return 0
    return max(numeric, 0)


def _non_negative_float(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0.0
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        return 0.0
    return max(numeric, 0.0)


def _ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) / float(denominator), 6)


def _asymmetry(forward_mean: float, backward_mean: float) -> float:
    largest = max(forward_mean, backward_mean)
    if largest <= 0:
        return 0.0
    return round(abs(forward_mean - backward_mean) / largest, 6)
