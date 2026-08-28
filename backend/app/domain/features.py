from dataclasses import dataclass
from typing import Any, Literal


FeatureKind = Literal["string", "integer", "number", "timestamp"]


@dataclass(frozen=True, slots=True)
class FeatureDefinition:
    name: str
    kind: FeatureKind
    unit: str
    source: str
    window_seconds: int | None = None
    minimum: float | None = None
    maximum: float | None = None


FEATURE_VERSION = "flow-v1"

FEATURES = {
    item.name: item
    for item in [
        FeatureDefinition("flow_id", "string", "id", "internal"),
        FeatureDefinition("timestamp", "timestamp", "iso8601", "sensor"),
        FeatureDefinition("src_ip", "string", "ip", "packet"),
        FeatureDefinition("src_port", "integer", "port", "packet", minimum=0, maximum=65535),
        FeatureDefinition("dst_ip", "string", "ip", "packet"),
        FeatureDefinition("dst_port", "integer", "port", "packet", minimum=0, maximum=65535),
        FeatureDefinition("protocol", "string", "name", "packet"),
        FeatureDefinition("service", "string", "name", "suricata"),
        FeatureDefinition("flow_duration", "number", "seconds", "flow", minimum=0),
        FeatureDefinition("forward_packet_count", "integer", "packets", "flow", minimum=0),
        FeatureDefinition("backward_packet_count", "integer", "packets", "flow", minimum=0),
        FeatureDefinition("forward_bytes", "integer", "bytes", "flow", minimum=0),
        FeatureDefinition("backward_bytes", "integer", "bytes", "flow", minimum=0),
        FeatureDefinition("packets_per_second", "number", "packets/second", "flow", minimum=0),
        FeatureDefinition("bytes_per_second", "number", "bytes/second", "flow", minimum=0),
        FeatureDefinition("syn_ratio", "number", "ratio", "flow", minimum=0, maximum=1),
        FeatureDefinition("ack_ratio", "number", "ratio", "flow", minimum=0, maximum=1),
        FeatureDefinition("rst_ratio", "number", "ratio", "flow", minimum=0, maximum=1),
        FeatureDefinition("destination_port_count_60s", "integer", "ports", "window", 60, 0),
        FeatureDefinition("destination_ip_count_60s", "integer", "addresses", "window", 60, 0),
        FeatureDefinition("flow_count_60s", "integer", "flows", "window", 60, 0),
        FeatureDefinition("average_packet_size", "number", "bytes", "flow", minimum=0),
    ]
}


def validate_feature_record(record: dict[str, Any], *, require_all: bool = False) -> list[str]:
    errors: list[str] = []
    if require_all:
        errors.extend(f"missing feature: {name}" for name in FEATURES if name not in record)

    for name, value in record.items():
        definition = FEATURES.get(name)
        if definition is None:
            errors.append(f"unknown feature: {name}")
            continue
        if value is None:
            errors.append(f"{name} cannot be null")
            continue
        if definition.kind == "string" and not isinstance(value, str):
            errors.append(f"{name} must be a string")
        elif definition.kind == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
            errors.append(f"{name} must be an integer")
        elif definition.kind == "number" and (not isinstance(value, (int, float)) or isinstance(value, bool)):
            errors.append(f"{name} must be numeric")
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            if definition.minimum is not None and value < definition.minimum:
                errors.append(f"{name} is below {definition.minimum}")
            if definition.maximum is not None and value > definition.maximum:
                errors.append(f"{name} is above {definition.maximum}")
    return errors

