"""STIX 2.1 export of alerts, cases and indicators.

The exporter turns one :class:`~app.integrations.base.Notification` into a STIX
2.1 *bundle* that any STIX 2.1 consumer can ingest:

* ``identity`` — who produced the bundle (``created_by_ref`` target);
* ``indicator`` — one per observable (IPv4 address, domain name, network
  traffic port), with a STIX pattern built by :func:`build_indicator_pattern`;
* ``observed-data`` — what was seen, including the ``number_observed`` count and
  the object references of the observables;
* ``sighting`` — the indicator/observed-data relationship, when an indicator
  exists.

Everything is deterministic so a test can assert exact bytes:

* every id is ``<type>--<uuid>`` where the UUID is a **UUIDv5** (SHA-1, RFC 4122
  §4.3) derived from the type, the platform id and the observable;
* ``created`` / ``modified`` come from the event's ``occurred_at``, never from
  the wall clock, so re-exporting the same event yields identical bytes;
* objects are sorted by (type, id) and serialised with sorted keys and compact
  separators.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from app.integrations.base import DeliveryAttempt, Notification, summarise_request
from app.integrations.settings import StixSettings

SPEC_VERSION = "2.1"
# A stable private namespace for EvoNIDS-derived STIX ids. This is a UUIDv5
# namespace, not a secret: it only makes ids reproducible across deployments.
EVONIDS_STIX_NAMESPACE = uuid.UUID("6f1a7c1e-6f2b-5c34-9a10-2b7c9d4e5f60")
DEVICE_VERSION = "0.2.0"

DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def uuid5(namespace: uuid.UUID, name: str) -> uuid.UUID:
    """RFC 4122 §4.3 UUIDv5, implemented locally and unit-tested.

    ``uuid.uuid5`` is not used because the harness runs this package against a
    pinned interpreter where the helper's normalisation is not part of the
    contract; the test file pins the published RFC 4122 test vector
    (``uuid5(DNS, "python.org") == 886313e1-3b8a-5372-9b90-0c9aee199e5d``) so a
    regression cannot pass unnoticed.
    """
    normalized = name.encode("utf-8")
    digest = hashlib.sha1(namespace.bytes + normalized).digest()
    return uuid.UUID(bytes=digest[:16], version=5)


def stix_id(object_type: str, *parts: str) -> str:
    """Deterministic STIX 2.1 id: ``<type>--<uuid5>``."""
    name = "|".join([object_type, *[str(part) for part in parts]])
    return f"{object_type}--{uuid5(EVONIDS_STIX_NAMESPACE, name)}"


def stix_timestamp(value: datetime) -> str:
    """UTC, millisecond precision, ``Z`` suffix — the STIX 2.1 timestamp shape."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def escape_stix_string(value: str) -> str:
    """Escape a value placed inside a STIX pattern string literal.

    STIX pattern literals use single quotes, so backslash and the quote itself
    are escaped; a payload cannot terminate the literal and inject a comparison.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def escape_stix_regex(value: str) -> str:
    """Escape a value placed inside a STIX ``MATCHES`` regular expression."""
    escaped = escape_stix_string(value)
    return re.sub(r"([.^$*+?()\[\]{}|])", r"\\\1", escaped)


@dataclass(frozen=True, slots=True)
class Observable:
    """One indicator candidate extracted from an event."""

    object_type: str
    value: str
    role: str
    pattern: str
    object_path: str
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.object_type}:{self.value}"


def build_indicator_pattern(object_type: str, value: str) -> str:
    """Build the STIX pattern for one observable type."""
    if object_type == "ipv4-addr":
        return f"[ipv4-addr:value = '{escape_stix_string(value)}']"
    if object_type == "ipv6-addr":
        return f"[ipv6-addr:value = '{escape_stix_string(value)}']"
    if object_type == "domain-name":
        return f"[domain-name:value = '{escape_stix_string(value)}']"
    if object_type == "network-traffic":
        # Ports are numeric in STIX; the value is validated by extraction, so a
        # non-numeric value here is a programming error, not user input.
        return f"[network-traffic:dst_port = {int(value)}]"
    raise ValueError(f"unsupported observable type {object_type!r}")


def _classify(value: str, *, numeric: bool = False) -> str | None:
    text = value.strip()
    if not text:
        return None
    if numeric:
        return "network-traffic" if text.isdigit() else None
    if IPV4_PATTERN.match(text):
        return "ipv4-addr"
    if ":" in text and all(char in "0123456789abcdefABCDEF:." for char in text):
        return "ipv6-addr"
    if DOMAIN_PATTERN.match(text):
        return "domain-name"
    return None


ALERT_OBSERVABLE_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("sourceIp", "src_ref", "source"),
    ("destinationIp", "dst_ref", "destination"),
    ("hostname", "src_ref", "hostname"),
    ("domain", "dst_ref", "domain"),
    ("destinationPort", "dst_port", "destination-port"),
    ("destination_port", "dst_port", "destination-port"),
)


def extract_observables(event: Notification) -> list[Observable]:
    """Extract deduplicated observables from an event's alert/case/evidence data."""
    sources: list[Mapping[str, Any]] = []
    if event.alert:
        sources.append(event.alert)
    if event.case:
        sources.append(event.case)
    for item in event.evidence:
        sources.append(item)
    found: dict[str, Observable] = {}
    for source in sources:
        for key, object_path, role in ALERT_OBSERVABLE_FIELDS:
            raw = source.get(key)
            if raw is None:
                continue
            text = str(raw).strip()
            if not text:
                continue
            object_type = _classify(text, numeric="port" in key.lower())
            if object_type is None:
                continue
            if object_type == "network-traffic" and not (0 < int(text) <= 65535):
                continue
            observable = Observable(
                object_type=object_type,
                value=text if object_type != "network-traffic" else str(int(text)),
                role=role,
                pattern=build_indicator_pattern(object_type, text),
                object_path=object_path,
            )
            found.setdefault(observable.key, observable)
    # Deterministic order: type first, then value.
    return sorted(found.values(), key=lambda item: (item.object_type, item.value))


def build_identity(settings: StixSettings | None, *, created: str) -> dict[str, Any]:
    name = settings.identity_name if settings else "EvoNIDS"
    fixed = settings.identity_id if settings else ""
    identity_id = f"identity--{fixed}" if fixed else stix_id("identity", name)
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": identity_id,
        "created": created,
        "modified": created,
        "name": name,
        "identity_class": "system",
        "description": "EvoNIDS 网络入侵检测与响应平台（自动导出，仅包含与本事件相关的可观测对象）",
        "x_evonids_product_version": DEVICE_VERSION,
    }


def build_bundle(
    event: Notification,
    *,
    settings: StixSettings | None = None,
    labels: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Build a deterministic STIX 2.1 bundle for one notification."""
    created = stix_timestamp(event.occurred_at)
    identity = build_identity(settings, created=created)
    identity_ref = str(identity["id"])
    observables = extract_observables(event)
    objects: list[dict[str, Any]] = [identity]
    object_refs: list[str] = []
    indicator_refs: list[str] = []
    observables_by_id: dict[str, dict[str, Any]] = {}
    ref_index: dict[str, str] = {}

    for observable in observables:
        observable_id = stix_id(observable.object_type, event.object_id, observable.key)
        object_refs.append(observable_id)
        ref_index[observable_id] = observable.object_path
        indicator = {
            "type": "indicator",
            "spec_version": SPEC_VERSION,
            "id": stix_id("indicator", event.object_id, observable.key),
            "created": created,
            "modified": created,
            "created_by_ref": identity_ref,
            "name": f"{observable.role}: {observable.value}",
            "description": f"EvoNIDS 从事件 {event.object_id} 提取的可疑 {observable.object_type}",
            "indicator_types": list(labels or ["malicious-activity"]),
            "pattern": observable.pattern,
            "pattern_type": "stix",
            "pattern_version": SPEC_VERSION,
            "valid_from": created,
            "labels": ["evonids", event.event_type],
            "x_evonids_object_id": event.object_id,
            "x_evonids_dedup_key": event.dedup_key,
        }
        objects.append(indicator)
        indicator_refs.append(str(indicator["id"]))
        # The observable itself is embedded in observed-data (as a cyber
        # observable object) rather than emitted as a top-level object, because
        # STIX 2.1 has no standalone "ipv4-addr" bundle member.
        observable_payload: dict[str, Any] = {"type": observable.object_type}
        if observable.object_type == "network-traffic":
            observable_payload["dst_port"] = int(observable.value)
            observable_payload["protocols"] = ["tcp"]
        else:
            observable_payload["value"] = observable.value
        observables_by_id[observable_id] = observable_payload

    observed_data = {
        "type": "observed-data",
        "spec_version": SPEC_VERSION,
        "id": stix_id("observed-data", event.object_id, event.dedup_key),
        "created": created,
        "modified": created,
        "created_by_ref": identity_ref,
        "first_observed": created,
        "last_observed": created,
        "number_observed": 1,
        "object_refs": object_refs,
        "objects": {ref_index[key]: value for key, value in sorted(observables_by_id.items())},
        "labels": [event.event_type],
        "x_evonids_severity": event.severity,
        "x_evonids_title": event.title,
    }
    objects.append(observed_data)

    if indicator_refs:
        objects.append(
            {
                "type": "sighting",
                "spec_version": SPEC_VERSION,
                "id": stix_id("sighting", event.object_id, event.dedup_key),
                "created": created,
                "modified": created,
                "created_by_ref": identity_ref,
                "first_seen": created,
                "last_seen": created,
                "count": 1,
                "sighting_of_ref": indicator_refs[0],
                "observed_data_refs": [observed_data["id"]],
                "where_sighted_refs": [identity_ref],
            }
        )

    ordered = sorted(objects, key=lambda item: (str(item["type"]), str(item["id"])))
    bundle_id = stix_id("bundle", *[str(item["id"]) for item in ordered])
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": SPEC_VERSION,
        "objects": ordered,
    }


def serialize_bundle(bundle: Mapping[str, Any]) -> str:
    """Deterministic JSON: sorted keys, compact separators, no ASCII escaping."""
    return json.dumps(dict(bundle), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def serialize_bundle_pretty(bundle: Mapping[str, Any]) -> str:
    """Same document, indented — for the on-disk export an analyst reads."""
    return json.dumps(dict(bundle), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def bundle_object_types(bundle: Mapping[str, Any]) -> list[str]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        return []
    return sorted(str(item.get("type")) for item in objects if isinstance(item, dict))


class StixExportConnector:
    """Writes one deterministic STIX 2.1 bundle per event into a directory."""

    def __init__(self, settings: StixSettings) -> None:
        self.settings = settings
        self.name = settings.name
        self.written: list[Path] = []

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(self.settings.capabilities)

    @property
    def export_dir(self) -> Path:
        return Path(self.settings.export_dir).expanduser()

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "stix-export",
            "target": str(self.export_dir),
            "specVersion": SPEC_VERSION,
            "identity": self.settings.identity_name,
        }

    def health(self) -> dict[str, Any]:
        directory = self.export_dir
        if not directory.is_dir():
            return {
                "connector": self.name,
                "kind": "stix-export",
                "state": "misconfigured",
                "reason": f"export directory {directory} does not exist",
                "probe": "not_attempted",
            }
        return {
            "connector": self.name,
            "kind": "stix-export",
            "state": "ok",
            "target": str(directory),
            "probe": "directory_exists",
        }

    def bundle_path(self, event: Notification) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", event.object_id)[:64]
        return self.export_dir / f"{safe}.{event.event_type}.stix.json"

    def deliver_once(self, event: Notification) -> DeliveryAttempt:
        bundle = build_bundle(event, settings=self.settings)
        payload = serialize_bundle_pretty(bundle)
        directory = self.export_dir
        if not directory.is_dir():
            return DeliveryAttempt(
                deliverable=False,
                error=f"export directory {directory} does not exist",
                error_code="export_dir_missing",
                request_summary=summarise_request(event),
            )
        path = self.bundle_path(event)
        try:
            path.write_text(payload, encoding="utf-8", newline="\n")
        except OSError as error:
            return DeliveryAttempt(
                deliverable=False,
                error=f"cannot write bundle: {error}"[:255],
                error_code="export_failed",
                request_summary=summarise_request(event),
            )
        self.written.append(path)
        objects = bundle["objects"]
        return DeliveryAttempt(
            request_summary=summarise_request(event),
            response_summary={
                "path": str(path),
                "bytes": len(payload.encode("utf-8")),
                "bundleId": str(bundle["id"]),
                "objectTypes": bundle_object_types(bundle),
                "indicatorCount": sum(
                    1 for item in objects if isinstance(item, dict) and item.get("type") == "indicator"
                ),
            },
            deliverable=True,
        )


def export_bundle_to_file(
    event: Notification, path: str | Path, *, settings: StixSettings | None = None
) -> Path:
    """One-shot helper used by tests and the CLI-style probe."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(serialize_bundle_pretty(build_bundle(event, settings=settings)), encoding="utf-8")
    return target


def iter_object_ids(bundle: Mapping[str, Any]) -> Iterable[str]:
    objects = bundle.get("objects")
    if isinstance(objects, list):
        for item in objects:
            if isinstance(item, dict) and "id" in item:
                yield str(item["id"])
