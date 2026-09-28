"""Collector: batching, spool durability, retry/backoff, idempotency, heartbeat."""
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.collector.cli import read_new_lines
from app.collector.client import (
    CollectorClient,
    CollectorConfig,
    chunk_events,
)
from app.collector.spool import DiskSpool, SpoolFull
from app.collector.transport import TransportError, TransportResponse


class FakeTransport:
    """Deterministic transport that records requests and replays scripted responses."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def send(self, method, url, *, headers, body=None, timeout=15.0):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        if not self.responses:
            return TransportResponse(status=200, headers={}, body=b'{"replayed": false}')
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(**payload):
    body = json.dumps({"replayed": False, **payload}).encode("utf-8")
    return TransportResponse(status=200, headers={"date": "Wed, 09 Sep 2026 10:00:00 GMT"}, body=body)


def _client(tmp_path: Path, transport: FakeTransport, **overrides) -> tuple[CollectorClient, list[float]]:
    sleeps: list[float] = []
    config = CollectorConfig(
        sensor_id="sensor-a",
        endpoint="https://evonids.test/api/v1",
        token="sensor-token",
        spool_root=tmp_path,
        **overrides,
    )
    client = CollectorClient(
        config,
        transport,
        clock=lambda: 1_000_000.0,
        monotonic=lambda: 5.0,
        sleeper=sleeps.append,
        random_source=lambda: 0.0,
    )
    return client, sleeps


def test_chunk_events_bounds_count_and_bytes():
    lines = [f"line-{index}" for index in range(7)]
    assert [len(batch) for batch in chunk_events(lines, max_events=3, max_bytes=10_000)] == [3, 3, 1]
    small = chunk_events(["a" * 10, "b" * 10, "c" * 10], max_events=100, max_bytes=12)
    assert [len(batch) for batch in small] == [1, 1, 1]


def test_submit_delivers_batches_and_empties_the_spool(tmp_path):
    transport = FakeTransport([_ok(acceptedEvents=2)])
    client, _ = _client(tmp_path, transport)
    results = client.submit(['{"a":1}', '{"a":2}'])
    assert [result.status for result in results] == ["delivered"]
    assert results[0].accepted_events == 2
    assert client.spool.depth() == 0
    assert transport.calls[0]["headers"]["X-Evonids-Batch-Id"].startswith("sensor-a-")
    assert transport.calls[0]["headers"]["X-Evonids-Encoding"] == "gzip"
    assert gzip.decompress(transport.calls[0]["body"]).decode("utf-8") == '{"a":1}\n{"a":2}\n'
    assert client.metrics.batches_delivered == 1


def test_retry_uses_the_same_batch_id_and_exponential_backoff(tmp_path):
    transport = FakeTransport([TransportError("boom"), _ok()])
    client, sleeps = _client(tmp_path, transport)
    results = client.submit(['{"a":1}'])
    assert results[0].status == "delivered"
    assert results[0].attempts == 2
    assert len(transport.calls) == 2
    assert (
        transport.calls[0]["headers"]["X-Evonids-Batch-Id"]
        == transport.calls[1]["headers"]["X-Evonids-Batch-Id"]
    )
    assert sleeps == [0.5]
    assert client.metrics.retries == 1


def test_exhausted_retries_keep_the_batch_spooled(tmp_path):
    transport = FakeTransport([TransportError("boom")] * 3)
    client, _ = _client(tmp_path, transport, max_attempts=3)
    results = client.submit(['{"a":1}'])
    assert results[0].status == "spooled"
    assert client.spool.depth() == 1
    assert client.metrics.batches_spooled == 1
    pending = client.spool.pending()[0]
    assert pending.event_count == 1


def test_flush_spool_retries_pending_segments_in_order(tmp_path):
    spool = DiskSpool(tmp_path)
    spool.append('{"a":1}\n', event_count=1, batch_id="first")
    spool.append('{"a":2}\n', event_count=1, batch_id="second")
    transport = FakeTransport([_ok(), _ok()])
    client, _ = _client(tmp_path, transport)
    results = client.flush_spool()
    assert [result.batch_id for result in results] == ["first", "second"]
    assert client.spool.depth() == 0
    assert client.flush_spool() == []


def test_replayed_batch_is_reported_as_duplicate_not_failure(tmp_path):
    body = json.dumps({"replayed": True, "acceptedEvents": 3, "duplicateEvents": 3}).encode()
    transport = FakeTransport([TransportResponse(200, {}, body)])
    client, _ = _client(tmp_path, transport)
    results = client.submit(['{"a":1}'])
    assert results[0].status == "duplicate"
    assert client.metrics.batches_duplicate == 1
    assert client.spool.depth() == 0


def test_batch_id_conflict_is_dead_lettered_and_not_retried(tmp_path):
    body = json.dumps({"error": "conflict", "message": "batch id reused"}).encode()
    transport = FakeTransport([TransportResponse(409, {}, body)])
    client, _ = _client(tmp_path, transport)
    results = client.submit(['{"a":1}'])
    assert results[0].status == "dead_letter"
    assert len(transport.calls) == 1
    assert client.spool.pending() == []
    assert client.spool.dead_letter_count() == 1
    reasons = list((tmp_path / "dead-letter").glob("*.reason.txt"))
    assert reasons and "conflict" in reasons[0].read_text(encoding="utf-8")


def test_non_retryable_status_is_dead_lettered_without_retry(tmp_path):
    transport = FakeTransport([TransportResponse(400, {}, b'{"message":"bad ndjson"}')])
    client, sleeps = _client(tmp_path, transport)
    results = client.submit(['{"a":1}'])
    assert results[0].status == "dead_letter"
    assert len(transport.calls) == 1
    assert sleeps == []
    assert client.spool.dead_letter_count() == 1


def test_retry_after_header_is_honoured(tmp_path):
    transport = FakeTransport([TransportResponse(429, {"retry-after": "7"}, b""), _ok()])
    client, sleeps = _client(tmp_path, transport)
    client.submit(['{"a":1}'])
    assert sleeps == [7.0]


def test_rate_limit_paces_events(tmp_path):
    transport = FakeTransport([_ok(), _ok()])
    client, sleeps = _client(tmp_path, transport, rate_limit_events_per_second=10.0, batch_max_events=5)
    client.submit([f'{{"n":{index}}}' for index in range(10)])
    # 10 events at 10 events/s must pace at least once (monotonic is frozen at 5.0).
    assert sleeps and sleeps[0] == pytest.approx(0.5, abs=0.6)


def test_spool_refuses_to_grow_past_its_cap(tmp_path):
    transport = FakeTransport([_ok()])
    client, _ = _client(tmp_path, transport, spool_max_bytes=8)
    results = client.submit(['{"a":1}', '{"a":2}'])
    assert results[0].status == "spool_full"
    assert transport.calls == []
    assert client.metrics.last_error is not None


def test_spool_is_crash_safe_and_ordered(tmp_path):
    spool = DiskSpool(tmp_path)
    first = spool.append('{"a":1}\n', event_count=1, batch_id="one")
    second = spool.append('{"a":2}\n', event_count=1, batch_id="two")
    assert spool.depth() == 2
    assert [segment.batch_id for segment in spool.pending()] == ["one", "two"]
    assert spool.read(first).startswith('{"a":1}')
    spool.ack(first)
    assert [segment.batch_id for segment in spool.pending()] == ["two"]
    spool.dead_letter_segment(second, reason="test")
    assert spool.pending() == []
    assert spool.dead_letter_count() == 1


def test_spool_full_is_raised_when_the_cap_would_be_exceeded(tmp_path):
    spool = DiskSpool(tmp_path, max_bytes=10)
    spool.append('{"a":1}\n', event_count=1)
    with pytest.raises(SpoolFull):
        spool.append('{"a":2}\n', event_count=1)


def test_heartbeat_reports_spool_depth_and_records_server_skew(tmp_path):
    body = json.dumps({"id": "sensor-a", "state": "online"}).encode()
    transport = FakeTransport([TransportResponse(200, {"date": "Wed, 09 Sep 2026 09:59:00 GMT"}, body)])
    sleeps: list[float] = []
    config = CollectorConfig(
        sensor_id="sensor-a",
        endpoint="https://evonids.test/api/v1",
        token="sensor-token",
        spool_root=tmp_path,
    )
    client = CollectorClient(
        config,
        transport,
        clock=lambda: datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc).timestamp(),
        monotonic=lambda: 5.0,
        sleeper=sleeps.append,
        random_source=lambda: 0.0,
    )
    DiskSpool(tmp_path).append('{"a":1}\n', event_count=1)
    outcome = client.heartbeat()
    assert outcome["delivered"] is True
    request = transport.calls[0]
    assert request["url"].endswith("/sensors/sensor-a/heartbeat")
    payload = json.loads(request["body"].decode("utf-8"))
    assert payload["spoolDepth"] == 1
    assert payload["capabilities"] == ["suricata-eve"]
    assert client.metrics.last_clock_skew_seconds == pytest.approx(60.0, abs=0.001)


def test_heartbeat_failure_is_counted_and_reported(tmp_path):
    transport = FakeTransport([TransportError("no route")])
    client, _ = _client(tmp_path, transport)
    outcome = client.heartbeat()
    assert outcome["delivered"] is False
    assert client.metrics.heartbeat_failures == 1


def test_read_new_lines_waits_for_complete_lines_and_resets_on_truncation(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text('{"a":1}\n{"a":2}\n{"partial"', encoding="utf-8", newline="")
    lines, offset, inode = read_new_lines(eve, 0, 0, max_lines=100)
    assert lines == ['{"a":1}', '{"a":2}']
    assert offset == len('{"a":1}\n{"a":2}\n')

    with eve.open("a", encoding="utf-8", newline="") as handle:
        handle.write(':3}\n')
    lines, offset, inode = read_new_lines(eve, offset, inode, max_lines=100)
    assert lines == ['{"partial":3}']

    eve.write_text('{"b":1}\n', encoding="utf-8", newline="")
    lines, _, _ = read_new_lines(eve, offset, inode, max_lines=100)
    assert lines == ['{"b":1}']


def test_read_new_lines_tolerates_a_byte_order_mark(tmp_path):
    eve = tmp_path / "eve-bom.json"
    eve.write_bytes(b"\xef\xbb\xbf" + b'{"a":1}\n{"a":2}\n')
    lines, offset, _ = read_new_lines(eve, 0, 0, max_lines=10)
    assert lines == ['{"a":1}', '{"a":2}']
    assert offset > 0


def test_metrics_snapshot_is_json_serialisable(tmp_path):
    transport = FakeTransport([_ok()])
    client, _ = _client(tmp_path, transport)
    client.submit(['{"a":1}'])
    snapshot = client.metrics.as_dict()
    json.dumps(snapshot)
    assert snapshot["eventsSubmitted"] == 1
    assert snapshot["batchesDelivered"] == 1
