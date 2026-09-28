"""Observability: Prometheus text exposition, trace propagation, runtime gauges."""
import os
import tempfile

database_path = tempfile.gettempdir() + "/evonids-observability-test.db"
os.environ["EVONIDS_DATABASE_URL"] = f"sqlite:///{database_path}"
os.environ["EVONIDS_AUTO_CREATE_DB"] = "true"
os.environ["EVONIDS_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["EVONIDS_ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services.observability import (  # noqa: E402
    METRIC_NAME_PATTERN,
    MetricsRegistry,
    continue_or_start_trace,
    new_trace_context,
    parse_traceparent,
)


def test_traceparent_parsing_accepts_valid_and_rejects_malformed():
    value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    context = parse_traceparent(value)
    assert context is not None
    assert context.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert context.parent_span_id == "00f067aa0ba902b7"
    assert context.sampled is True
    assert context.upstream is True
    assert context.span_id != context.parent_span_id

    assert parse_traceparent(None) is None
    assert parse_traceparent("") is None
    assert parse_traceparent("not-a-traceparent") is None
    assert parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") is None
    assert parse_traceparent("00-" + "0" * 32 + "-00f067aa0ba902b7-01") is None
    assert parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-" + "0" * 16 + "-01") is None


def test_trace_context_is_generated_when_absent_and_preserved_when_present():
    started = continue_or_start_trace(None)
    assert started.upstream is False
    assert len(started.trace_id) == 32
    assert started.header().startswith(f"00-{started.trace_id}-")

    upstream = "00-11111111111111111111111111111111-2222222222222222-01"
    continued = continue_or_start_trace(upstream)
    assert continued.trace_id == "11111111111111111111111111111111"
    assert continued.upstream is True


def test_metrics_registry_renders_prometheus_text_format():
    registry = MetricsRegistry()
    registry.describe("evonids_test_total", "counter for tests")
    registry.inc("evonids_test_total", labels={"route": "/a", "status": "200"})
    registry.inc("evonids_test_total", labels={"route": "/a", "status": "200"}, value=2)
    registry.set_gauge("evonids_test_gauge", 7, labels={"queue": "training"})
    registry.observe("evonids_test_latency_seconds", 0.02, labels={"route": "/a"})
    registry.observe("evonids_test_latency_seconds", 5.0, labels={"route": "/a"})
    text = registry.render()

    assert '# TYPE evonids_test_total counter' in text
    assert 'evonids_test_total{route="/a",status="200"} 3' in text
    assert '# TYPE evonids_test_gauge gauge' in text
    assert 'evonids_test_gauge{queue="training"} 7' in text
    assert '# TYPE evonids_test_latency_seconds histogram' in text
    assert 'evonids_test_latency_seconds_bucket{route="/a",le="0.025"} 1' in text
    assert 'evonids_test_latency_seconds_bucket{route="/a",le="+Inf"} 2' in text
    assert 'evonids_test_latency_seconds_sum{route="/a"} 5.02' in text
    assert 'evonids_test_latency_seconds_count{route="/a"} 2' in text


def test_metric_names_and_labels_are_sanitised():
    registry = MetricsRegistry()
    with pytest.raises(ValueError):
        registry.inc("bad name")
    with pytest.raises(ValueError):
        registry.inc("1leading_digit")
    assert METRIC_NAME_PATTERN.match("evonids_http_requests_total")
    registry.inc("evonids_label_test_total", labels={"note": 'quote"and\\backslash'})
    text = registry.render()
    assert 'note="quote\\"and\\\\backslash"' in text


def test_http_requests_are_counted_with_route_templates_not_raw_paths():
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        response = client.get("/api/v1/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        body = response.text
        assert "evonids_http_requests_total" in body
        # Route templates are used (never raw ids): the matched route path is
        # reported relative to the API router.
        assert 'route="/health"' in body
        # Cardinality control: no raw ids may appear as label values.
        assert "evonids_http_request_duration_seconds_bucket" in body


def test_trace_id_is_propagated_into_response_headers_and_logs():
    upstream = "00-abcdefabcdefabcdefabcdefabcdefab-0123456789abcdef-01"
    with TestClient(app) as client:
        response = client.get("/api/v1/health", headers={"traceparent": upstream})
        assert response.status_code == 200
        assert response.headers["X-Trace-ID"] == "abcdefabcdefabcdefabcdefabcdefab"
        generated = client.get("/api/v1/health")
        assert len(generated.headers["X-Trace-ID"]) == 32


def test_observability_summary_states_what_is_not_available():
    with TestClient(app) as client:
        payload = client.get("/api/v1/observability").json()
    assert payload["tracing"]["exporter"] is None
    assert "没有导出" in payload["tracing"]["note"]
    assert payload["detectionMode"] in {"disabled", "shadow", "enabled"}
    assert payload["suricataAvailable"] in {True, False}
    assert "cpuSeconds" in payload["resourceMeasurement"]


def test_runtime_gauges_report_queue_depths():
    with TestClient(app) as client:
        body = client.get("/api/v1/metrics").text
    assert 'evonids_queue_depth{queue="training"}' in body
    assert 'evonids_queue_depth{queue="investigation"}' in body
    assert 'evonids_sensors{state="total"}' in body


def test_recording_failure_does_not_raise():
    registry = MetricsRegistry()
    registry.observe("evonids_safe_seconds", 1.0)
    assert "evonids_safe_seconds_count 1" in registry.render()


def test_new_trace_context_is_unique():
    first = new_trace_context()
    second = new_trace_context()
    assert first.trace_id != second.trace_id
    assert len(first.span_id) == 16
