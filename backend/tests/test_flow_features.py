"""Online feature contract: parity, missing-data markers and window context."""
from datetime import datetime, timezone

from app.domain.flow_features import (
    ONLINE_CONTEXT_FEATURES,
    ONLINE_FEATURE_VERSION,
    ONLINE_MODEL_FEATURES,
    WindowCounts,
    build_online_features,
    project_cicids_row,
    protocol_number,
)

EVE_FLOW = {
    "external_id": "flow-1",
    "timestamp": "2026-09-09T10:00:00+00:00",
    "src_ip": "192.0.2.10",
    "src_port": 51000,
    "dst_ip": "10.0.0.8",
    "dst_port": 445,
    "protocol": "TCP",
    "flow_duration": 2.0,
    "forward_packet_count": 10,
    "backward_packet_count": 5,
    "forward_bytes": 1200,
    "backward_bytes": 300,
}

# The same observation expressed with CICIDS2017 column names. The parity test
# below is the guarantee that offline training and online inference compute the
# model features with identical formulas.
CICIDS_ROW = {
    "source_port": 51000,
    "destination_port": 445,
    "protocol": 6,
    "duration_us": 2_000_000,
    "total_fwd_packets": 10,
    "total_bwd_packets": 5,
    "total_fwd_bytes": 1200,
    "total_bwd_bytes": 300,
}


def _vector(**overrides):
    payload = {**EVE_FLOW, **overrides}
    return build_online_features(
        payload,
        sensor_id="sensor-a",
        observed_at=datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc),
        window=WindowCounts(
            destination_port_count=7, destination_ip_count=3, flow_count=20, source_port_count=1
        ),
    )


def test_contract_layers_are_disjoint_and_versioned():
    assert set(ONLINE_MODEL_FEATURES).isdisjoint(ONLINE_CONTEXT_FEATURES)
    vector = _vector()
    assert vector.feature_version == ONLINE_FEATURE_VERSION
    assert set(vector.model_values) == set(ONLINE_MODEL_FEATURES)
    assert set(vector.context_values) == set(ONLINE_CONTEXT_FEATURES)
    assert vector.data_missing == "none"


def test_build_online_features_computes_documented_formulas():
    values = _vector().values
    assert values["source_port"] == 51000
    assert values["destination_port"] == 445
    assert values["protocol_number"] == 6
    assert values["flow_duration_seconds"] == 2.0
    assert values["packets_per_second"] == 7.5
    assert values["bytes_per_second"] == 750.0
    assert values["average_packet_size"] == 100.0
    assert values["forward_mean_packet_size"] == 120.0
    assert values["backward_mean_packet_size"] == 60.0
    assert values["packet_size_asymmetry"] == 0.5
    assert values["byte_ratio"] == 0.8
    assert values["packet_ratio"] == 0.666667


def test_window_context_features_are_computed_but_kept_out_of_the_model_input():
    vector = _vector()
    assert vector.context_values["destination_port_count_60s"] == 7
    assert vector.context_values["flow_count_60s"] == 20
    assert vector.context_values["destination_port_ratio_60s"] == 0.35
    assert "destination_port_count_60s" not in vector.model_values
    record = vector.as_record()
    assert record["windowSeconds"] == 60
    assert record["missingFields"] == []
    assert record["modelFeatures"]["packet_ratio"] == 0.666667


def test_missing_flow_fields_are_reported_instead_of_silently_zeroed():
    payload = {
        key: value
        for key, value in EVE_FLOW.items()
        if key not in {"forward_bytes", "backward_bytes", "flow_duration"}
    }
    vector = build_online_features(
        payload,
        sensor_id="sensor-a",
        observed_at=datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc),
    )
    assert set(vector.missing_fields) == {"flow_duration", "forward_bytes", "backward_bytes"}
    assert vector.data_missing == "partial"
    assert vector.values["byte_ratio"] == 0.0
    assert vector.values["packets_per_second"] == 0.0


def test_online_builder_and_cicids_projection_agree_on_model_features():
    online = _vector().model_values
    offline = project_cicids_row(CICIDS_ROW)
    assert set(offline) == set(ONLINE_MODEL_FEATURES)
    for name in ONLINE_MODEL_FEATURES:
        assert offline[name] == online[name], name


def test_protocol_number_mapping_handles_names_numbers_and_unknowns():
    assert protocol_number("tcp") == 6
    assert protocol_number("UDP") == 17
    assert protocol_number("ICMP") == 1
    assert protocol_number(6) == 6
    assert protocol_number("something-else") == 0
    assert protocol_number(None) == 0
    assert protocol_number(True) == 0


def test_zero_duration_and_zero_packet_flows_do_not_divide_by_zero():
    values = _vector(flow_duration=0, forward_packet_count=0, backward_packet_count=0).values
    assert values["packets_per_second"] == 0.0
    assert values["bytes_per_second"] == 0.0
    assert values["average_packet_size"] == 0.0
    assert values["packet_size_asymmetry"] == 0.0
    assert values["packet_ratio"] == 0.0
