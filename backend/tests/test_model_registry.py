from app.services.model_registry import artifact_state


def test_artifact_state_requires_a_real_local_file(tmp_path):
    artifact = tmp_path / "flow-transformer.onnx"
    artifact.write_bytes(b"real-test-artifact")

    assert artifact_state(None) == "missing"
    assert artifact_state(str(tmp_path / "missing.onnx")) == "missing"
    assert artifact_state(str(artifact)) == "available"
    assert artifact_state(artifact.as_uri()) == "available"
    assert artifact_state("s3://evonids-models/flow-transformer.onnx") == "unverified"
