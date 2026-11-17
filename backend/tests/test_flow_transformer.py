"""Unit tests for the Flow Transformer (MFM) module and its training pipeline.

The architecture is exercised with tiny tensors on CPU so the suite stays fast;
one subprocess test runs the real script in ``--smoke`` mode to prove the
training entry point, the ablation flags and the artifact format are wired.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from app.ml.flow_transformer import (  # noqa: E402
    CATEGORY_MASK_SLOT,
    FlowTransformerConfig,
    build_model,
    load_model_from_payload,
    sample_field_mask,
    state_dict_to_payload,
)


def tiny_config(**overrides) -> FlowTransformerConfig:
    values = dict(
        numeric_fields=4,
        categorical_cardinalities=[3, 5],
        d_model=16,
        n_layers=1,
        n_heads=2,
        dim_feedforward=32,
        dropout=0.0,
        mask_ratio=0.15,
        n_classes=3,
    )
    values.update(overrides)
    return FlowTransformerConfig(**values)


def tiny_batch(config: FlowTransformerConfig, batch: int = 6, seed: int = 0):
    generator = torch.Generator().manual_seed(seed)
    x_num = torch.randn(batch, config.numeric_fields, generator=generator)
    x_cat = torch.randint(0, 2, (batch, len(config.categorical_cardinalities)), generator=generator)
    return x_num, x_cat


def test_forward_shapes_cover_both_channels():
    config = tiny_config()
    model = build_model(config)
    x_num, x_cat = tiny_batch(config)
    outputs = model(x_num, x_cat)

    assert outputs["pooled"].shape == (x_num.shape[0], config.d_model)
    assert outputs["numeric_pred"].shape == x_num.shape
    assert outputs["class_logits"].shape == (x_num.shape[0], config.n_classes)
    assert len(outputs["categorical_logits"]) == len(config.categorical_cardinalities)
    for index, cardinality in enumerate(config.categorical_cardinalities):
        # +1 slot for the mask token
        assert outputs["categorical_logits"][index].shape == (x_num.shape[0], cardinality + 1)


def test_model_without_categorical_fields_still_runs():
    config = tiny_config(categorical_cardinalities=[])
    model = build_model(config)
    outputs = model(torch.randn(3, config.numeric_fields))
    assert outputs["numeric_pred"].shape == (3, config.numeric_fields)
    assert outputs["categorical_logits"] == []


def test_field_embedding_ablation_is_configurable():
    # The blueprint's "drop Field-ID embeddings" ablation must be a flag, not an edit.
    with_fields = build_model(tiny_config(use_field_embeddings=True))
    without_fields = build_model(tiny_config(use_field_embeddings=False))
    assert with_fields.field_embeddings is not None
    assert without_fields.field_embeddings is None
    x_num, x_cat = tiny_batch(tiny_config())
    assert without_fields(x_num, x_cat)["pooled"].shape == (x_num.shape[0], 16)


def test_mask_sampling_never_hides_every_field_and_is_deterministic():
    config = tiny_config(mask_ratio=0.9)  # aggressive on purpose
    numeric_mask, categorical_mask = sample_field_mask(64, config, generator=torch.Generator().manual_seed(7))
    repeat_numeric, repeat_categorical = sample_field_mask(
        64, config, generator=torch.Generator().manual_seed(7)
    )
    assert torch.equal(numeric_mask, repeat_numeric), "masking must be reproducible from the seed"
    assert categorical_mask is not None and repeat_categorical is not None
    assert torch.equal(categorical_mask, repeat_categorical)
    # The invariant is per-sample, across both field kinds: with every field hidden
    # the reconstruction task carries no information, so one must always survive.
    combined = torch.cat([numeric_mask, categorical_mask], dim=1)
    assert int((~combined).sum(dim=1).min()) >= 1


def test_zero_mask_ratio_produces_no_masking():
    config = tiny_config()
    numeric_mask, categorical_mask = sample_field_mask(8, config, mask_ratio=0.0)
    assert not numeric_mask.any()
    assert categorical_mask is not None and not categorical_mask.any()
    with pytest.raises(ValueError):
        sample_field_mask(8, config, mask_ratio=1.0)


def test_mfm_loss_ignores_unmasked_fields():
    config = tiny_config()
    model = build_model(config)
    x_num, x_cat = tiny_batch(config)
    numeric_mask, categorical_mask = sample_field_mask(len(x_num), config, mask_ratio=0.0)
    outputs = model(x_num, x_cat, numeric_mask=numeric_mask, categorical_mask=categorical_mask)
    loss = model.mfm_loss(outputs, x_num, x_cat, numeric_mask=numeric_mask, categorical_mask=categorical_mask)
    assert float(loss.detach()) == pytest.approx(0.0, abs=0.0), "no masked field means no reconstruction loss"
    assert loss.requires_grad


def test_mfm_loss_is_positive_when_everything_is_masked():
    config = tiny_config()
    model = build_model(config)
    x_num, x_cat = tiny_batch(config)
    numeric_mask = torch.ones_like(x_num, dtype=torch.bool)
    categorical_mask = torch.ones_like(x_cat, dtype=torch.bool)
    outputs = model(x_num, x_cat, numeric_mask=numeric_mask, categorical_mask=categorical_mask)
    loss = model.mfm_loss(outputs, x_num, x_cat, numeric_mask=numeric_mask, categorical_mask=categorical_mask)
    assert float(loss.detach()) > 0.0


def test_reconstruction_error_is_per_sample_and_finite():
    config = tiny_config()
    model = build_model(config)
    x_num, x_cat = tiny_batch(config)
    error = model.reconstruction_error(x_num, x_cat)
    assert error.shape == (x_num.shape[0],)
    assert torch.isfinite(error).all()


def test_state_dict_round_trip_reproduces_outputs():
    config = tiny_config()
    model = build_model(config)
    x_num, x_cat = tiny_batch(config)
    with torch.no_grad():
        before = model(x_num, x_cat)["class_logits"]
    restored = load_model_from_payload(config, state_dict_to_payload(model))
    with torch.no_grad():
        after = restored(x_num, x_cat)["class_logits"]
    assert torch.allclose(before, after, atol=1e-6)


def test_config_validation_rejects_impossible_architectures():
    with pytest.raises(ValueError):
        FlowTransformerConfig(numeric_fields=4, d_model=15, n_heads=4)
    with pytest.raises(ValueError):
        FlowTransformerConfig(numeric_fields=0)


def test_category_mask_slot_matches_embedding_table():
    # The mask slot is one past the real categories; the embedding table is sized
    # cardinality + 1 in exactly the same way, so the two must stay in sync.
    assert CATEGORY_MASK_SLOT == "mask"
    config = tiny_config()
    model = build_model(config)
    for index, cardinality in enumerate(config.categorical_cardinalities):
        assert model.categorical_embeddings[index].num_embeddings == cardinality + 1


def _run_smoke(args, *, expect_success: bool = True):
    backend_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "scripts/train_flow_transformer.py", *args],
        cwd=backend_root, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=600,
    )
    if expect_success:
        assert result.returncode == 0, f"smoke run failed:\nSTDOUT:\n{result.stdout[-2000:]}\nSTDERR:\n{result.stderr[-2000:]}"
    else:
        assert result.returncode != 0, "the run was expected to fail"
    return result


def test_training_script_smoke_run_writes_an_artifact(tmp_path):
    """End-to-end: the CLI trains on synthetic data and writes a usable artifact."""

    backend_root = Path(__file__).resolve().parent.parent
    output_dir = tmp_path / "flow-transformer"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/train_flow_transformer.py",
            "--smoke",
            "--d-model", "16",
            "--layers", "1",
            "--heads", "2",
            "--feedforward", "32",
            "--pretrain-epochs", "1",
            "--epochs", "1",
            "--batch-size", "64",
            "--output-dir", str(output_dir),
        ],
        cwd=backend_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        timeout=600,
    )
    assert result.returncode == 0, f"smoke run failed:\nSTDOUT:\n{result.stdout[-2000:]}\nSTDERR:\n{result.stderr[-2000:]}"
    assert "smoke run finished" in result.stdout

    artifact = output_dir / "model.joblib"
    metadata = output_dir / "metadata.json"
    assert artifact.is_file() and artifact.stat().st_size > 0
    assert metadata.is_file()

    payload = json.loads(metadata.read_text(encoding="utf-8"))
    assert payload["algorithm"] == "flow_transformer_mfm"
    assert payload["task"] == "flow_transformer_mfm"
    assert payload["featureVersion"] == "tabular-mfm-v1"
    assert payload["architecture"]["use_field_embeddings"] is True
    assert payload["ablations"]["pretrained"] is True
    assert payload["metrics"]["testSamples"] > 0
    assert "note" in payload["metrics"], "a smoke run must label its numbers as pipeline-only"


def test_anomaly_task_calibrates_a_frozen_threshold(tmp_path):
    """E05: the anomaly channel must report a calibrated operating point, not a guess."""

    output_dir = tmp_path / "flow-transformer-anomaly"
    result = _run_smoke(
        [
            "--smoke",
            "--task", "anomaly",
            "--target-fpr", "0.1",
            "--d-model", "16",
            "--layers", "1",
            "--heads", "2",
            "--feedforward", "32",
            "--pretrain-epochs", "1",
            "--batch-size", "64",
            "--output-dir", str(output_dir),
        ]
    )
    assert "task=anomaly" in result.stdout
    assert "[anomaly]" in result.stdout, "the run must print the calibrated threshold"

    payload = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert payload["task"] == "flow_transformer_anomaly"
    assert payload["ablations"]["task"] == "anomaly"
    operating_point = payload["operatingPoint"]
    assert operating_point["targetFpr"] == 0.1
    assert operating_point["threshold"] > 0
    assert operating_point["calibratedOn"].startswith("validation-split")

    metrics = payload["metrics"]
    for key in ("auroc", "auprc", "attackRecall", "precision", "f1", "normalFpr", "perClassDetectionRate"):
        assert key in metrics, f"anomaly metrics must report {key}"
    # The anomaly channel has no supervised classifier, so it must not claim one.
    assert "macroF1" not in metrics


def test_anomaly_task_requires_pretraining(tmp_path):
    """Scoring rows by reconstruction error is meaningless without the MFM objective."""

    result = _run_smoke(
        ["--smoke", "--task", "anomaly", "--no-pretrain", "--output-dir", str(tmp_path / "never")],
        expect_success=False,
    )
    assert "needs MFM pretraining" in (result.stderr + result.stdout)
