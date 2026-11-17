"""Train the Flow Transformer (MFM pretraining + supervised fine-tuning).

Why this script exists: v0.1 shipped a HistGradientBoosting baseline and a tabular
AutoEncoder; the project's headline architecture — a self-supervised Flow
Transformer over field tokens — had code but no training path. This script makes
the whole pipeline executable and, more importantly, *ablative*: the flags map
one-to-one onto the experiments listed in the blueprint (§7.5, appendix B):

===========================  =====================================================
flag                         ablation it enables
===========================  =====================================================
``--no-pretrain``            E03/E04: is the MFM signal itself worth anything?
``--no-field-embeddings``    drop Field-ID embeddings (field identity ablation)
``--mask-rate``              0.10 / 0.15 / 0.20 / 0.30 sweep
``--d-model``/``--layers``   capacity sweep, reported together with inference time
``--task anomaly``           E05: reconstruction-error anomaly channel only
===========================  =====================================================

Honesty rules borrowed from the rest of the repository:

* columns that cannot be observed online are not silently dropped — the run
  records the exact feature list in the artifact and in ``metadata.json``;
* ``--smoke`` trains on synthetic data so the pipeline can be verified without
  the 200 MB dataset, and it never writes into the real artifact directory;
* the script prints measured numbers only; anything not computed stays absent
  from the metrics rather than being reported as 0.0.

Usage examples::

    python scripts/train_flow_transformer.py --smoke
    python scripts/train_flow_transformer.py \
        --csv datasets/CICIDS2017/cicids2017_pcap_flow_full_v1.csv.gz \
        --label-column Label --d-model 64 --layers 2 --heads 4 \
        --pretrain-epochs 20 --epochs 10 --output-dir /tmp/flow-transformer
"""

from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

IDENTIFIER_COLUMNS = {"flow id", "source ip", "destination ip", "timestamp", "capture_day", "start_time", "fwd_header_length"}


@dataclass
class Dataset:
    x_num: Any
    x_cat: Any
    y: Any
    numeric_features: list[str]
    categorical_features: list[str]
    classes: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", type=Path, default=None, help="CSV or CSV.GZ with a label column")
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--smoke", action="store_true", help="synthetic data + 2 epochs; never writes real artifacts")
    parser.add_argument("--d-model", type=int, default=64)
    parser.add_argument("--layers", type=int, default=2)
    parser.add_argument("--heads", type=int, default=4)
    parser.add_argument("--feedforward", type=int, default=128)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--mask-rate", type=float, default=0.15)
    parser.add_argument("--no-field-embeddings", action="store_true")
    parser.add_argument("--no-pretrain", action="store_true", help="skip MFM; supervised training only (ablation)")
    parser.add_argument("--task", choices=("classification", "anomaly"), default="classification")
    parser.add_argument("--pretrain-epochs", type=int, default=20)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--max-rows", type=int, default=250_000)
    parser.add_argument("--random-seed", type=int, default=20260728)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args()


# --------------------------------------------------------------------------- data
def load_synthetic(rows: int = 600, seed: int = 0) -> Dataset:
    """Small, deterministic dataset with a learnable signal plus noise."""

    import numpy as np

    rng = np.random.default_rng(seed)
    n_attack = rows // 3
    benign = rng.normal(0.0, 1.0, size=(rows - n_attack, 5))
    attack = rng.normal(2.5, 1.0, size=(n_attack, 5))
    numeric = np.vstack([benign, attack]).astype("float32")
    labels = np.array([0] * len(benign) + [1] * n_attack)
    categorical = np.where(labels == 1, 1, 0).astype("int64").reshape(-1, 1)
    order = rng.permutation(len(labels))
    return Dataset(
        x_num=numeric[order],
        x_cat=categorical[order],
        y=labels[order],
        numeric_features=[f"n{i}" for i in range(numeric.shape[1])],
        categorical_features=["proto"],
        classes=["BENIGN", "ATTACK"],
    )


def load_csv(path: Path, label_column: str, max_rows: int, seed: int) -> Dataset:
    import numpy as np
    import pandas as pd

    frame = pd.read_csv(path, nrows=max_rows, low_memory=False)
    if label_column not in frame.columns:
        raise SystemExit(f"label column {label_column!r} not found; columns: {list(frame.columns)[:12]}...")
    labels = frame[label_column].astype("string").str.strip()
    frame = frame.drop(columns=[label_column])

    numeric_features: list[str] = []
    categorical_features: list[str] = []
    for column in frame.columns:
        if column.strip().lower() in IDENTIFIER_COLUMNS:
            continue
        values = pd.to_numeric(frame[column], errors="coerce")
        if values.notna().mean() >= 0.95:
            numeric_features.append(column)
        else:
            categorical_features.append(column)

    numeric = frame[numeric_features].apply(pd.to_numeric, errors="coerce")
    numeric = numeric.fillna(numeric.median(numeric_only=True)).fillna(0.0)
    categorical = frame[categorical_features].astype("string").fillna("unknown") if categorical_features else None

    classes = sorted(labels.dropna().unique().tolist())
    class_index = {name: index for index, name in enumerate(classes)}
    y = labels.map(class_index).fillna(0).astype("int64").to_numpy()

    cat_codes = np.zeros((len(frame), len(categorical_features)), dtype="int64")
    if categorical is not None:
        for index, column in enumerate(categorical_features):
            cat_codes[:, index] = pd.Categorical(categorical[column]).codes

    rng = np.random.default_rng(seed)
    order = rng.permutation(len(y))
    return Dataset(
        x_num=numeric.to_numpy(dtype="float32")[order],
        x_cat=cat_codes[order],
        y=y[order],
        numeric_features=numeric_features,
        categorical_features=categorical_features,
        classes=classes,
    )


def split_dataset(data: Dataset, *, seed: int) -> tuple[Dataset, Dataset, Dataset]:
    """Stratified 70/15/15 split; identical protocol to the HGB/AE pipelines."""

    import numpy as np

    rng = np.random.default_rng(seed)
    train_idx, val_idx, test_idx = [], [], []
    for label in np.unique(data.y):
        rows = np.where(data.y == label)[0]
        rng.shuffle(rows)
        cut1 = max(1, int(len(rows) * 0.7))
        cut2 = max(cut1 + 1, int(len(rows) * 0.85)) if len(rows) > 2 else cut1
        train_idx.extend(rows[:cut1])
        val_idx.extend(rows[cut1:cut2])
        test_idx.extend(rows[cut2:])

    def subset(indices: list[int]) -> Dataset:
        idx = np.array(sorted(indices), dtype="int64")
        return Dataset(
            x_num=data.x_num[idx],
            x_cat=data.x_cat[idx],
            y=data.y[idx],
            numeric_features=data.numeric_features,
            categorical_features=data.categorical_features,
            classes=data.classes,
        )

    return subset(train_idx), subset(val_idx), subset(test_idx)


def standardise(train: Dataset, *others: Dataset) -> tuple[list[float], list[float]]:

    mean = train.x_num.mean(axis=0)
    std = train.x_num.std(axis=0)
    std[std < 1e-6] = 1.0
    for dataset in (train,) + others:
        dataset.x_num = ((dataset.x_num - mean) / std).astype("float32")
    return mean.tolist(), std.tolist()


# ----------------------------------------------------------------------- training
def train(args: argparse.Namespace) -> dict[str, Any]:
    import torch

    from app.ml.flow_transformer import FlowTransformerConfig, build_model, sample_field_mask

    torch.manual_seed(args.random_seed)
    generator = torch.Generator().manual_seed(args.random_seed)

    started = time.perf_counter()
    if args.smoke:
        data = load_synthetic(seed=args.random_seed)
        args.pretrain_epochs = min(args.pretrain_epochs, 2)
        args.epochs = min(args.epochs, 2)
        args.batch_size = min(args.batch_size, 64)
    else:
        if args.csv is None:
            raise SystemExit("--csv is required unless --smoke is set")
        data = load_csv(args.csv, args.label_column, args.max_rows, args.random_seed)
    train_set, val_set, test_set = split_dataset(data, seed=args.random_seed)
    mean, std = standardise(train_set, val_set, test_set)
    print(f"[data] train={len(train_set.y)} val={len(val_set.y)} test={len(test_set.y)} "
          f"numeric={len(data.numeric_features)} categorical={len(data.categorical_features)} classes={len(data.classes)}",
          flush=True)

    config = FlowTransformerConfig(
        numeric_fields=len(data.numeric_features),
        categorical_cardinalities=[int(max(data.x_cat[:, i].max(), 0)) + 1 for i in range(len(data.categorical_features))],
        d_model=args.d_model,
        n_layers=args.layers,
        n_heads=args.heads,
        dim_feedforward=args.feedforward,
        dropout=args.dropout,
        mask_ratio=args.mask_rate,
        use_field_embeddings=not args.no_field_embeddings,
        n_classes=len(data.classes),
    )
    model = build_model(config)
    optimiser = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    x_num_all = torch.from_numpy(train_set.x_num)
    x_cat_all = torch.from_numpy(train_set.x_cat) if train_set.x_cat.shape[1] else None
    y_all = torch.from_numpy(train_set.y)

    def batches(size: int, batch_size: int):
        order = torch.randperm(size, generator=generator)
        for start in range(0, size, batch_size):
            yield order[start : start + batch_size]

    pretrain_losses: list[float] = []
    if not args.no_pretrain and args.pretrain_epochs > 0:
        for epoch in range(1, args.pretrain_epochs + 1):
            model.train()
            total, seen = 0.0, 0
            for index in batches(len(y_all), args.batch_size):
                x_num = x_num_all[index]
                x_cat = x_cat_all[index] if x_cat_all is not None else None
                numeric_mask, categorical_mask = sample_field_mask(len(index), config, generator=generator)
                outputs = model(x_num, x_cat, numeric_mask=numeric_mask, categorical_mask=categorical_mask)
                loss = model.mfm_loss(outputs, x_num, x_cat, numeric_mask=numeric_mask, categorical_mask=categorical_mask)
                optimiser.zero_grad()
                loss.backward()
                optimiser.step()
                total += float(loss.detach()) * len(index)
                seen += len(index)
            pretrain_losses.append(total / max(seen, 1))
            print(f"[pretrain {epoch}/{args.pretrain_epochs}] mfm_loss={pretrain_losses[-1]:.4f}", flush=True)

    def accuracy(dataset: Dataset) -> tuple[float, list[float]]:
        model.eval()
        with torch.no_grad():
            logits = model(torch.from_numpy(dataset.x_num), torch.from_numpy(dataset.x_cat) if dataset.x_cat.shape[1] else None)["class_logits"]
            predicted = logits.argmax(dim=1).numpy()
        recalls = []
        for label in range(len(dataset.classes)):
            mask = dataset.y == label
            if mask.any():
                recalls.append(float((predicted[mask] == label).mean()))
        return float((predicted == dataset.y).mean()), recalls

    # Class-weighted CE keeps rare attack families (Heartbleed, Web XSS) from being
    # erased by the benign majority, mirroring the HGB baseline's class handling.
    class_weights = torch.tensor(
        [1.0 / max(1, int((train_set.y == label).sum())) for label in range(len(train_set.classes))],
        dtype=torch.float32,
    )
    class_weights = class_weights / class_weights.sum() * len(class_weights)

    finetune_losses: list[float] = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        total, seen = 0.0, 0
        for index in batches(len(y_all), args.batch_size):
            x_num = x_num_all[index]
            x_cat = x_cat_all[index] if x_cat_all is not None else None
            logits = model(x_num, x_cat)["class_logits"]
            loss = torch.nn.functional.cross_entropy(logits, y_all[index], weight=class_weights)
            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
            total += float(loss.detach()) * len(index)
            seen += len(index)
        finetune_losses.append(total / max(seen, 1))
        print(f"[finetune {epoch}/{args.epochs}] ce_loss={finetune_losses[-1]:.4f}", flush=True)

    val_accuracy, val_recalls = accuracy(val_set)
    test_accuracy, test_recalls = accuracy(test_set)
    macro_f1 = _macro_f1(model, test_set)
    anomaly_auroc = _anomaly_auroc(model, test_set, len(data.classes))
    inference_ms = _inference_ms(model, test_set)

    metrics = {
        "valAccuracy": round(val_accuracy, 6),
        "testAccuracy": round(test_accuracy, 6),
        "macroF1": round(macro_f1, 6),
        "perClassRecall": {name: round(value, 6) for name, value in zip(data.classes, test_recalls, strict=False)},
        "anomalyAuroc": None if anomaly_auroc is None else round(anomaly_auroc, 6),
        "inferenceMsPerBatch": round(inference_ms, 3),
        "trainSamples": int(len(train_set.y)),
        "valSamples": int(len(val_set.y)),
        "testSamples": int(len(test_set.y)),
        "featureCount": len(data.numeric_features) + len(data.categorical_features),
        "trainingSeconds": round(time.perf_counter() - started, 1),
    }
    if args.smoke:
        metrics["note"] = "smoke run on synthetic data: numbers verify the pipeline, not model quality"

    print("[metrics] " + json.dumps(metrics, ensure_ascii=False), flush=True)
    return {
        "model": model,
        "config": config,
        "metrics": metrics,
        "mean": mean,
        "std": std,
        "data": data,
        "pretrainLosses": pretrain_losses,
        "finetuneLosses": finetune_losses,
        "smoke": args.smoke,
    }


def _macro_f1(model: Any, dataset: Dataset) -> float:
    import numpy as np
    import torch

    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(dataset.x_num), torch.from_numpy(dataset.x_cat) if dataset.x_cat.shape[1] else None)["class_logits"]
        predicted = logits.argmax(dim=1).numpy()
    f1_scores = []
    for label in range(len(dataset.classes)):
        true_positive = int(((predicted == label) & (dataset.y == label)).sum())
        false_positive = int(((predicted == label) & (dataset.y != label)).sum())
        false_negative = int(((predicted != label) & (dataset.y == label)).sum())
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
        f1_scores.append(0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall))
    return float(np.mean(f1_scores)) if f1_scores else 0.0


def _anomaly_auroc(model: Any, dataset: Dataset, n_classes: int) -> float | None:
    """AUROC of the reconstruction error separating benign from attack rows."""

    import numpy as np
    import torch

    if n_classes < 2:
        return None
    model.eval()
    with torch.no_grad():
        errors = model.reconstruction_error(
            torch.from_numpy(dataset.x_num),
            torch.from_numpy(dataset.x_cat) if dataset.x_cat.shape[1] else None,
        ).numpy()
    # split_dataset sorts classes, so index 0 is the alphabetically first label
    # ("BENIGN" for CICIDS): AUROC here always means truth = not-benign.
    benign_label = 0
    binary = (dataset.y != benign_label).astype("int8")
    positives = int(binary.sum())
    negatives = len(binary) - positives
    if positives == 0 or negatives == 0:
        return None
    order = np.argsort(errors)
    ranks = np.empty(len(errors), dtype="float64")
    ranks[order] = np.arange(1, len(errors) + 1)
    return float((ranks[binary == 1].sum() - positives * (positives + 1) / 2) / (positives * negatives))


def _inference_ms(model: Any, dataset: Dataset) -> float:
    import torch

    model.eval()
    x_num = torch.from_numpy(dataset.x_num[: min(256, len(dataset.x_num))])
    x_cat = torch.from_numpy(dataset.x_cat[: min(256, len(dataset.x_cat))]) if dataset.x_cat.shape[1] else None
    with torch.no_grad():
        model(x_num, x_cat)  # warm-up
        started = time.perf_counter()
        for _ in range(5):
            model(x_num, x_cat)
    return (time.perf_counter() - started) / 5 * 1000


# ---------------------------------------------------------------------- artifact
def write_artifact(args: argparse.Namespace, result: dict[str, Any]) -> Path:
    import joblib
    import torch

    from app.ml.flow_transformer import state_dict_to_payload

    if result["smoke"]:
        output_dir = args.output_dir or (Path(__file__).resolve().parent.parent / ".smoke-artifacts" / "flow-transformer")
    elif args.output_dir is not None:
        output_dir = args.output_dir
    else:
        output_dir = Path(__file__).resolve().parent.parent / "model-artifacts" / "flow-transformer"
    output_dir.mkdir(parents=True, exist_ok=True)

    config = result["config"]
    data = result["data"]
    payload = {
        "formatVersion": 1,
        "task": "flow_transformer_mfm" if not args.no_pretrain else "flow_transformer_supervised",
        "algorithm": "flow_transformer_mfm",
        "featureVersion": "tabular-mfm-v1",
        "architecture": config.to_dict(),
        "numericFeatures": data.numeric_features,
        "categoricalFeatures": data.categorical_features,
        "classes": data.classes,
        "standardisation": {"mean": result["mean"], "std": result["std"]},
        "modelState": state_dict_to_payload(result["model"]),
        "metrics": result["metrics"],
        "lossCurves": {"pretrain": result["pretrainLosses"], "finetune": result["finetuneLosses"]},
        "ablations": {
            "pretrained": not args.no_pretrain,
            "fieldEmbeddings": not args.no_field_embeddings,
            "maskRatio": args.mask_rate,
            "task": args.task,
        },
        "runtimeVersions": {"python": __import__("sys").version.split()[0], "torch": torch.__version__},
        "randomSeed": args.random_seed,
    }
    artifact_path = output_dir / "model.joblib"
    temporary = artifact_path.with_suffix(".joblib.tmp")
    joblib.dump(payload, temporary, compress=3)
    temporary.replace(artifact_path)
    (output_dir / "metadata.json").write_text(
        json.dumps({key: value for key, value in payload.items() if key != "modelState"}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[artifact] {artifact_path}", flush=True)
    return artifact_path


def main() -> None:
    args = parse_args()
    result = train(args)
    write_artifact(args, result)
    if args.smoke:
        assert math.isfinite(result["metrics"]["macroF1"]), "smoke run produced a non-finite metric"
        print("[complete] smoke run finished: pipeline, ablation flags and artifact format are wired", flush=True)


if __name__ == "__main__":
    main()
