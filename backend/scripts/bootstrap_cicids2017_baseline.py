from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.core.config import get_settings
from app.db.models import DatasetAsset, TrainingRun
from app.db.session import SessionLocal
from app.schemas.api import DatasetRegistration, DatasetSplit, TrainingRunCreate
from app.services.dataset_catalog import profile_dataset_asset, register_dataset_asset
from app.services.training import execute_training_run, queue_training_run, to_training_run_read


DATASET_ID = "DS-CIC-2017-PCAP-V1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Register, profile and train the reproducible CICIDS2017 PCAP-derived CPU baseline."
    )
    parser.add_argument(
        "--relative-path",
        default="CICIDS2017/cicids2017_pcap_flow_research_v1.csv.gz",
    )
    parser.add_argument("--max-rows", type=int, default=500_000)
    parser.add_argument("--max-iter", type=int, default=180)
    parser.add_argument("--random-seed", type=int, default=20260728)
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("./model-artifacts/cicids2017-latest-summary.json"),
    )
    return parser.parse_args()


def ensure_dataset(relative_path: str) -> None:
    settings = get_settings()
    with SessionLocal() as db:
        existing = db.get(DatasetAsset, DATASET_ID)
        if existing is None:
            payload = DatasetRegistration(
                id=DATASET_ID,
                name="CICIDS2017 PCAP Flow Research Set",
                version="pcap-flow-research-v1",
                relative_path=relative_path,
                source_uri="https://www.unb.ca/cic/datasets/ids-2017.html",
                label_column="Label",
                normal_labels=["BENIGN"],
                split=DatasetSplit(train=70, validation=15, test=15),
                main_training_set=True,
                unknown_holdout=True,
                rule_replay=True,
                uses=[
                    "PCAPNG 双向五元组流特征基线",
                    "已知攻击多分类 CPU 基线",
                    "低置信度样本路由验证",
                    "规则回放与告警研判演示",
                ],
                actor="cicids2017-bootstrap",
                note="Derived locally from the five original CICIDS2017 PCAPNG captures with audited metadata.",
            )
            register_dataset_asset(
                db,
                payload,
                settings=settings,
                request_id="local-cicids2017-bootstrap",
            )
            print(f"[register] created dataset {DATASET_ID}", flush=True)
        elif existing.relative_path != relative_path.replace("\\", "/"):
            raise ValueError(
                f"{DATASET_ID} already points to {existing.relative_path}; "
                f"refusing to replace immutable lineage with {relative_path}"
            )
        else:
            print(f"[register] dataset {DATASET_ID} already exists", flush=True)
    print("[profile] hashing and profiling the real derived CSV", flush=True)
    profile_dataset_asset(DATASET_ID)
    with SessionLocal() as db:
        dataset = db.get(DatasetAsset, DATASET_ID)
        if dataset is None or dataset.state != "ready":
            detail = dataset.inspection_error if dataset is not None else "dataset disappeared"
            raise RuntimeError(f"Dataset profiling failed: {detail}")
        print(
            f"[profile] ready rows={dataset.total_samples:,} features={dataset.feature_count} "
            f"normal={dataset.normal_samples:,} attack={dataset.attack_samples:,} "
            f"sha256={dataset.sha256}",
            flush=True,
        )


def train(args: argparse.Namespace) -> dict[str, object]:
    settings = get_settings()
    with SessionLocal() as db:
        run = queue_training_run(
            db,
            TrainingRunCreate(
                dataset_id=DATASET_ID,
                algorithm="hist_gradient_boosting",
                max_rows=args.max_rows,
                random_seed=args.random_seed,
                max_iter=args.max_iter,
                learning_rate=0.08,
                max_leaf_nodes=31,
                l2_regularization=0.2,
                actor="cicids2017-bootstrap",
            ),
            settings=settings,
            request_id="local-cicids2017-bootstrap",
        )
        run_id = run.id
        print(f"[train] queued run={run_id} algorithm=hist_gradient_boosting", flush=True)
    execute_training_run(run_id)
    with SessionLocal() as db:
        row = db.get(TrainingRun, run_id)
        if row is None:
            raise RuntimeError(f"Training run disappeared: {run_id}")
        result = to_training_run_read(db, row).model_dump(mode="json", by_alias=True)
        if row.state != "succeeded":
            raise RuntimeError(f"Training failed: {row.error_message}")
        metrics = result["metrics"]
        print(
            f"[train] succeeded macro_f1={metrics['macroF1']:.4f} "
            f"weighted_f1={metrics['weightedF1']:.4f} "
            f"samples={result['samplesUsed']:,} artifact={result['artifactSha256']}",
            flush=True,
        )
        return result


def main() -> None:
    args = parse_args()
    ensure_dataset(args.relative_path)
    result = train(args)
    summary = args.summary.resolve()
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[complete] summary={summary}", flush=True)


if __name__ == "__main__":
    main()
