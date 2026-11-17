"""Experiment registry for the E01-E10 matrix (blueprint appendix B).

Why this script exists: the repository has scripts for individual experiments but
no single artefact that answers "which experiments exist, which are runnable here,
and which numbers were actually measured". Without that, a thesis table gets
assembled from memory and guesses.

Design rules, matching the rest of the project:

* the registry **never fabricates a result** — an experiment that has not been run
  is reported as ``not_run`` with its exact command, not as zero;
* readiness is probed from the machine (dataset present, torch importable, Suricata
  on PATH, LLM key configured), so a blocked experiment says *why*;
* only the Transformer family (E03-E05) is executable here, because it is the only
  family whose CLI emits machine-readable metrics; E01/E02 are run through their own
  training scripts and are registered as pointers.

Usage::

    python scripts/run_experiments.py --check                    # write the registry
    python scripts/run_experiments.py --run E03,E04,E05 --csv <dataset.csv.gz>
    python scripts/run_experiments.py --check --output docs/experiments
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = BACKEND_ROOT / "datasets" / "CICIDS2017" / "cicids2017_pcap_flow_full_v1.csv.gz"
DEFAULT_OUTPUT = BACKEND_ROOT.parent / "docs" / "experiments"


@dataclass(frozen=True)
class Experiment:
    id: str
    title: str
    hypothesis: str
    measures: str
    requires: tuple[str, ...] = ()
    command: tuple[str, ...] = ()
    runnable_here: bool = False
    note: str = ""


EXPERIMENTS: tuple[Experiment, ...] = (
    Experiment(
        id="E01",
        title="Known-attack classification, strong tabular baseline",
        hypothesis="A tuned gradient-boosted baseline sets the number any deep model must beat.",
        measures="macro-F1, per-class recall, PR-AUC, confusion matrix",
        requires=("dataset",),
        command=("python", "scripts/train_full_baseline.py", "--csv", "<dataset>"),
        note="Measured numbers live in MODEL_CARD.md (full_v1 run).",
    ),
    Experiment(
        id="E02",
        title="Unknown-anomaly baseline (tabular AutoEncoder)",
        hypothesis="Reconstruction error trained on benign traffic separates unseen attacks.",
        measures="AUROC, AUPRC, recall at fixed FPR, normal FPR",
        requires=("dataset", "torch"),
        command=("python", "scripts/train_full_autoencoder.py", "--csv", "<dataset>"),
        note="Measured numbers live in MODEL_CARD.md (AUROC 0.9042).",
    ),
    Experiment(
        id="E03",
        title="Flow Transformer without pretraining",
        hypothesis="The architecture alone, with no MFM signal, is the honest floor.",
        measures="macro-F1, per-class recall",
        requires=("dataset", "torch"),
        command=(
            "python", "scripts/train_flow_transformer.py", "--csv", "<dataset>",
            "--no-pretrain", "--d-model", "64", "--layers", "2", "--heads", "4",
        ),
        runnable_here=True,
    ),
    Experiment(
        id="E04",
        title="MFM pretraining + classification head",
        hypothesis="Self-supervised pretraining improves the same architecture (E03 vs E04).",
        measures="macro-F1, per-class recall, delta against E03",
        requires=("dataset", "torch"),
        command=(
            "python", "scripts/train_flow_transformer.py", "--csv", "<dataset>",
            "--pretrain-epochs", "20", "--epochs", "10",
        ),
        runnable_here=True,
    ),
    Experiment(
        id="E05",
        title="MFM pretraining + anomaly head only",
        hypothesis="Reconstruction error from the shared encoder is a usable anomaly channel.",
        measures="AUROC, AUPRC, recall at fixed FPR, normal FPR",
        requires=("dataset", "torch"),
        command=(
            "python", "scripts/train_flow_transformer.py", "--csv", "<dataset>",
            "--task", "anomaly", "--target-fpr", "0.05", "--pretrain-epochs", "20",
        ),
        runnable_here=True,
    ),
    Experiment(
        id="E06",
        title="Dual-channel risk fusion",
        hypothesis="Classification and anomaly channels are complementary, not redundant.",
        measures="fusion precision/recall against each channel alone",
        requires=("dataset", "torch"),
        command=("python", "scripts/backfill_dual_channel_inference.py", "--dataset", "<dataset>"),
    ),
    Experiment(
        id="E07",
        title="Open-set evaluation by attack family",
        hypothesis="Family holdout is the only defensible measure of 'unknown attack' ability.",
        measures="unknown-family recall, AUROC, AUPRC, recall at fixed FPR",
        requires=("dataset",),
        command=("python", "scripts/evaluate_model_splits.py", "--strategy", "family_holdout"),
    ),
    Experiment(
        id="E08",
        title="Out-of-time and cross-host generalisation",
        hypothesis="Random splits overstate performance; time and host holdouts expose it.",
        measures="macro-F1, per-class recall per split strategy",
        requires=("dataset",),
        command=("python", "scripts/evaluate_model_splits.py", "--strategy", "time_holdout,group_holdout"),
    ),
    Experiment(
        id="E09",
        title="Rule replay and benign regression under real Suricata",
        hypothesis="LLM-authored rules only earn trust by passing a real engine and PCAP replay.",
        measures="target hits, benign false positives, load-test result",
        requires=("suricata",),
        command=("python", "-m", "app.services.rule_sandbox", "--help"),
        note="Needs the Suricata binary and an annotated PCAP corpus; recorded as blocked until then.",
    ),
    Experiment(
        id="E10",
        title="RAG citation correctness",
        hypothesis="The Agent's rules must cite retrievable, permitted knowledge.",
        measures="Recall@K, MRR, citation correctness, refusal rate",
        requires=("llm-key",),
        command=("python", "-m", "app.services.knowledge_retrieval", "--help"),
        note="Needs a real embedding/LLM provider; the default hashing embedder is lexical only.",
    ),
)

REQUIREMENT_LABELS = {
    "dataset": "a registered flow dataset (CSV/CSV.GZ)",
    "torch": "PyTorch installed (the `ml` extra)",
    "suricata": "the Suricata binary on PATH",
    "llm-key": "an LLM/embedding provider key",
}


def display_path(path: Path) -> str:
    """Portable label for a path: never leak an absolute developer path into a registry."""

    try:
        return path.resolve().relative_to(BACKEND_ROOT.parent).as_posix()
    except ValueError:
        return path.name


def probe_environment() -> dict[str, bool | str]:
    """What this machine can actually run right now."""

    dataset = DEFAULT_DATASET if DEFAULT_DATASET.is_file() else None
    return {
        "dataset": bool(dataset),
        # Relative on purpose: this block is written into committed documentation.
        "datasetPath": display_path(dataset) if dataset else "",
        "torch": importlib.util.find_spec("torch") is not None,
        "suricata": shutil.which("suricata") is not None,
        "llm-key": bool(
            os.environ.get("NUXT_DEEPSEEK_API_KEY") or os.environ.get("EVONIDS_LLM_API_KEY")
        ),
    }


def experiment_status(experiment: Experiment, probe: dict[str, Any], results: dict[str, Any]) -> str:
    if experiment.id in results:
        return "completed"
    missing = [REQUIREMENT_LABELS[item] for item in experiment.requires if not probe.get(item)]
    if missing:
        return "blocked: needs " + ", ".join(missing)
    return "ready"


def run_transformer_experiment(experiment: Experiment, dataset: Path, output_dir: Path) -> dict[str, Any]:
    """Execute E03/E04/E05 and capture the metrics line the CLI prints."""

    command = list(experiment.command)
    command = ["python" if part == "python" else part for part in command]
    command = [part.replace("<dataset>", str(dataset)) for part in command]
    command = command[:2] + ["--output-dir", str(output_dir / experiment.id)] + command[2:]
    # Use the interpreter running this script, not whatever "python" resolves to.
    command[0] = sys.executable
    print(f"[{experiment.id}] {' '.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=BACKEND_ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=None)
    if completed.returncode != 0:
        return {"id": experiment.id, "status": "failed",
                "detail": (completed.stderr or completed.stdout)[-1500:]}
    for line in reversed(completed.stdout.splitlines()):
        if line.startswith("[metrics] "):
            # Record which dataset produced these numbers: a result without its
            # dataset identity is not a reproducible experiment.
            return {"id": experiment.id, "status": "measured",
                    "dataset": display_path(dataset),
                    "metrics": json.loads(line[len("[metrics] "):])}
    return {"id": experiment.id, "status": "failed", "detail": "the run printed no [metrics] line"}


def build_rows(probe: dict[str, Any], results: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for experiment in EXPERIMENTS:
        status = experiment_status(experiment, probe, results)
        row = {
            "id": experiment.id,
            "title": experiment.title,
            "hypothesis": experiment.hypothesis,
            "measures": experiment.measures,
            "status": status,
            "requires": list(experiment.requires),
            "command": " ".join(experiment.command),
            "note": experiment.note,
        }
        if experiment.id in results:
            row.update({k: v for k, v in results[experiment.id].items() if k != "id"})
        else:
            row["metrics"] = None
        rows.append(row)
    return rows


def render_markdown(rows: list[dict[str, Any]], probe: dict[str, Any]) -> str:
    dataset_status = (
        f"已就绪：`{probe['datasetPath']}`" if probe["dataset"] else "未找到默认数据集（用 `--csv` 指定）"
    )
    torch_status = "可用" if probe["torch"] else '未安装（pip install -e ".[ml]"）'
    suricata_status = "在 PATH 上" if probe["suricata"] else "未安装"
    llm_status = "已配置" if probe["llm-key"] else "未配置"
    lines = [
        "# E01-E10 实验登记表",
        "",
        "> 由 `backend/scripts/run_experiments.py` 生成。**未运行的实验标注为 `not_run` / `blocked`，"
        "不写任何猜测数字。** 重新生成：`python scripts/run_experiments.py --check`。",
        "",
        "## 环境探测",
        "",
        "| 项 | 状态 |",
        "|---|---|",
        f"| 数据集 | {dataset_status} |",
        f"| PyTorch | {torch_status} |",
        f"| Suricata 二进制 | {suricata_status} |",
        f"| LLM / 嵌入密钥 | {llm_status} |",
        "",
        "## 实验矩阵",
        "",
        "| 编号 | 实验 | 假设 | 指标 | 状态 |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['id']} | {row['title']} | {row['hypothesis']} | {row['measures']} | {row['status']} |"
        )

    measured = [row for row in rows if row.get("metrics")]
    lines += ["", "## 已测量结果", ""]
    if not measured:
        lines.append("尚无实验在本机运行；没有可报告的数字。")
    else:
        for row in measured:
            lines.append(f"### {row['id']} — {row['title']}")
            lines.append("")
            if row.get("dataset"):
                lines.append(f"数据集：`{row['dataset']}`")
                lines.append("")
            lines.append("```json")
            lines.append(json.dumps(row["metrics"], ensure_ascii=False, indent=2))
            lines.append("```")
            lines.append("")

    lines += ["", "## 如何运行未完成的实验", ""]
    for row in rows:
        if not row.get("metrics"):
            lines.append(f"- **{row['id']}**：`{row['command']}`")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="write the registry without running anything")
    parser.add_argument("--run", default="", help="comma-separated experiment ids to execute (E03, E04, E05)")
    parser.add_argument("--csv", type=Path, default=None, help="dataset for the experiments that need one")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="output stem; writes <stem>.md and <stem>.json")
    args = parser.parse_args()

    probe = probe_environment()
    results: dict[str, Any] = {}

    requested = [item.strip().upper() for item in args.run.split(",") if item.strip()]
    if requested:
        dataset = args.csv or (Path(probe["datasetPath"]) if probe["dataset"] else None)
        if dataset is None:
            raise SystemExit("--run needs a dataset: pass --csv or place the default dataset under backend/datasets")
        by_id = {experiment.id: experiment for experiment in EXPERIMENTS}
        unknown = [item for item in requested if item not in by_id]
        if unknown:
            raise SystemExit(f"unknown experiment ids: {', '.join(unknown)}")
        for item in requested:
            experiment = by_id[item]
            if not experiment.runnable_here:
                raise SystemExit(
                    f"{item} is not executed by this runner; run it directly: {' '.join(experiment.command)}"
                )
            result = run_transformer_experiment(experiment, dataset, args.output.parent / "artifacts")
            results[item] = result
            print(f"[{item}] {result['status']}", flush=True)

    rows = build_rows(probe, results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    markdown_path = args.output.with_suffix(".md")
    json_path = args.output.with_suffix(".json")
    markdown_path.write_text(render_markdown(rows, probe), encoding="utf-8")
    json_path.write_text(
        json.dumps({"environment": probe, "experiments": rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[registry] {markdown_path}", flush=True)
    print(f"[registry] {json_path}", flush=True)
    print(f"[summary] measured={sum(1 for row in rows if row.get('metrics'))} of {len(rows)}", flush=True)


if __name__ == "__main__":
    main()
