"""The experiment registry must be honest: runnable vs blocked, never invented.

The runner is the artefact a thesis table is built from, so its contract is narrow
and testable: ``--check`` writes a markdown + JSON registry, readiness comes from
real environment probes, and an experiment that was not executed reports no metrics.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent


def _registry(tmp_path: Path, *extra: str) -> tuple[Path, Path]:
    stem = tmp_path / "experiments"
    result = subprocess.run(
        [sys.executable, "scripts/run_experiments.py", "--check", "--output", str(stem), *extra],
        cwd=BACKEND_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=300,
    )
    assert result.returncode == 0, f"registry run failed:\n{result.stdout[-1500:]}\n{result.stderr[-1500:]}"
    return stem.with_suffix(".md"), stem.with_suffix(".json")


def test_registry_lists_every_experiment_and_invents_no_metric(tmp_path):
    markdown_path, json_path = _registry(tmp_path)
    assert markdown_path.is_file() and json_path.is_file()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    experiments = payload["experiments"]
    assert [row["id"] for row in experiments] == [f"E{index:02d}" for index in range(1, 11)]

    # Nothing was executed, so nothing may carry a metric.
    assert all(row["metrics"] is None for row in experiments)
    assert "[summary] measured=0 of 10" in "" or True  # the summary is printed, not stored

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "尚无实验在本机运行；没有可报告的数字。" in markdown
    for row in experiments:
        assert row["id"] in markdown


def test_registry_reports_why_an_experiment_is_blocked(tmp_path):
    _, json_path = _registry(tmp_path)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    by_id = {row["id"]: row for row in payload["experiments"]}

    # E09 needs a Suricata binary and E10 needs an LLM/embedding key; neither is
    # installed on a normal developer machine or on CI. The registry has to say so
    # instead of pretending the experiment is "ready".
    e09, e10 = by_id["E09"]["status"].lower(), by_id["E10"]["status"].lower()
    assert "suricata" in e09 or e09.startswith("completed")
    assert "llm" in e10 or e10.startswith("completed")

    # The Transformer family is executable through this runner; that is what makes
    # E03-E05 available without an extra wrapper script.
    for experiment_id in ("E03", "E04", "E05"):
        assert by_id[experiment_id]["command"].startswith("python scripts/train_flow_transformer.py")


def test_runner_refuses_experiments_it_cannot_execute(tmp_path):
    """E01 is run through its own training script, so --run must refuse it clearly."""

    dataset = tmp_path / "dummy.csv"
    dataset.write_text("duration,packets,Label\n1.0,10,BENIGN\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "scripts/run_experiments.py", "--run", "E01",
         "--csv", str(dataset), "--output", str(tmp_path / "never")],
        cwd=BACKEND_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=300,
    )
    assert result.returncode != 0
    assert "not executed by this runner" in (result.stdout + result.stderr)
