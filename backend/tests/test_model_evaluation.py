"""Deterministic unit tests for the model evaluation protocol.

Pure in-memory frames only: no dataset files, no torch, no environment
bootstrap.  Everything is verified against hand-computed values or known
synthetic distributions.
"""
import numpy as np
import pandas as pd
import pytest

from app.services import model_evaluation as ev


def make_frame(seed: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    labels = ["BENIGN"] * 60 + ["DDoS"] * 60 + ["PortScan"] * 40 + ["WebAttack"] * 40
    rows = []
    for index in range(200):
        rows.append(
            {
                "f_a": float(rng.normal(index % 2, 1.0)),
                "f_b": float(rng.random()),
                "Label": labels[index],
                "ts": f"2017-07-{index // 60 + 1:02d}T{index % 24:02d}:{(index * 7) % 60:02d}:00+00:00",
                "host": f"host-{index % 7}",
            }
        )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# split protocol
# ---------------------------------------------------------------------------
def test_random_split_is_deterministic_and_partitions_exactly():
    frame = make_frame()
    first = ev.split_manifest(frame, strategy="random", seed=11, label_column="Label")
    second = ev.split_manifest(frame, strategy="random", seed=11, label_column="Label")
    assert first == second  # full manifest determinism
    train = set(first["splits"]["train"]["rowIndices"])
    test = set(first["splits"]["test"]["rowIndices"])
    assert first["splits"]["train"]["rows"] == len(train) == 140
    assert len(test) == 60
    assert train.isdisjoint(test)
    assert train | test == set(range(200))
    assert first["splits"]["train"]["rows"] + first["splits"]["test"]["rows"] == 200
    # per-class counts across splits sum to the frame total
    total = {}
    for split in ("train", "test"):
        for label, count in first["splits"][split]["classCounts"].items():
            total[label] = total.get(label, 0) + count
    assert total == dict(pd.Series(frame["Label"]).value_counts())


def test_random_is_labelled_weakest_evidence():
    manifest = ev.split_manifest(make_frame(), strategy="random", seed=1, label_column="Label")
    assert manifest["evidence"]["rank"] == 1
    assert manifest["evidence"]["label"] == "weakest"


def test_time_ordered_split_boundaries_and_disjointness():
    frame = make_frame()
    manifest = ev.split_manifest(
        frame,
        strategy="time_ordered",
        seed=3,
        label_column="Label",
        time_column="ts",
        test_ratio=0.3,
    )
    train = set(manifest["splits"]["train"]["rowIndices"])
    test = set(manifest["splits"]["test"]["rowIndices"])
    assert train.isdisjoint(test)
    assert len(train) + len(test) == 200
    parsed = pd.to_datetime(frame["ts"], utc=True)
    assert parsed.iloc[sorted(train)].max() <= parsed.iloc[sorted(test)].min()
    boundaries = manifest["timestampBoundaries"]
    first_test_in_time_order = min(test, key=lambda i: parsed.iloc[i])
    assert boundaries["testFirstRaw"] == str(frame["ts"].iloc[first_test_in_time_order])
    assert boundaries["column"] == "ts"
    assert boundaries["trainMax"] <= boundaries["testMin"]
    assert manifest["splits"]["test"]["rows"] == 60


def test_time_ordered_requires_a_parseable_timestamp_column():
    frame = make_frame().drop(columns=["ts"])
    with pytest.raises(ValueError, match="time_ordered strategy requires time_column"):
        ev.split_manifest(frame, strategy="time_ordered", seed=1, label_column="Label")
    missing_column = make_frame().drop(columns=["ts"])
    with pytest.raises(ValueError, match="not found in frame"):
        ev.split_manifest(
            missing_column,
            strategy="time_ordered",
            seed=1,
            label_column="Label",
            time_column="ts",
        )
    broken = make_frame().assign(bad_ts="not-a-date")
    with pytest.raises(ValueError, match="unparseable"):
        ev.split_manifest(
            broken,
            strategy="time_ordered",
            seed=1,
            label_column="Label",
            time_column="bad_ts",
        )


def test_group_holdout_holds_out_whole_groups_and_is_deterministic():
    frame = make_frame()
    first = ev.split_manifest(
        frame,
        strategy="group_holdout",
        seed=5,
        label_column="Label",
        group_column="host",
        normal_labels=["BENIGN"],
    )
    second = ev.split_manifest(
        frame,
        strategy="group_holdout",
        seed=5,
        label_column="Label",
        group_column="host",
        normal_labels=["BENIGN"],
    )
    assert first == second
    held = set(first["heldOutGroups"])
    assert held
    assert first["heldOutGroups"] == sorted(held)
    # no held group row may appear in train
    for position in first["splits"]["train"]["rowIndices"]:
        assert frame["host"].iloc[position] not in held
    for position in first["splits"]["test"]["rowIndices"]:
        assert frame["host"].iloc[position] in held
    assert len(first["splits"]["train"]["rowIndices"]) + len(first["splits"]["test"]["rowIndices"]) == 200
    # every host group is covered by exactly one split
    all_hosts = set(first["splits"]["train"]["rowIndices"]) | set(first["splits"]["test"]["rowIndices"])
    assert all_hosts == set(range(200))


def test_group_holdout_requires_at_least_two_attack_groups():
    frame = make_frame().iloc[:60]  # BENIGN only -> no attack group at all
    with pytest.raises(ValueError, match="at least two groups containing attack rows"):
        ev.split_manifest(
            frame,
            strategy="group_holdout",
            seed=1,
            label_column="Label",
            group_column="host",
            normal_labels=["BENIGN"],
        )
    # one attacker on one host plus benign everywhere else: 1 attack group
    one_attacker = pd.DataFrame(
        [
            {"Label": "BENIGN", "host": "h0"},
            {"Label": "BENIGN", "host": "h1"},
            {"Label": "DDoS", "host": "h1"},
            {"Label": "BENIGN", "host": "h1"},
            {"Label": "BENIGN", "host": "h2"},
        ]
    )
    with pytest.raises(ValueError, match="at least two groups containing attack rows"):
        ev.split_manifest(
            one_attacker,
            strategy="group_holdout",
            seed=1,
            label_column="Label",
            group_column="host",
            normal_labels=["BENIGN"],
        )


def test_family_holdout_removes_whole_families_from_train():
    frame = make_frame()
    family_map = {"BENIGN": "benign", "DDoS": "DoS", "PortScan": "Scan", "WebAttack": "Web"}
    manifest = ev.split_manifest(
        frame,
        strategy="family_holdout",
        seed=9,
        label_column="Label",
        family_map=family_map,
        normal_labels=["BENIGN"],
    )
    held = set(manifest["heldOutFamilies"])
    assert held and held != {"benign"}  # normal family is never held out
    assert manifest["heldOutFamilies"] == sorted(held)
    train_labels = {
        frame["Label"].iloc[position]
        for position in manifest["splits"]["train"]["rowIndices"]
    }
    for label in train_labels:
        assert family_map[label] not in held
    # every held-family row landed in test
    for position in manifest["splits"]["test"]["rowIndices"]:
        assert family_map[frame["Label"].iloc[position]] in held
    # the manifest records the family map and the exact held list
    assert manifest["familyMap"] == dict(sorted(family_map.items()))
    assert manifest["evidence"]["label"] == "unseen_family"


def test_family_holdout_refuses_when_only_one_attack_family_exists():
    frame = pd.DataFrame(
        {"Label": ["BENIGN", "BENIGN", "BENIGN", "DDoS", "DDoS", "BENIGN"]}
    )
    with pytest.raises(ValueError, match="at least two non-normal families"):
        ev.split_manifest(
            frame,
            strategy="family_holdout",
            seed=1,
            label_column="Label",
            normal_labels=["BENIGN"],
        )


def test_split_refuses_missing_label_or_ambiguous_labels():
    frame = make_frame().drop(columns=["Label"])
    with pytest.raises(ValueError, match="not found"):
        ev.split_manifest(frame, strategy="random", seed=1, label_column="Label")
    ambiguous = make_frame().assign(Label=["<NA>"] * 200)
    with pytest.raises(ValueError, match="missing/empty"):
        ev.split_manifest(ambiguous, strategy="random", seed=1, label_column="Label")


# ---------------------------------------------------------------------------
# binary evaluation
# ---------------------------------------------------------------------------
def test_binary_metrics_match_hand_computed_values():
    y_true = [1, 1, 0, 0]
    scores = [0.9, 0.8, 0.3, 0.2]
    result = ev.evaluate_binary_scores(y_true, scores, thresholds=[0.85, 0.5], positive_label=1)
    assert result["counts"] == {"total": 4, "positive": 2, "negative": 2}
    assert result["rocAuc"] == pytest.approx(1.0)
    assert result["prAuc"] == pytest.approx(1.0)
    by_threshold = {row["threshold"]: row for row in result["operatingThresholds"]}
    # threshold 0.5 -> predict [1,1,0,0]
    row = by_threshold[0.5]
    assert (row["tp"], row["fp"], row["tn"], row["fn"]) == (2, 0, 2, 0)
    assert row["precision"] == pytest.approx(1.0)
    assert row["recall"] == pytest.approx(1.0)
    assert row["f1"] == pytest.approx(1.0)
    assert row["fprPerMillion"] == pytest.approx(0.0)
    assert row["confusionMatrix"] == [[2, 0], [0, 2]]
    # threshold 0.85 -> predict [1,0,0,0]
    strict = by_threshold[0.85]
    assert (strict["tp"], strict["fp"], strict["tn"], strict["fn"]) == (1, 0, 2, 1)
    assert strict["precision"] == pytest.approx(1.0)
    assert strict["recall"] == pytest.approx(0.5)
    assert strict["f1"] == pytest.approx(2 * 1.0 * 0.5 / (1.0 + 0.5))
    assert strict["measured"]["precision"] is True
    assert strict["measured"]["f1"] is True


def test_binary_operating_point_at_target_fpr():
    rng = np.random.default_rng(42)
    n = 2000
    y_true = [1] * (n // 2) + [0] * (n // 2)
    scores = [float(0.6 + rng.random() * 0.4) for _ in range(n // 2)] + [
        float(rng.random() * 0.4) for _ in range(n // 2)
    ]
    result = ev.evaluate_binary_scores(y_true, scores, thresholds=[0.5], positive_label=1)
    points = {p["targetFpr"]: p for p in result["targetFprOperatingPoints"]}
    for target in (0.01, 0.001):
        point = points[target]
        assert point["pointMeasured"] is True
        assert point["fprPerMillion"] / 1_000_000 <= target + 1e-6
        assert point["resolutionFloorFpr"] == pytest.approx(1.0 / (n // 2))
    # this synthetic set is cleanly separable, so a finite threshold with fp=0
    # exists and the 1e-4 point is measurable (observed fpr exactly 0) with the
    # resolution floor reported for context.
    below = points[0.0001]
    assert below["pointMeasured"] is True
    assert below["fprPerMillion"] == pytest.approx(0.0)
    assert below["resolutionFloorFpr"] == pytest.approx(1.0 / (n // 2))


def test_binary_operating_picks_best_recall_within_fpr_budget():
    # clean score gap: many thresholds reach fpr=0; the protocol must report the
    # one with the highest recall, not the degenerate never-alert +inf point.
    y_true = [1] * 5 + [0] * 5
    scores = [0.95, 0.93, 0.91, 0.89, 0.87, 0.1, 0.09, 0.08, 0.07, 0.06]
    result = ev.evaluate_binary_scores(y_true, scores, thresholds=[0.5], positive_label=1)
    point = {p["targetFpr"]: p for p in result["targetFprOperatingPoints"]}[0.0001]
    assert point["pointMeasured"] is True
    assert point["threshold"] == pytest.approx(0.87)
    assert point["tp"] == 5 and point["fp"] == 0
    assert point["recall"] == pytest.approx(1.0)
    assert point["fprPerMillion"] == pytest.approx(0.0)


def test_binary_subresolution_fpr_is_not_measured_when_not_separable():
    # interleaved scores: every finite threshold that detects the positive also
    # raises a false positive, and 1/2 negatives = 0.5 > any target FPR.
    y_true = [0, 1, 0]
    scores = [0.1, 0.5, 0.9]
    result = ev.evaluate_binary_scores(y_true, scores, thresholds=[0.5], positive_label=1)
    point = {p["targetFpr"]: p for p in result["targetFprOperatingPoints"]}[0.0001]
    assert point["pointMeasured"] is False
    assert "never-alert" in point["reason"]
    assert point["resolutionFloorFpr"] == pytest.approx(0.5)


def test_binary_single_class_test_is_not_measured_never_zero():
    result = ev.evaluate_binary_scores([0] * 10, [0.1] * 10, thresholds=[0.5], positive_label=1)
    assert result["aucMeasured"] is False
    assert result["rocAuc"] is ev.NOT_MEASURED
    assert result["prAuc"] is ev.NOT_MEASURED
    assert result["notMeasured"], "single-class must carry a reason"
    row = result["operatingThresholds"][0]
    assert row["precision"] is ev.NOT_MEASURED
    assert row["recall"] is ev.NOT_MEASURED
    assert row["f1"] is ev.NOT_MEASURED
    assert row["fprPerMillion"] is ev.NOT_MEASURED
    assert row["measured"]["precision"] is False
    for point in result["targetFprOperatingPoints"]:
        assert point["pointMeasured"] is False
        assert point["reason"]


def test_binary_constant_scores_auc_not_measured():
    result = ev.evaluate_binary_scores([1] * 5 + [0] * 5, [0.7] * 10, thresholds=[0.5])
    assert result["aucMeasured"] is False
    assert result["rocAuc"] is ev.NOT_MEASURED
    assert any(item["metric"] == "roc_auc" for item in result["notMeasured"])


# ---------------------------------------------------------------------------
# multiclass evaluation
# ---------------------------------------------------------------------------
def test_multiclass_per_class_and_unknown_family_recall():
    y_true = ["BENIGN"] * 4 + ["DDoS"] * 4 + ["WebAttack"] * 3 + ["PortScan"] * 3
    y_pred = ["BENIGN"] * 4 + ["DDoS"] * 3 + ["PortScan"] + ["WebAttack"] * 3 + ["WebAttack"] * 3
    result = ev.evaluate_multiclass(
        y_true,
        y_pred,
        normal_labels=["BENIGN"],
        train_classes=["BENIGN", "DDoS"],
    )
    by_label = {row["label"]: row for row in result["perClass"]}
    # DDoS: support 4, tp=3, no fp, fn=1
    ddos = by_label["DDoS"]
    assert ddos["support"] == 4
    assert ddos["recall"] == pytest.approx(0.75)
    assert ddos["precision"] == pytest.approx(1.0)
    # WebAttack: support 3, tp=3, fp=3 (three PortScan rows predicted WebAttack)
    web = by_label["WebAttack"]
    assert web["support"] == 3
    assert web["recall"] == pytest.approx(1.0)
    assert web["precision"] == pytest.approx(0.5)
    # unknown families: WebAttack + PortScan (never in train_classes) -> all flagged malicious
    unknown = result["unknownFamily"]
    assert unknown["measured"] is True
    assert unknown["rows"] == 6
    assert unknown["families"] == ["PortScan", "WebAttack"]
    assert unknown["recall"] == pytest.approx(1.0)
    assert unknown["detectedAsMalicious"] == 6
    # accuracy: 4 + 3 + 3 + 0 = 10 / 14
    assert result["accuracy"] == pytest.approx(10 / 14)


def test_multiclass_never_predicted_class_precision_is_not_measured():
    y_true = ["BENIGN"] * 5 + ["DDoS"] * 5 + ["Rare"] * 5
    y_pred = ["BENIGN"] * 15  # classifier never outputs Rare or DDoS
    result = ev.evaluate_multiclass(y_true, y_pred, normal_labels=["BENIGN"])
    by_label = {row["label"]: row for row in result["perClass"]}
    rare = by_label["Rare"]
    assert rare["support"] == 5
    assert rare["recall"] == pytest.approx(0.0)  # a real measured zero
    assert rare["precision"] is ev.NOT_MEASURED
    assert rare["measured"]["precision"] is False
    assert "never predicted" in rare["reason"]["precision"]
    # macro f1 becomes undefined when a present class has no measured precision
    macro_f1 = result["aggregates"]["macroF1"]
    assert macro_f1["measured"] is False
    assert macro_f1["value"] is ev.NOT_MEASURED


def test_multiclass_unknown_family_requires_train_classes():
    result = ev.evaluate_multiclass(
        ["BENIGN", "DDoS", "BENIGN"],
        ["BENIGN", "DDoS", "DDoS"],
        normal_labels=["BENIGN"],
    )
    assert result["unknownFamily"]["measured"] is False
    assert "train_classes" in result["unknownFamily"]["reason"]


def test_multiclass_refuses_single_class_domain():
    with pytest.raises(ValueError, match="at least two classes"):
        ev.evaluate_multiclass(["BENIGN"] * 3, ["BENIGN"] * 3, normal_labels=["BENIGN"])


# ---------------------------------------------------------------------------
# calibration
# ---------------------------------------------------------------------------
def test_calibration_refuses_single_class_calibration_split():
    with pytest.raises(ValueError, match="single-class"):
        ev.calibrate_scores([1] * 40, [0.6] * 40, method="isotonic")
    with pytest.raises(ValueError, match="single-class"):
        ev.calibrate_scores([0] * 40, [0.4] * 40, method="platt")


def test_calibration_refuses_non_probability_scores():
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        ev.calibrate_scores([0, 1] * 20, [1.5] * 40, method="isotonic")


def _miscalibrated_synthetic() -> tuple[list[int], list[float]]:
    """Model emits identity probabilities while the true process is steeper."""
    rng = np.random.default_rng(123)
    z = rng.uniform(0.0, 1.0, 4000)
    p_true = np.clip(0.5 + 0.9 * (z - 0.5), 0.01, 0.99)
    y = (rng.random(4000) < p_true).astype(int).tolist()
    scores = np.clip(z, 0.01, 0.99).tolist()
    return y, scores


def test_calibration_improves_ece_on_miscalibrated_set():
    y_true, scores = _miscalibrated_synthetic()
    result = ev.calibrate_scores(y_true, scores, method="isotonic", n_bins=10)
    assert result["scope"] == "in_sample"
    assert result["before"]["eceMeasured"] is True
    assert result["after"]["eceMeasured"] is True
    assert result["before"]["brier"] > result["after"]["brier"]
    assert result["before"]["ece"] > result["after"]["ece"]
    assert result["delta"]["eceImproved"] is True
    assert len(result["calibratedScores"]) == len(y_true)
    assert all(0.0 <= value <= 1.0 for value in result["calibratedScores"])


def test_platt_calibration_produces_coefficients_and_valid_scores():
    y_true, scores = _miscalibrated_synthetic()
    result = ev.calibrate_scores(y_true[:1500], scores[:1500], method="platt", n_bins=10)
    assert result["coefficients"]["kind"] == "platt"
    assert isinstance(result["coefficients"]["slope"], float)
    assert isinstance(result["coefficients"]["intercept"], float)
    assert all(0.0 <= value <= 1.0 for value in result["calibratedScores"])
    assert result["before"]["eceMeasured"] is True


def test_calibration_holdout_scope_is_honest():
    y_fit, scores_fit = _miscalibrated_synthetic()
    # a held-out evaluation set drawn from the same distribution
    result = ev.calibrate_scores(
        y_fit[:2000],
        scores_fit[:2000],
        method="isotonic",
        y_evaluation=y_fit[2000:],
        scores_evaluation=scores_fit[2000:],
    )
    assert result["scope"] == "holdout"
    assert result["calibrationRows"] == 2000
    assert result["evaluationRows"] == 2000
    assert "before" in result and "after" in result


# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------
def test_drift_identical_vs_shifted_distributions():
    rng = np.random.default_rng(5)
    reference = np.column_stack(
        [rng.normal(0.0, 1.0, 1000), rng.normal(0.0, 1.0, 1000)]
    )
    current_same = np.column_stack(
        [rng.normal(0.0, 1.0, 1000), rng.normal(0.0, 1.0, 1000)]
    )
    current_shifted = np.column_stack(
        [rng.normal(2.0, 1.0, 1000), rng.normal(-2.0, 1.0, 1000)]
    )
    same = ev.drift_report(reference, current_same, feature_names=["a", "b"])
    shifted = ev.drift_report(reference, current_shifted, feature_names=["a", "b"])
    assert [entry["status"] for entry in same["features"]] == ["ok", "ok"]
    assert [entry["status"] for entry in shifted["features"]] == ["drift", "drift"]
    for entry in same["features"]:
        assert entry["psiMeasured"] is True
        assert entry["ks"]["measured"] is True
        assert entry["psi"] < 0.10
        assert entry["ks"]["statistic"] < 0.10
    shifted_psi = [entry["psi"] for entry in shifted["features"]]
    assert all(value >= 0.25 for value in shifted_psi)
    assert shifted["population"]["statusCounts"]["drift"] == 2


def test_drift_empty_inputs_are_not_measured():
    empty = np.empty((0, 2))
    rng = np.random.default_rng(3)
    current = np.column_stack([rng.normal(0, 1, 200), rng.normal(0, 1, 200)])
    report = ev.drift_report(empty, current, feature_names=["a", "b"])
    for entry in report["features"]:
        assert entry["status"] == "not_measured"
        assert entry["psi"] is ev.NOT_MEASURED
        assert entry["reference"]["rows"] == 0
        assert entry["reason"]
    assert report["population"]["measured"] == 0
    assert report["population"]["referenceRows"] == 0


def test_drift_rejects_nan_input():
    reference = np.array([[1.0, np.nan], [2.0, 3.0]])
    with pytest.raises(ValueError, match="NaN/Inf"):
        ev.drift_report(reference, np.zeros((2, 2)), feature_names=["a", "b"])


# ---------------------------------------------------------------------------
# markdown rendering
# ---------------------------------------------------------------------------
def _report_fixture_with_unmeasured() -> dict:
    return {
        "protocolVersion": ev.PROTOCOL_VERSION,
        "generatedAtUtc": "2026-09-15T00:00:00+00:00",
        "command": "python scripts/evaluate_model_splits.py",
        "dataset": {
            "path": "/data/real.csv.gz",
            "sha256": "abc123",
            "labelColumn": "Label",
            "normalLabels": ["BENIGN"],
            "timeColumn": "ts",
            "groupColumn": "host",
            "labelDistribution": {"BENIGN": 100, "DDoS": 50},
            "sampling": {"maxRows": 0, "method": "every row", "seed": 1},
        },
        "runtime": {
            "python": "3.11.1",
            "platform": "Windows",
            "machine": "AMD64",
            "processor": "x",
            "cpuCount": 8,
            "hostname": "host",
            "versions": {"numpy": "2.4.6", "sklearn": "1.9.0"},
        },
        "models": [
            {
                "id": "m1",
                "name": "Model",
                "task": "known_attack_classification_baseline",
                "algorithm": "hist_gradient_boosting",
                "trainedOnWholeDataset": True,
                "artifact": {"path": "model.joblib", "sha256": "sha", "provenance": {}},
                "strategies": [
                    {
                        "strategy": "random",
                        "evidence": ev.STRATEGY_EVIDENCE["random"],
                        "manifest": {
                            "strategy": "random",
                            "seed": 1,
                            "datasetSha256": "abc123",
                            "rowsTotal": 150,
                            "splits": {
                                "train": {"rows": 100, "rowIndices": list(range(100)),
                                          "classCounts": {"BENIGN": 70, "DDoS": 30}},
                                "test": {"rows": 50, "rowIndices": list(range(100, 150)),
                                         "classCounts": {"BENIGN": 30, "DDoS": 20}},
                            },
                        },
                        "overlap": {"risk": "high", "basis": "in-sample"},
                        "evaluation": {
                            "kind": "multiclass",
                            "rows": 50,
                            "accuracy": 0.9,
                            "perClass": [
                                {
                                    "label": "BENIGN",
                                    "support": 30,
                                    "precision": 0.9,
                                    "recall": 1.0,
                                    "f1": 0.947,
                                    "measured": {"precision": True, "recall": True, "f1": True},
                                },
                                {
                                    "label": "DDoS",
                                    "support": 20,
                                    "precision": ev.NOT_MEASURED,
                                    "recall": ev.NOT_MEASURED,
                                    "f1": ev.NOT_MEASURED,
                                    "measured": {"precision": False, "recall": False, "f1": False},
                                },
                            ],
                            "aggregates": {
                                "macroF1": {
                                    "value": ev.NOT_MEASURED,
                                    "measured": False,
                                    "reason": "not all classes have measured values",
                                }
                            },
                            "unknownFamily": {
                                "rows": 0,
                                "families": [],
                                "recall": ev.NOT_MEASURED,
                                "detectedAsMalicious": 0,
                                "measured": False,
                                "reason": "train_classes not provided",
                            },
                        },
                    }
                ],
            }
        ],
    }


def test_markdown_render_is_deterministic_and_marks_unmeasured():
    report = _report_fixture_with_unmeasured()
    first = ev.render_report_markdown(report)
    second = ev.render_report_markdown(report)
    assert first == second
    assert "未测量" in first
    # the exact split manifest is included: sha256, seed, row counts, labels
    assert "abc123" in first
    assert "datasetSha256" in first
    assert "BENIGN" in first
    assert "DDoS" in first
    assert "hist_gradient_boosting" in first


def test_markdown_renders_binary_unmeasured_cells():
    report = _report_fixture_with_unmeasured()
    report["models"][0]["strategies"][0]["evaluation"] = {
        "kind": "binary",
        "positiveLabel": "1",
        "counts": {"total": 10, "positive": 0, "negative": 10},
        "scoreSummary": {"min": 0.1, "max": 0.1, "unique": 1},
        "rocAuc": ev.NOT_MEASURED,
        "prAuc": ev.NOT_MEASURED,
        "aucMeasured": False,
        "notMeasured": [{"metric": "roc_auc", "reason": "no positive rows"}],
        "operatingThresholds": [
            {
                "threshold": 0.5,
                "precision": ev.NOT_MEASURED,
                "recall": ev.NOT_MEASURED,
                "f1": ev.NOT_MEASURED,
            }
        ],
        "targetFprOperatingPoints": [
            {"targetFpr": 0.01, "pointMeasured": False, "reason": "no positive rows"}
        ],
    }
    rendered = ev.render_report_markdown(report)
    assert "未测量" in rendered
    assert "no positive rows" in rendered
