"""EvoNIDS model evaluation protocol (pure, side-effect-free metrics).

This module implements the mandatory evaluation protocol that must back every
"production evidence" claim about a trained model (see
docs/adr/0009-model-evaluation-protocol.md).  The guiding rule is: **never
fabricate a number**.  Any metric that is undefined for the given data (for
example precision on a test set that never predicted the class, or any AUC when
the test set is single-class) is stored as ``None`` (the ``NOT_MEASURED``
sentinel) together with an explicit ``measured: False`` marker and a human
readable ``reason``.  A real measured zero is stored as ``0.0`` — the two are
never confused.

Every function in this module is pure: it only reads its arguments and returns
a JSON-serialisable structure (``dict[str, Any]`` with plain Python scalars and
lists).  No filesystem, network, database or clock access happens here.  Heavy
libraries (numpy / pandas / sklearn / scipy) are imported lazily inside each
function so that importing this module stays cheap.

Strategies (evidence strength, weakest first):

* ``random`` — same-distribution random split.  **Weakest evidence**: it cannot
  distinguish "the model memorised the dataset" from "the model generalises",
  and temporally adjacent near-duplicates can sit on both sides of the split.
* ``time_ordered`` — earliest rows (by a timestamp column) are the train split,
  latest rows the test split.  Measures temporal generalisation inside the same
  capture distribution.
* ``group_holdout`` — whole source-IP / host groups are held out of training.
  Measures host-level generalisation.
* ``family_holdout`` — whole attack families / labels are held out of training.
  Measures unseen-family generalisation.  A classifier that never saw a family
  cannot *name* it, so the family-level metric reported here is the share of
  unseen-family flows the model still flags as malicious (i.e. does not dump
  into the normal bucket).

Drift thresholds (documented, effect-size based — deliberately not
p-value-only because with millions of rows any tiny shift becomes
"significant"):

* PSI: ``< 0.10`` ok, ``0.10 .. 0.25`` warn, ``>= 0.25`` drift.
* KS (two-sample D statistic): ``< 0.10`` ok, ``0.10 .. 0.20`` warn,
  ``>= 0.20`` drift.  The exact p-value is reported informationally when scipy
  is available.
"""

from __future__ import annotations

import math
from typing import Any, Iterable, Sequence

# JSON-safe sentinel used for every undefined metric.  Never 0.0, never a
# guessed number: ``None`` renders as 未测量 in Markdown reports.
NOT_MEASURED = None

PROTOCOL_VERSION = "evonids-model-evaluation-v1"

STRATEGIES: tuple[str, ...] = ("random", "time_ordered", "group_holdout", "family_holdout")

# evidence strength metadata, rank 1 = weakest
STRATEGY_EVIDENCE: dict[str, dict[str, Any]] = {
    "random": {
        "rank": 1,
        "label": "weakest",
        "note": (
            "Same-distribution random split: weakest evidence. Cannot separate memorisation from "
            "generalisation and may put temporally adjacent near-duplicate rows on both sides."
        ),
    },
    "time_ordered": {
        "rank": 2,
        "label": "temporal",
        "note": (
            "Temporal holdout inside the same capture distribution: train rows are earlier than "
            "test rows, so the test set was never observable at training time."
        ),
    },
    "group_holdout": {
        "rank": 3,
        "label": "host",
        "note": "Whole source-IP/host groups are held out: measures host-level generalisation.",
    },
    "family_holdout": {
        "rank": 4,
        "label": "unseen_family",
        "note": (
            "Whole attack families/labels are held out: measures unseen-family generalisation. "
            "Reported family metric is the share of unseen-family flows still flagged as malicious."
        ),
    },
}

# target false-positive-rates for the operating-point table of binary scores
DEFAULT_TARGET_FPRS: tuple[float, ...] = (0.01, 0.001, 0.0001)

# drift thresholds (documented constants, see module docstring)
PSI_WARN = 0.10
PSI_DRIFT = 0.25
KS_WARN = 0.10
KS_DRIFT = 0.20
PSI_BINS = 10
PSI_EPSILON = 1e-6

DEFAULT_TEST_RATIO = 0.3


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def is_not_measured(value: Any) -> bool:
    """True when *value* is the ``NOT_MEASURED`` sentinel (an undefined metric)."""
    return value is None


def _as_float_list(values: Sequence[float] | Iterable[float], *, name: str) -> list[float]:
    result: list[float] = []
    for value in values:
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            raise ValueError(f"{name} contains NaN/Inf; refuse to compute on invalid input")
        result.append(number)
    return result


def _as_str_list(values: Sequence[Any], *, name: str) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in {"<missing>", "<NA>", "nan", "None"}:
            raise ValueError(f"{name} contains an empty/missing label; refuse to compute on invalid input")
        result.append(text)
    return result


def _counts_by_key(values: Sequence[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items()))


def _round_ratio(numerator: int, denominator: int) -> float | None:
    """Real ratio or NOT_MEASURED when the denominator is zero."""
    if denominator <= 0:
        return NOT_MEASURED
    return float(numerator / denominator)


def _score_binary_operating(
    actual: Any, scores: Any, *, threshold: float, positive: int = 1
) -> dict[str, Any]:
    import numpy as np

    predicted = np.asarray(scores) >= threshold
    y = np.asarray(actual)
    tp = int(np.logical_and(y == positive, predicted).sum())
    tn = int(np.logical_and(y != positive, ~predicted).sum())
    fp = int(np.logical_and(y != positive, predicted).sum())
    fn = int(np.logical_and(y == positive, ~predicted).sum())
    precision = _round_ratio(tp, tp + fp)
    recall = _round_ratio(tp, tp + fn)
    f1: float | None = NOT_MEASURED
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = float(2 * precision * recall / (precision + recall))
    fpr_per_million = _round_ratio(fp, fp + tn)
    if fpr_per_million is not None:
        fpr_per_million = float(fpr_per_million) * 1_000_000.0
    return {
        "threshold": float(threshold),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fprPerMillion": fpr_per_million,
        "confusionMatrix": [[tn, fp], [fn, tp]],
        "measured": {
            "precision": precision is not None,
            "recall": recall is not None,
            "f1": f1 is not None,
            "fprPerMillion": fpr_per_million is not None,
        },
    }


# ---------------------------------------------------------------------------
# dataset split protocol
# ---------------------------------------------------------------------------
def split_manifest(
    frame: Any,
    *,
    strategy: str,
    seed: int,
    label_column: str,
    test_ratio: float = DEFAULT_TEST_RATIO,
    time_column: str | None = None,
    group_column: str | None = None,
    family_map: dict[str, str] | None = None,
    normal_labels: Sequence[str] | None = None,
    dataset_sha256: str | None = None,
    include_row_indices: bool = True,
) -> dict[str, Any]:
    """Deterministically split ``frame`` (a pandas DataFrame) into train/test.

    Returns an explicit, JSON-serialisable manifest: strategy, seed, evidence
    strength, per-split row counts, per-split per-class counts, the exact held
    out group/family lists, exact timestamp boundaries, and the dataset sha256
    it was computed from (when provided).
    """
    if strategy not in STRATEGIES:
        raise ValueError(f"Unknown strategy {strategy!r}; expected one of {STRATEGIES}")
    if not 0.0 < test_ratio < 1.0:
        raise ValueError("test_ratio must be strictly between 0 and 1")
    if frame is None or getattr(frame, "shape", (0,))[0] == 0:
        raise ValueError("split_manifest requires a non-empty frame")
    if label_column not in frame.columns:
        raise ValueError(f"Label column {label_column!r} not found in frame")
    if int(seed) < 0:
        raise ValueError("seed must be a non-negative integer")
    seed = int(seed)

    import numpy as np
    import pandas as pd

    total = int(len(frame))
    labels = frame[label_column].astype("string").str.strip().astype(str).tolist()
    missing_labels = sorted(
        {label for label in labels if label in {"", "<NA>", "<missing>", "nan", "None"}}
    )
    if missing_labels:
        raise ValueError(
            f"Label column {label_column!r} contains {len(missing_labels)} missing/empty values "
            f"(e.g. {missing_labels[0]!r}); refuse to split on an ambiguous label"
        )
    normal_set = {str(value).strip() for value in (normal_labels or [])}
    test_count = max(1, min(total - 1, int(round(total * test_ratio))))

    manifest: dict[str, Any] = {
        "protocolVersion": PROTOCOL_VERSION,
        "strategy": strategy,
        "seed": seed,
        "evidence": dict(STRATEGY_EVIDENCE[strategy]),
        "datasetSha256": dataset_sha256,
        "rowsTotal": total,
        "testRatioTarget": float(test_ratio),
        "rowIndicesIncluded": bool(include_row_indices),
        "splits": {},
        "heldOutGroups": None,
        "heldOutFamilies": None,
        "familyMap": None,
        "timestampBoundaries": None,
        "splitRule": None,
    }

    all_indices = np.arange(total, dtype=np.int64)
    if strategy == "random":
        rng = np.random.default_rng(seed)
        shuffled = rng.permutation(all_indices)
        test_positions = set(int(value) for value in shuffled[:test_count])
        train_positions = [int(value) for value in all_indices if int(value) not in test_positions]
        test_list = sorted(test_positions)
        manifest["splitRule"] = (
            "seeded uniform shuffle, then the first ~test_ratio rows become the test split "
            "(listed in row order). Weakest evidence."
        )
    elif strategy == "time_ordered":
        if not time_column:
            raise ValueError("time_ordered strategy requires time_column")
        if time_column not in frame.columns:
            raise ValueError(f"Time column {time_column!r} not found in frame")
        parsed = pd.to_datetime(frame[time_column], utc=True, errors="coerce")
        if int(parsed.isna().sum()) > 0:
            raise ValueError(
                f"Time column {time_column!r} has {int(parsed.isna().sum())} unparseable/missing "
                "values; refuse to compute a time-ordered split"
            )
        time_ns = parsed.astype("int64").to_numpy()
        order = np.lexsort((all_indices, time_ns))
        boundary = total - test_count  # first test position in time order
        train_time_sorted = order[:boundary]
        test_time_sorted = order[boundary:]
        train_positions = sorted(int(value) for value in train_time_sorted)
        test_list = sorted(int(value) for value in test_time_sorted)
        pos_train_last = int(train_time_sorted[-1])
        pos_test_first = int(test_time_sorted[0])
        raw = frame[time_column]
        train_min = parsed.iloc[train_time_sorted[0]]
        train_max = parsed.iloc[pos_train_last]
        test_min = parsed.iloc[pos_test_first]
        test_max = parsed.iloc[test_time_sorted[-1]]
        manifest["timestampBoundaries"] = {
            "column": time_column,
            "normalisation": "pandas to_datetime(utc=True); raw values preserved below",
            "trainMin": train_min.isoformat(),
            "trainMax": train_max.isoformat(),
            "testMin": test_min.isoformat(),
            "testMax": test_max.isoformat(),
            "trainLastRaw": str(raw.iloc[pos_train_last]),
            "testFirstRaw": str(raw.iloc[pos_test_first]),
            "tiesAcrossBoundary": str(raw.iloc[pos_train_last]) == str(raw.iloc[pos_test_first]),
        }
        manifest["splitRule"] = (
            "rows sorted by timestamp ascending; the latest ~test_ratio rows form the test split, "
            "so every test row is at or after the newest train row."
        )
    elif strategy == "group_holdout":
        if not group_column:
            raise ValueError("group_holdout strategy requires group_column")
        if group_column not in frame.columns:
            raise ValueError(f"Group column {group_column!r} not found in frame")
        groups = frame[group_column].astype("string").str.strip()
        if int(groups.isna().sum()) > 0 or int((groups == "").sum()) > 0:
            raise ValueError(f"Group column {group_column!r} contains missing values; refuse to split")
        group_list = groups.astype(str).tolist()
        group_of: dict[int, str] = {}
        for position, value in enumerate(group_list):
            group_of[position] = value
        row_is_attack = [labels[position] not in normal_set for position in range(total)]
        # candidate groups must contain at least one attack row so the hold-out
        # actually tests unseen malicious hosts rather than pure-benign hosts.
        has_attack: dict[str, bool] = {}
        group_rows: dict[str, list[int]] = {}
        for position, value in group_of.items():
            group_rows.setdefault(value, []).append(position)
            if row_is_attack[position]:
                has_attack[value] = True
        candidates = sorted(
            (value for value, flagged in has_attack.items() if flagged),
            key=lambda key: (len(group_rows[key]), key),
        )
        if len(candidates) < 2:
            raise ValueError(
                "group_holdout requires at least two groups containing attack rows "
                f"(found {len(candidates)})"
            )
        target_rows = max(1, int(round(total * test_ratio)))
        held_groups: list[str] = []
        held_positions: set[int] = set()
        index = 0
        while index < len(candidates) and len(held_positions) < target_rows:
            remaining_candidates = [key for key in candidates if key not in held_groups]
            if len(remaining_candidates) <= 1:  # leave at least one group for training
                break
            held_groups.append(candidates[index])
            held_positions.update(group_rows[candidates[index]])
            index += 1
        if not held_groups:
            raise ValueError("group_holdout failed to select any held-out group")
        test_list = sorted(held_positions)
        train_positions = sorted(set(range(total)) - held_positions)
        manifest["heldOutGroups"] = sorted(held_groups)
        manifest["splitRule"] = (
            "attack-bearing groups held out smallest-first (by row count, then key) until the test "
            f"split reached its ~{test_ratio:.0%} target; at least one group always remains in train."
        )
    elif strategy == "family_holdout":
        mapping = {str(key).strip(): str(value).strip() for key, value in (family_map or {}).items()}
        attack_labels = sorted(label for label in set(labels) if label not in normal_set)
        if not attack_labels:
            raise ValueError("family_holdout requires at least one non-normal label")
        label_of_row: list[str] = []
        for label in labels:
            family = mapping.get(label, label)
            label_of_row.append(family)
        families = sorted(set(label_of_row))
        # normal families are never held out: benign must stay observable in train
        candidates = sorted(
            (family for family in families if family not in {mapping.get(label, label) for label in normal_set}),
            key=lambda key: (sum(1 for f in label_of_row if f == key), key),
        )
        if not candidates:
            raise ValueError("family_holdout requires at least one non-normal family")
        if len(candidates) < 2:
            raise ValueError(
                "family_holdout requires at least two non-normal families "
                f"(found {len(candidates)}); holding out the only attack family leaves a "
                "single-class train split"
            )
        family_rows: dict[str, list[int]] = {}
        for position, family in enumerate(label_of_row):
            family_rows.setdefault(family, []).append(position)
        # how many distinct labels remain in train after holding a family out
        labels_in_family: dict[str, set[str]] = {}
        for position, family in enumerate(label_of_row):
            labels_in_family.setdefault(family, set()).add(labels[position])
        all_labels = set(labels)
        target_rows = max(1, int(round(total * test_ratio)))
        held_families: list[str] = []
        held_family_positions: set[int] = set()
        remaining_labels = set(all_labels)
        index = 0
        while index < len(candidates) and len(held_family_positions) < target_rows:
            family = candidates[index]
            remaining_labels_after = remaining_labels - labels_in_family[family]
            if len(remaining_labels_after) < 2:  # training needs >= 2 classes
                break
            held_families.append(family)
            held_family_positions.update(family_rows[family])
            remaining_labels = remaining_labels_after
            index += 1
        if not held_families:
            raise ValueError("family_holdout failed to select any held-out family")
        test_list = sorted(held_family_positions)
        train_positions = sorted(set(range(total)) - held_family_positions)
        manifest["heldOutFamilies"] = sorted(held_families)
        manifest["familyMap"] = dict(sorted(mapping.items()))
        manifest["splitRule"] = (
            "non-normal families held out smallest-first (by row count, then key) until the test "
            f"split reached its ~{test_ratio:.0%} target; training always keeps at least two classes."
        )
    else:  # pragma: no cover - guarded above
        raise AssertionError(f"unreachable strategy {strategy}")

    def split_block(positions: Sequence[int]) -> dict[str, Any]:
        split_labels = [labels[position] for position in positions]
        block: dict[str, Any] = {
            "rows": len(positions),
            "classCounts": _counts_by_key(split_labels),
        }
        if include_row_indices:
            block["rowIndices"] = [int(position) for position in positions]
        else:
            block["rowIndicesOmitted"] = True
        return block

    manifest["splits"] = {
        "train": split_block(train_positions),
        "test": split_block(test_list),
    }
    # integrity: rows partition exactly once
    assert len(train_positions) + len(test_list) == total
    assert len(set(train_positions) & set(test_list)) == 0
    return manifest


# ---------------------------------------------------------------------------
# binary evaluation
# ---------------------------------------------------------------------------
def evaluate_binary_scores(
    y_true: Sequence[Any],
    scores: Sequence[float],
    *,
    thresholds: Sequence[float],
    positive_label: Any = 1,
    target_fprs: Sequence[float] = DEFAULT_TARGET_FPRS,
) -> dict[str, Any]:
    """Evaluate binary scores (higher = more likely *positive*).

    Every value that is undefined (single-class test set, constant scores, no
    threshold reaching a target FPR) is ``None`` with an explicit reason; it is
    never coerced to 0.0.
    """
    labels = list(y_true)
    score_values = _as_float_list(scores, name="scores")
    if len(labels) != len(score_values):
        raise ValueError("y_true and scores must have the same length")
    if not labels:
        raise ValueError("evaluate_binary_scores requires at least one labelled row")
    threshold_values = _as_float_list(thresholds, name="thresholds")
    if not threshold_values:
        raise ValueError("evaluate_binary_scores requires at least one operating threshold")
    target_list = _as_float_list(target_fprs, name="target_fprs")
    for fpr in target_list:
        if not 0.0 < fpr < 1.0:
            raise ValueError("target_fprs values must be in (0, 1)")

    import numpy as np

    y = np.asarray([1 if value == positive_label else 0 for value in labels], dtype=np.int64)
    scores_arr = np.asarray(score_values, dtype=np.float64)
    n_positive = int((y == 1).sum())
    n_negative = int((y == 0).sum())
    unique_scores = int(np.unique(scores_arr).size)

    reasons: dict[str, str] = {}
    measured = n_positive > 0 and n_negative > 0
    if n_positive == 0:
        reasons["positiveClassAbsent"] = f"no row equals positive_label {positive_label!r}"
    if n_negative == 0:
        reasons["negativeClassAbsent"] = "no negative row present (single-class test set)"
    if measured and unique_scores < 2:
        reasons["constantScores"] = "scores are constant; no threshold can separate classes"

    roc_auc: float | None = NOT_MEASURED
    pr_auc: float | None = NOT_MEASURED
    if measured and unique_scores >= 2:
        from sklearn.metrics import average_precision_score, roc_auc_score

        roc_auc = float(roc_auc_score(y, scores_arr))
        pr_auc = float(average_precision_score(y, scores_arr))

    # one row per requested operating threshold, sorted most-permissive first
    ordered_thresholds = sorted(set(threshold_values), reverse=True)
    if measured:
        operating_rows = [_score_binary_operating(y, scores_arr, threshold=value) for value in ordered_thresholds]
    else:
        # single-class test set: no decision metric may pretend to be defined
        single_reason = next(iter(reasons.values()), "not measurable on this data")
        operating_rows = [
            {
                "threshold": value,
                "tp": NOT_MEASURED,
                "fp": NOT_MEASURED,
                "tn": NOT_MEASURED,
                "fn": NOT_MEASURED,
                "precision": NOT_MEASURED,
                "recall": NOT_MEASURED,
                "f1": NOT_MEASURED,
                "fprPerMillion": NOT_MEASURED,
                "confusionMatrix": NOT_MEASURED,
                "measured": {
                    "precision": False,
                    "recall": False,
                    "f1": False,
                    "fprPerMillion": False,
                },
                "reason": single_reason,
            }
            for value in ordered_thresholds
        ]

    operating_points: list[dict[str, Any]] = []
    if measured and unique_scores >= 2:
        from sklearn.metrics import roc_curve

        fpr, tpr, thresholds = roc_curve(y, scores_arr, pos_label=1)
        floor = 1.0 / n_negative
        for target in target_list:
            best: tuple[tuple[float, float], int] | None = None  # ((tpr, -fpr), index)
            # index 0 of roc_curve is the +inf threshold (flag nothing: fpr=0,
            # tpr=0). It is a degenerate operating point and must never be
            # reported as a real threshold.
            for index, achieved in enumerate(fpr):
                if index == 0:
                    continue
                if not np.isfinite(thresholds[index]):
                    continue
                if achieved <= target + 1e-12:
                    candidate = (float(tpr[index]), -float(achieved))
                    if best is None or candidate > best[0]:
                        best = (candidate, index)
            if best is None:
                operating_points.append(
                    {
                        "targetFpr": target,
                        "pointMeasured": False,
                        "reason": (
                            f"no finite threshold with any true detection reaches fpr <= {target}; "
                            f"the only qualifying point is the degenerate never-alert threshold "
                            f"(fpr=0, recall=0). Sample resolution floor is {floor:.2e} "
                            f"(1/n_negative)."
                        ),
                        "resolutionFloorFpr": floor,
                    }
                )
                continue
            # among qualifying thresholds report the one with the highest recall
            # (ties broken toward the lower achieved fpr)
            row = _score_binary_operating(y, scores_arr, threshold=float(thresholds[best[1]]))
            row["targetFpr"] = target
            row["resolutionFloorFpr"] = floor
            row["pointMeasured"] = True
            operating_points.append(row)
    else:
        for target in target_list:
            operating_points.append(
                {
                    "targetFpr": target,
                    "pointMeasured": False,
                    "reason": next(iter(reasons.values()), "not measurable on this data"),
                    "resolutionFloorFpr": 1.0 / n_negative if n_negative else None,
                }
            )

    not_measured: list[dict[str, str]] = [
        {"metric": "roc_auc", "reason": reason} for reason in reasons.values()
    ]
    return {
        "kind": "binary",
        "positiveLabel": str(positive_label),
        "counts": {"total": int(len(y)), "positive": n_positive, "negative": n_negative},
        "scoreSummary": {
            "min": float(scores_arr.min()),
            "max": float(scores_arr.max()),
            "unique": unique_scores,
        },
        "rocAuc": roc_auc,
        "prAuc": pr_auc,
        "aucMeasured": measured and unique_scores >= 2,
        "operatingThresholds": operating_rows,
        "targetFprOperatingPoints": operating_points,
        "notMeasured": not_measured,
    }


# ---------------------------------------------------------------------------
# multiclass evaluation
# ---------------------------------------------------------------------------
def evaluate_multiclass(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    *,
    normal_labels: Sequence[str] | None = None,
    train_classes: Sequence[str] | None = None,
    labels: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Evaluate a multiclass prediction against ground truth.

    Per-class precision/recall/F1/support, macro and support-weighted
    aggregates, the confusion matrix, and unknown-family recall (the share of
    rows whose true class was never seen in training that the model still flags
    as malicious).  Every field carries an explicit ``measured`` marker and
    undefined values are the ``NOT_MEASURED`` sentinel.
    """
    truth = _as_str_list(y_true, name="y_true")
    predicted = _as_str_list(y_pred, name="y_pred")
    if len(truth) != len(predicted):
        raise ValueError("y_true and y_pred must have the same length")
    if not truth:
        raise ValueError("evaluate_multiclass requires at least one labelled row")
    normal_set = {str(value).strip() for value in (normal_labels or [])}
    known_classes = {str(value).strip() for value in (train_classes or [])}
    if labels is not None:
        domain = sorted({str(value).strip() for value in labels})
    else:
        domain = sorted(set(truth) | set(predicted))
    if len(domain) < 2:
        raise ValueError("evaluate_multiclass requires at least two classes in the evaluation domain")

    import numpy as np
    from sklearn.metrics import confusion_matrix

    matrix = confusion_matrix(truth, predicted, labels=domain).astype(np.int64)
    support = matrix.sum(axis=1).tolist()

    per_class: list[dict[str, Any]] = []
    for index, label in enumerate(domain):
        tp = int(matrix[index, index])
        fn = int(matrix[index, :].sum() - tp)
        present = support[index] > 0
        predicted_count = int(matrix[:, index].sum())
        precision: float | None = NOT_MEASURED
        recall: float | None = NOT_MEASURED
        f1: float | None = NOT_MEASURED
        precision_reason = recall_reason = f1_reason = None
        if present:
            recall = _round_ratio(tp, tp + fn)
            if predicted_count > 0:
                precision = _round_ratio(tp, predicted_count)
            else:
                precision_reason = "class present in test but never predicted; precision undefined"
            if precision is not None and recall is not None and (precision + recall) > 0:
                f1 = float(2 * precision * recall / (precision + recall))
            else:
                f1_reason = "requires both measured precision and recall"
        else:
            recall_reason = "class absent from the evaluation (test) rows"
        per_class.append(
            {
                "label": label,
                "support": int(support[index]),
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "measured": {
                    "precision": precision is not None,
                    "recall": recall is not None,
                    "f1": f1 is not None,
                },
                "reason": {
                    "precision": precision_reason,
                    "recall": recall_reason,
                    "f1": f1_reason,
                },
            }
        )

    present_classes = [row for row in per_class if row["support"] > 0]
    present_count = len(present_classes)

    def aggregate(field: str, weighted: bool) -> dict[str, Any]:
        measured_rows = [row for row in present_classes if row[field] is not None]
        measured_count = len(measured_rows)
        if measured_count == 0 or measured_count < present_count:
            return {
                "value": NOT_MEASURED,
                "measured": False,
                "measuredClasses": measured_count,
                "totalClasses": present_count,
                "reason": "not all classes present in the test set have a measured value",
            }
        if weighted:
            total_support = sum(int(row["support"]) for row in measured_rows)
            value = float(
                sum(float(row[field]) * int(row["support"]) for row in measured_rows) / total_support
            )
        else:
            value = float(sum(float(row[field]) for row in measured_rows) / measured_count)
        return {
            "value": value,
            "measured": True,
            "measuredClasses": measured_count,
            "totalClasses": present_count,
        }

    correct = sum(1 for true, pred in zip(truth, predicted, strict=True) if true == pred)
    accuracy = float(correct / len(truth))

    # unknown-family recall: rows whose true class was never in train_classes
    # and is not a normal label; detection = prediction outside the normal set.
    # Only measurable when the caller states what the model actually saw in
    # training (train_classes); without that information nothing may be claimed.
    unknown_measurable = train_classes is not None
    unknown_labels = sorted(
        {
            value
            for value in set(truth)
            if value not in known_classes and value not in normal_set
        }
    )
    unknown_recall: float | None = NOT_MEASURED
    unknown_measured = unknown_measurable and bool(unknown_labels)
    unknown_rows = [index for index, value in enumerate(truth) if value in set(unknown_labels)]
    detected = 0
    if unknown_rows:
        detected = sum(1 for index in unknown_rows if predicted[index] not in normal_set)
        unknown_recall = float(detected / len(unknown_rows))
    per_family_rows: list[dict[str, Any]] = []
    if unknown_measured:
        predicted_counters: dict[str, dict[str, int]] = {}
        for index in unknown_rows:
            label = truth[index]
            pred = predicted[index]
            counter = predicted_counters.setdefault(label, {})
            counter[pred] = counter.get(pred, 0) + 1
        for label in unknown_labels:
            rows = [index for index, value in enumerate(truth) if value == label]
            if not rows:
                continue
            family_detected = sum(1 for index in rows if predicted[index] not in normal_set)
            per_family_rows.append(
                {
                    "label": label,
                    "rows": len(rows),
                    "detectedAsMalicious": family_detected,
                    "recall": float(family_detected / len(rows)),
                    "predictedDistribution": dict(
                        sorted(predicted_counters.get(label, {}).items(), key=lambda item: -item[1])
                    ),
                }
            )
        per_family_rows.sort(key=lambda row: (-row["rows"], row["label"]))

    return {
        "kind": "multiclass",
        "rows": int(len(truth)),
        "labels": domain,
        "accuracy": accuracy,
        "accuracyMeasured": True,
        "perClass": per_class,
        "aggregates": {
            "macroPrecision": aggregate("precision", weighted=False),
            "macroRecall": aggregate("recall", weighted=False),
            "macroF1": aggregate("f1", weighted=False),
            "weightedF1": aggregate("f1", weighted=True),
        },
        "confusionMatrix": matrix.astype(int).tolist(),
        "confusionLabels": domain,
        "unknownFamily": {
            "rows": len(unknown_rows),
            "families": unknown_labels,
            "recall": unknown_recall,
            "detectedAsMalicious": detected,
            "measured": unknown_measured,
            "reason": (
                None
                if unknown_measured
                else (
                    "train_classes not provided; cannot state which families the model saw in training"
                    if not unknown_measurable
                    else "no unknown-family rows (every test class was seen in train_classes or is a normal label)"
                )
            ),
            "basis": "detection = prediction outside normal_labels",
            "normalLabels": sorted(normal_set),
            "perFamily": per_family_rows,
        },
        "normalLabels": sorted(normal_set),
    }


# ---------------------------------------------------------------------------
# probability calibration
# ---------------------------------------------------------------------------
def calibrate_scores(
    y_calibration: Sequence[int],
    scores_calibration: Sequence[float],
    *,
    method: str,
    n_bins: int = 10,
    y_evaluation: Sequence[int] | None = None,
    scores_evaluation: Sequence[float] | None = None,
) -> dict[str, Any]:
    """Fit isotonic or Platt (sigmoid/logistic) calibration and quantify it.

    Raises a clear ``ValueError`` when the calibration split is single-class
    (no honest calibration is possible) or when scores are not
    probability-like values in ``[0, 1]``.  If evaluation arrays are supplied
    the reported before/after Brier and ECE describe that held-out set
    (out-of-sample, the honest case); otherwise they describe the calibration
    set itself and the result carries ``scope: "in_sample"``.
    """
    if method not in {"isotonic", "platt"}:
        raise ValueError("method must be 'isotonic' or 'platt'")
    cal_y = [int(value) for value in y_calibration]
    cal_scores = _as_float_list(scores_calibration, name="scores_calibration")
    if len(cal_y) != len(cal_scores):
        raise ValueError("y_calibration and scores_calibration must have the same length")
    if not cal_y:
        raise ValueError("calibrate_scores requires a non-empty calibration split")
    if any(value not in (0, 1) for value in cal_y):
        raise ValueError("y_calibration must contain only 0/1 values")
    if any(value < 0.0 or value > 1.0 for value in cal_scores):
        raise ValueError(
            "scores_calibration must be probability-like values in [0, 1] "
            "(ECE/reliability bins require a probability scale)"
        )
    seen_classes = set(cal_y)
    if seen_classes == {0} or seen_classes == {1}:
        raise ValueError(
            "calibration split is single-class "
            f"(only class {sorted(seen_classes)[0]!r} present); cannot fit a calibrator "
            "or measure Brier/ECE honestly"
        )
    scope = "in_sample"
    if y_evaluation is not None or scores_evaluation is not None:
        if y_evaluation is None or scores_evaluation is None:
            raise ValueError("y_evaluation and scores_evaluation must be provided together")
        eval_y = [int(value) for value in y_evaluation]
        eval_scores = _as_float_list(scores_evaluation, name="scores_evaluation")
        if len(eval_y) != len(eval_scores):
            raise ValueError("y_evaluation and scores_evaluation must have the same length")
        if not eval_y:
            raise ValueError("y_evaluation must be non-empty")
        if any(value not in (0, 1) for value in eval_y):
            raise ValueError("y_evaluation must contain only 0/1 values")
        if any(value < 0.0 or value > 1.0 for value in eval_scores):
            raise ValueError("scores_evaluation must be in [0, 1]")
        scope = "holdout"

    import numpy as np

    bins = max(2, min(int(n_bins), 50))

    def reliability(y: Sequence[int], prob: Sequence[float]) -> dict[str, Any]:
        arr = np.asarray(prob, dtype=np.float64)
        truth = np.asarray(y, dtype=np.int64)
        quantiles = np.quantile(arr, np.linspace(0.0, 1.0, bins + 1))
        unique_edges = np.unique(quantiles)
        if unique_edges.size < 2:
            return {
                "bins": [],
                "ece": NOT_MEASURED,
                "eceMeasured": False,
                "reason": "fewer than two distinct predicted values; cannot form bins",
            }
        lower = unique_edges[:-1]
        upper = unique_edges[1:]
        upper[-1] = np.nextafter(upper[-1], np.inf)
        rows: list[dict[str, Any]] = []
        ece = 0.0
        measured_bins = 0
        total = float(len(arr))
        for lo, hi in zip(lower, upper, strict=True):
            selected = (arr >= lo) & (arr < hi)
            count = int(selected.sum())
            if count == 0:
                continue
            mean_pred = float(arr[selected].mean())
            mean_obs = float(truth[selected].mean())
            rows.append(
                {
                    "bin": measured_bins,
                    "n": count,
                    "lower": float(lo),
                    "upper": float(hi if hi < np.inf else unique_edges[-1]),
                    "meanPredicted": mean_pred,
                    "meanObserved": mean_obs,
                    "gap": float(mean_pred - mean_obs),
                }
            )
            ece += (count / total) * abs(mean_pred - mean_obs)
            measured_bins += 1
        return {"bins": rows, "ece": float(ece), "eceMeasured": True}

    def brier(y: Sequence[int], prob: Sequence[float]) -> float:
        import numpy as np

        truth = np.asarray(y, dtype=np.float64)
        arr = np.asarray(prob, dtype=np.float64)
        return float(np.mean(np.square(arr - truth)))

    before_cal = reliability(cal_y, cal_scores)
    before_brier = brier(cal_y, cal_scores)

    if method == "isotonic":
        from sklearn.isotonic import IsotonicRegression

        calibrator = IsotonicRegression(out_of_bounds="clip", increasing=True)
        calibrator.fit(np.asarray(cal_scores), np.asarray(cal_y))
        coefficients: dict[str, Any] = {
            "kind": "isotonic",
            "x": [float(value) for value in calibrator.X_thresholds_.tolist()],
            "y": [float(value) for value in calibrator.y_thresholds_.tolist()],
        }
    else:
        from sklearn.linear_model import LogisticRegression

        regressor = LogisticRegression(max_iter=10_000)
        regressor.fit(np.asarray(cal_scores).reshape(-1, 1), np.asarray(cal_y))
        calibrator = regressor
        coefficients = {
            "kind": "platt",
            "slope": float(regressor.coef_[0][0]),
            "intercept": float(regressor.intercept_[0]),
        }

    def transform(scores: Sequence[float]) -> list[float]:
        import numpy as np

        values = np.asarray([float(value) for value in scores], dtype=np.float64)
        if method == "isotonic":
            return [float(value) for value in calibrator.predict(values).tolist()]
        proba = calibrator.predict_proba(values.reshape(-1, 1))
        return [float(value) for value in proba[:, 1].tolist()]

    cal_scores_after = transform(cal_scores)
    before_cal["brier"] = before_brier
    after_cal = reliability(cal_y, cal_scores_after)
    after_cal["brier"] = brier(cal_y, cal_scores_after)

    if scope == "holdout":
        assert y_evaluation is not None and scores_evaluation is not None
        eval_y_int = [int(value) for value in y_evaluation]
        eval_scores_list = [float(value) for value in scores_evaluation]
        before_eval = reliability(eval_y_int, eval_scores_list)
        before_eval["brier"] = brier(eval_y_int, eval_scores_list)
        after_list = transform(eval_scores_list)
        after_eval = reliability(eval_y_int, after_list)
        after_eval["brier"] = brier(eval_y_int, after_list)
        before = before_eval
        after = after_eval
        calibrated_scores = after_list
        evaluation_counts: dict[str, int] = {"positive": sum(1 for value in eval_y_int if value == 1),
                                             "negative": sum(1 for value in eval_y_int if value == 0)}
    else:
        before = before_cal
        after = after_cal
        calibrated_scores = cal_scores_after
        evaluation_counts = {
            "positive": sum(1 for value in cal_y if value == 1),
            "negative": sum(1 for value in cal_y if value == 0),
        }

    def deltas() -> dict[str, Any]:
        ece_measured = bool(before.get("eceMeasured") and after.get("eceMeasured"))
        return {
            "eceDelta": (
                float(after["ece"] - before["ece"]) if ece_measured else NOT_MEASURED
            ),
            "brierDelta": float(after["brier"] - before["brier"]),
            "eceImproved": bool(ece_measured and float(after["ece"]) < float(before["ece"])),
            "brierImproved": float(after["brier"]) < float(before["brier"]),
            "eceMeasured": ece_measured,
        }

    return {
        "kind": "calibration",
        "method": method,
        "scope": scope,
        "calibrationRows": int(len(cal_y)),
        "evaluationRows": int(len(calibrated_scores)),
        "evaluationCounts": evaluation_counts,
        "bins": bins,
        "before": before,
        "after": after,
        "delta": deltas(),
        "coefficients": coefficients,
        "calibratedScores": calibrated_scores,
    }


# ---------------------------------------------------------------------------
# feature drift (PSI + KS)
# ---------------------------------------------------------------------------
def drift_report(
    reference: Any,
    current: Any,
    *,
    feature_names: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Per-feature PSI + two-sample KS drift report.

    ``reference`` and ``current`` are pandas DataFrames or 2-D numeric
    array-likes with the same columns.  Empty inputs produce explicit
    ``not_measured`` entries — never a fabricated number.
    """
    import numpy as np

    if feature_names is not None:
        names = [str(value) for value in feature_names]
    else:
        names = None

    ref_array = np.asarray(reference, dtype=np.float64)
    cur_array = np.asarray(current, dtype=np.float64)
    if ref_array.ndim == 1:
        ref_array = ref_array.reshape(-1, 1)
    if cur_array.ndim == 1:
        cur_array = cur_array.reshape(-1, 1)
    if ref_array.ndim != 2 or cur_array.ndim != 2:
        raise ValueError("reference and current must be 2-D numeric inputs")
    if ref_array.shape[1] != cur_array.shape[1]:
        raise ValueError(
            f"reference and current feature counts differ ({ref_array.shape[1]} vs {cur_array.shape[1]})"
        )
    if names is None:
        if hasattr(reference, "columns") and list(reference.columns):
            names = [str(value) for value in reference.columns]
        elif hasattr(current, "columns") and list(current.columns):
            names = [str(value) for value in current.columns]
        else:
            names = [f"feature_{index}" for index in range(ref_array.shape[1])]
    if len(names) != ref_array.shape[1]:
        raise ValueError("feature_names length does not match the feature matrix width")
    if ref_array.size and not np.isfinite(ref_array).all():
        raise ValueError("reference contains NaN/Inf; impute before computing drift")
    if cur_array.size and not np.isfinite(cur_array).all():
        raise ValueError("current contains NaN/Inf; impute before computing drift")

    def stats_of(values: np.ndarray) -> dict[str, Any]:
        if values.size == 0:
            return {"rows": 0, "mean": None, "std": None, "min": None, "max": None}
        return {
            "rows": int(values.size),
            "mean": float(values.mean()),
            "std": float(values.std()),
            "min": float(values.min()),
            "max": float(values.max()),
        }

    def psi_and_ks(ref: np.ndarray, cur: np.ndarray) -> tuple[float | None, str | None, float | None, float | None, str | None]:
        """Return (psi, psi_reason, ks_d, ks_p, ks_reason)."""
        psi: float | None = None
        psi_reason: str | None = None
        ks_d: float | None = None
        ks_p: float | None = None
        ks_reason: str | None = None
        if ref.size == 0 or cur.size == 0:
            psi_reason = "one side of the comparison is empty"
            ks_reason = "one side of the comparison is empty"
            return psi, psi_reason, ks_d, ks_p, ks_reason
        unique_edges = np.unique(np.quantile(ref, np.linspace(0.0, 1.0, PSI_BINS + 1)))
        if unique_edges.size < 2:
            psi_reason = "reference feature has fewer than two distinct values; PSI bins cannot be formed"
        else:
            bins = np.concatenate(([-np.inf], unique_edges[1:-1], [np.inf]))
            ref_hist, _ = np.histogram(ref, bins=bins)
            cur_hist, _ = np.histogram(cur, bins=bins)
            share_ref = ref_hist / float(ref.size)
            share_cur = cur_hist / float(cur.size)
            smoothed_ref = np.where(share_ref == 0, PSI_EPSILON, share_ref)
            smoothed_cur = np.where(share_cur == 0, PSI_EPSILON, share_cur)
            terms = (smoothed_ref - smoothed_cur) * np.log(smoothed_ref / smoothed_cur)
            psi = float(terms.sum())
        ks_d, ks_p, ks_reason = _two_sample_ks(ref, cur)
        return psi, psi_reason, ks_d, ks_p, ks_reason

    thresholds_doc = {
        "psi": {"warn": PSI_WARN, "drift": PSI_DRIFT, "basis": "industry-standard PSI bands"},
        "ks": {"warn": KS_WARN, "drift": KS_DRIFT, "basis": "effect-size bands on the two-sample D statistic (documented protocol threshold; p-value is informational)"},
    }

    features: list[dict[str, Any]] = []
    worst: dict[str, Any] | None = None
    status_counts = {"ok": 0, "warn": 0, "drift": 0, "not_measured": 0}

    def drift_score(entry: dict[str, Any]) -> float:
        """Max of the (normalised) statistics that are measured for ranking."""
        scores = []
        psi = entry.get("psi")
        if isinstance(psi, float):
            scores.append(psi / PSI_DRIFT)
        ks_stat = (entry.get("ks") or {}).get("statistic")
        if isinstance(ks_stat, float):
            scores.append(ks_stat / KS_DRIFT)
        return max(scores) if scores else -1.0

    for index, name in enumerate(names):
        ref_col = ref_array[:, index]
        cur_col = cur_array[:, index]
        psi, psi_reason, ks_d, ks_p, ks_reason = psi_and_ks(ref_col, cur_col)

        def classify(value: float | None, warn: float, drift: float) -> str | None:
            if value is None:
                return None
            if value >= drift:
                return "drift"
            if value >= warn:
                return "warn"
            return "ok"

        psi_status = classify(psi, PSI_WARN, PSI_DRIFT)
        ks_status = classify(ks_d, KS_WARN, KS_DRIFT)

        def combine(left: str | None, right: str | None) -> str:
            ranks = {"drift": 2, "warn": 1, "ok": 0}
            if left is None and right is None:
                return "not_measured"
            if left is None:
                return right or "ok"
            if right is None:
                return left
            return left if ranks[left] >= ranks[right] else right

        status = combine(psi_status, ks_status)
        status_counts[status] = status_counts.get(status, 0) + 1
        reasons = [reason for reason in (psi_reason, ks_reason) if reason]
        entry: dict[str, Any] = {
            "feature": name,
            "reference": stats_of(ref_col),
            "current": stats_of(cur_col),
            "psi": psi,
            "psiMeasured": psi is not None,
            "ks": {"statistic": ks_d, "pvalue": ks_p, "measured": ks_d is not None},
            "status": status,
            "reason": "; ".join(reasons) if reasons else None,
        }
        features.append(entry)
        if status in {"warn", "drift"}:
            if worst is None or drift_score(entry) > drift_score(worst):
                worst = entry

    population: dict[str, Any] = {
        "referenceRows": int(ref_array.shape[0]),
        "currentRows": int(cur_array.shape[0]),
        "featureCount": len(names),
        "statusCounts": status_counts,
        "measured": int(status_counts["ok"] + status_counts["warn"] + status_counts["drift"]),
        "worstFeature": (
            {"feature": worst["feature"], "psi": worst["psi"], "ks": worst["ks"], "status": worst["status"]}
            if worst is not None
            else None
        ),
        "thresholds": thresholds_doc,
    }
    if ref_array.shape[0] == 0 or cur_array.shape[0] == 0:
        population["measured"] = 0
    return {"kind": "drift", "features": features, "population": population}


def _two_sample_ks(reference: Any, current: Any) -> tuple[float | None, float | None, str | None]:
    """Two-sample KS statistic (and p-value when scipy is importable)."""
    try:
        from scipy import stats

        result = stats.ks_2samp(reference, current, alternative="two-sided")
        return float(result.statistic), float(result.pvalue), None
    except ImportError:
        return _ks_statistic_manual(reference, current), None, "scipy unavailable; p-value not computed"


def _ks_statistic_manual(a: Any, b: Any) -> float:
    """Exact two-sample KS D statistic without scipy (ECDF max gap)."""
    import numpy as np

    left = np.sort(np.asarray(a, dtype=np.float64))
    right = np.sort(np.asarray(b, dtype=np.float64))
    n_left = float(left.size)
    n_right = float(right.size)
    if n_left == 0 or n_right == 0:
        return 0.0
    all_values = np.concatenate((left, right))
    ecdf_left = np.searchsorted(left, all_values, side="right") / n_left
    ecdf_right = np.searchsorted(right, all_values, side="right") / n_right
    return float(np.max(np.abs(ecdf_left - ecdf_right)))


# ---------------------------------------------------------------------------
# deterministic Markdown rendering
# ---------------------------------------------------------------------------
def _fmt_number(value: Any, decimals: int = 4) -> str:
    if value is None:
        return "未测量"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.{decimals}f}"
    return str(value)


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(str(header) for header in headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        cells = [_fmt_number(value) for value in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def render_report_markdown(report: dict[str, Any]) -> str:
    """Deterministic Markdown rendering of an evaluation report.

    Unmeasured metrics render as 未测量; the split manifest, hardware/runtime
    versions and dataset sha256 are always included verbatim.
    """
    blocks: list[str] = ["# EvoNIDS 模型评估报告（Model Evaluation Report）", ""]

    def kv_table(rows: Sequence[tuple[str, Any]]) -> str:
        return _md_table(("项", "值"), [[key, value] for key, value in rows])

    summary: list[tuple[str, Any]] = [
        ("protocolVersion", report.get("protocolVersion", "未测量")),
        ("generatedAtUtc", report.get("generatedAtUtc", "未测量")),
        ("command", report.get("command", "未测量")),
    ]
    blocks.append("## 0. 概要 Summary")
    blocks.append(kv_table(summary))
    blocks.append("")

    dataset = report.get("dataset") or {}
    if dataset:
        blocks.append("## 1. 数据集 Dataset")
        blocks.append(
            kv_table(
                [
                    ("path", dataset.get("path", "未测量")),
                    ("sha256", dataset.get("sha256", "未测量")),
                    ("labelColumn", dataset.get("labelColumn", "未测量")),
                    ("normalLabels", ", ".join(dataset.get("normalLabels", []) or [])),
                    ("timeColumn", dataset.get("timeColumn", "未测量")),
                    ("groupColumn", dataset.get("groupColumn", "未测量")),
                    ("sampling", dataset.get("sampling", "未测量")),
                ]
            )
        )
        blocks.append("")
        distribution = dataset.get("labelDistribution") or {}
        if distribution:
            blocks.append("标签分布 labelDistribution")
            blocks.append(
                _md_table(
                    ("label", "rows"),
                    [[label, count] for label, count in sorted(distribution.items(), key=lambda item: -item[1])],
                )
            )
            blocks.append("")

    runtime = report.get("runtime") or {}
    if runtime:
        blocks.append("## 2. 运行环境 Environment（硬件 / 运行库版本）")
        hardware = [
            ("python", runtime.get("python", "未测量")),
            ("platform", runtime.get("platform", "未测量")),
            ("machine", runtime.get("machine", "未测量")),
            ("processor", runtime.get("processor", "未测量")),
            ("cpuCount", runtime.get("cpuCount", "未测量")),
            ("hostname", runtime.get("hostname", "未测量")),
        ]
        blocks.append(kv_table(hardware))
        blocks.append("")
        versions = runtime.get("versions") or {}
        if versions:
            blocks.append(_md_table(("package", "version"), sorted(versions.items())))
            blocks.append("")

    models = report.get("models") or []
    for model_index, model in enumerate(models, start=1):
        blocks.append(f"## 3.{model_index} 模型 Model: {model.get('name', '未测量')}")
        blocks.append(
            kv_table(
                [
                    ("id", model.get("id", "未测量")),
                    ("task", model.get("task", "未测量")),
                    ("algorithm", model.get("algorithm", "未测量")),
                    ("artifactPath", (model.get("artifact") or {}).get("path", "未测量")),
                    ("artifactSha256", (model.get("artifact") or {}).get("sha256", "未测量")),
                    ("trainedOnWholeDataset", model.get("trainedOnWholeDataset", "未测量")),
                    ("overlapNote", model.get("overlapNote", "未测量")),
                ]
            )
        )
        blocks.append("")

        provenance = (model.get("artifact") or {}).get("provenance") or {}
        if provenance:
            blocks.append("产物来源 provenance（训练时自报指标，仅供参考，非协议证据）")
            blocks.append(_md_table(("key", "value"), sorted(provenance.items())))
            blocks.append("")

        for strategy in model.get("strategies") or []:
            name = strategy.get("strategy", "未测量")
            evidence = strategy.get("evidence") or {}
            blocks.append(f"### 策略 strategy: {name}（证据等级 evidence: {evidence.get('label', '未测量')}）")
            blocks.append(
                kv_table(
                    [
                        ("rank", evidence.get("rank", "未测量")),
                        ("note", evidence.get("note", "未测量")),
                        ("overlapRisk", strategy.get("overlap", "未测量")),
                    ]
                )
            )
            blocks.append("")
            error = strategy.get("error")
            if error:
                blocks.append(f"> ⚠️ 该策略未能完成评估：{error}")
                blocks.append("")
                continue

            manifest = strategy.get("manifest") or {}
            if manifest:
                blocks.append("#### 切分清单 split manifest")
                splits = manifest.get("splits") or {}
                blocks.append(
                    _md_table(
                        ("split", "rows", "indices"),
                        [
                            ["train", (splits.get("train") or {}).get("rows", "未测量"),
                             _compact_list((splits.get("train") or {}).get("rowIndices"))],
                            ["test", (splits.get("test") or {}).get("rows", "未测量"),
                             _compact_list((splits.get("test") or {}).get("rowIndices"))],
                        ],
                    )
                )
                blocks.append("")
                for split_name in ("train", "test"):
                    class_counts = (splits.get(split_name) or {}).get("classCounts") or {}
                    blocks.append(f"split={split_name} 每类行数 classCounts")
                    if class_counts:
                        blocks.append(
                            _md_table(
                                ("label", "rows"),
                                sorted(class_counts.items(), key=lambda item: -item[1]),
                            )
                        )
                    else:
                        blocks.append("未测量")
                    blocks.append("")
                boundaries = manifest.get("timestampBoundaries")
                if boundaries:
                    blocks.append("时间边界 timestamp boundaries")
                    blocks.append(_md_table(("key", "value"), sorted(boundaries.items())))
                    blocks.append("")
                held_groups = manifest.get("heldOutGroups")
                if held_groups is not None:
                    blocks.append(f"留出组 held-out groups（{len(held_groups)} 个）: {', '.join(map(str, held_groups))}")
                    blocks.append("")
                held_families = manifest.get("heldOutFamilies")
                if held_families is not None:
                    blocks.append(f"留出家族 held-out families（{len(held_families)} 个）: {', '.join(map(str, held_families))}")
                    blocks.append("")
                blocks.append(
                    kv_table(
                        [
                            ("seed", manifest.get("seed", "未测量")),
                            ("datasetSha256", manifest.get("datasetSha256", "未测量")),
                            ("strategy", manifest.get("strategy", "未测量")),
                            ("splitRule", manifest.get("splitRule", "未测量")),
                        ]
                    )
                )
                blocks.append("")

            drift = strategy.get("featureDrift")
            if drift:
                blocks.append("#### 训练/测试特征漂移 feature drift (PSI + KS)")
                population = drift.get("population") or {}
                blocks.append(_md_table(("key", "value"), sorted(population.items())))
                blocks.append("")
                feature_rows = [
                    [
                        (entry or {}).get("feature"),
                        (entry or {}).get("psi"),
                        ((entry or {}).get("ks") or {}).get("statistic"),
                        (entry or {}).get("status"),
                        (entry or {}).get("reason", ""),
                    ]
                    for entry in (drift.get("features") or [])
                ]
                if feature_rows:
                    blocks.append(_md_table(("feature", "psi", "ksD", "status", "reason"), feature_rows))
                    blocks.append("")

            evaluation = strategy.get("evaluation") or {}
            if not evaluation:
                blocks.append("未测量：该模型在本策略下没有可计算的评估指标。")
                blocks.append("")
                continue
            if evaluation.get("kind") == "multiclass":
                blocks.append(_render_multiclass(evaluation))
            elif evaluation.get("kind") == "binary":
                blocks.append(_render_binary(evaluation))

    blocks.append("---")
    blocks.append("_说明：所有值为 未测量 的指标在该数据集/切分下数学上无定义（例如测试集仅含一个类别、"
                  "类别从未被预测、目标 FPR 低于样本可分辨下限）。未测量 ≠ 0，二者绝不可互换。_")
    blocks.append("")
    return "\n".join(blocks)


def _compact_list(values: Any, limit: int = 24) -> str:
    if values is None:
        return "未测量"
    items = [str(value) for value in values]
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", …（共 {len(items)} 个）"


def _render_multiclass(evaluation: dict[str, Any]) -> str:
    blocks: list[str] = ["##### 多分类指标 multiclass metrics", ""]
    per_class = evaluation.get("perClass") or []
    if per_class:
        rows = [
            [
                (row or {}).get("label"),
                (row or {}).get("support"),
                (row or {}).get("precision"),
                (row or {}).get("recall"),
                (row or {}).get("f1"),
                "未测量" if not ((row or {}).get("measured") or {}).get("f1") else "measured",
            ]
            for row in per_class
        ]
        blocks.append(_md_table(("label", "support", "precision", "recall", "f1", "f1状态"), rows))
        blocks.append("")

    aggregates = evaluation.get("aggregates") or {}
    if aggregates:
        rows = []
        for key, value in sorted(aggregates.items()):
            if isinstance(value, dict):
                rows.append([key, value.get("value"), "measured" if value.get("measured") else "未测量"])
            else:
                rows.append([key, value, "measured"])
        blocks.append("聚合指标 aggregates")
        blocks.append(_md_table(("metric", "value", "measured"), rows))
        blocks.append("")

    blocks.append(
        kv_table_simple(
            [
                ("accuracy", evaluation.get("accuracy")),
                ("rows", evaluation.get("rows")),
                ("labels", ", ".join(map(str, evaluation.get("labels") or []))),
            ]
        )
    )
    blocks.append("")

    unknown = evaluation.get("unknownFamily") or {}
    if unknown:
        blocks.append("未知家族召回 unknown-family recall")
        blocks.append(
            kv_table_simple(
                [
                    ("rows", unknown.get("rows")),
                    ("families", ", ".join(map(str, unknown.get("families") or []))),
                    ("recall", unknown.get("recall")),
                    ("detectedAsMalicious", unknown.get("detectedAsMalicious")),
                    ("measured", "measured" if unknown.get("measured") else "未测量"),
                    ("basis", unknown.get("basis")),
                    ("normalLabels", ", ".join(map(str, unknown.get("normalLabels") or []))),
                    ("reason", unknown.get("reason")),
                ]
            )
        )
        blocks.append("")
        per_family = unknown.get("perFamily") or []
        if per_family:
            family_rows = [
                [
                    (row or {}).get("label"),
                    (row or {}).get("rows"),
                    (row or {}).get("recall"),
                    (row or {}).get("detectedAsMalicious"),
                    ", ".join(f"{label}:{count}" for label, count in ((row or {}).get("predictedDistribution") or {}).items()),
                ]
                for row in per_family
            ]
            blocks.append(_md_table(("family label", "rows", "recall", "detected", "predicted distribution"), family_rows))
            blocks.append("")
    return "\n".join(blocks)


def _render_binary(evaluation: dict[str, Any]) -> str:
    blocks: list[str] = ["##### 二分类（评分/异常分数）指标 binary metrics", ""]
    blocks.append(
        kv_table_simple(
            [
                ("positiveLabel", evaluation.get("positiveLabel")),
                ("total", (evaluation.get("counts") or {}).get("total")),
                ("positive", (evaluation.get("counts") or {}).get("positive")),
                ("negative", (evaluation.get("counts") or {}).get("negative")),
                ("scoreMin", (evaluation.get("scoreSummary") or {}).get("min")),
                ("scoreMax", (evaluation.get("scoreSummary") or {}).get("max")),
                ("rocAuc", evaluation.get("rocAuc")),
                ("prAuc", evaluation.get("prAuc")),
                ("aucMeasured", evaluation.get("aucMeasured")),
            ]
        )
    )
    blocks.append("")
    for reason in evaluation.get("notMeasured") or []:
        blocks.append(f"- 未测量: {(reason or {}).get('metric')} — {(reason or {}).get('reason')}")
    blocks.append("")
    operating = evaluation.get("operatingThresholds") or []
    if operating:
        rows = [
            [
                (row or {}).get("threshold"),
                (row or {}).get("tp"),
                (row or {}).get("fp"),
                (row or {}).get("tn"),
                (row or {}).get("fn"),
                (row or {}).get("precision"),
                (row or {}).get("recall"),
                (row or {}).get("f1"),
                (row or {}).get("fprPerMillion"),
            ]
            for row in operating
        ]
        blocks.append("给定判定阈值 operating thresholds（每百万正常流误报 fprPerMillion）")
        blocks.append(_md_table(("threshold", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "fprPerMillion"), rows))
        blocks.append("")
    target_points = evaluation.get("targetFprOperatingPoints") or []
    if target_points:
        rows = []
        for point in target_points:
            if point.get("pointMeasured"):
                rows.append(
                    [
                        point.get("targetFpr"),
                        point.get("threshold"),
                        point.get("fprPerMillion"),
                        point.get("precision"),
                        point.get("recall"),
                        point.get("f1"),
                        "measured",
                        point.get("reason") or "",
                    ]
                )
            else:
                rows.append(
                    [
                        point.get("targetFpr"),
                        "未测量",
                        "未测量",
                        "未测量",
                        "未测量",
                        "未测量",
                        "未测量",
                        point.get("reason") or "",
                    ]
                )
        blocks.append("目标 FPR 运行点 operating points at target FPRs")
        blocks.append(_md_table(("targetFpr", "threshold", "fprPerMillion", "precision", "recall", "f1", "measured", "note"), rows))
        blocks.append("")
    return "\n".join(blocks)


def kv_table_simple(rows: Sequence[tuple[str, Any]]) -> str:
    return _md_table(("key", "value"), [[key, value] for key, value in rows])
