# ADR 0009 — Mandatory model evaluation protocol (split families + honest metrics)

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** EvoNIDS maintainers

## Context

The current CICIDS2017 baseline metrics are **not production evidence**. The
registered full-baseline and full-autoencoder artifacts were trained on a
random-stratified 70/15/15 split of the *whole* `cicids2017_pcap_flow_full_v1.csv.gz`
file (2,120,625 rows): training rows and "test" rows are drawn from the same
distribution, can contain temporally adjacent near-duplicates, and — because
training sampled across every capture day and every host — the test window can
contain rows the model already saw. Random-split scores therefore cannot
distinguish "the model memorised the dataset" from "the model generalises".
There was also no place where an *undefined* metric could be expressed: the
training path coerced `0/0` to `0.0`, which silently fabricates a number for
classes never predicted, single-class test sets and unreachable FPR targets.

Phase 6 needs per-model claims (model cards, registry quality labels) that are
honest about *what kind* of generalisation was measured.

## Decision

1. **`app/services/model_evaluation.py` is the mandatory protocol.** It is a
   pure, importable, JSON-serialising module with no I/O. Every evaluation of a
   model that may become a production claim must go through it.

2. **Four split families, with explicit evidence strength** (`split_manifest`).
   Each manifest records the strategy, seed, per-split row counts, per-split
   per-class counts, the exact held-out group/family lists, the exact timestamp
   boundaries, and the dataset sha256 it was computed from:
   - `random` — same-distribution split, **rank 1 = weakest evidence**; it may
     be reported for continuity but can never be the sole basis of a
     production-readiness claim.
   - `time_ordered` — earliest rows train, latest rows test (requires a
     parseable timestamp column): temporal generalisation inside the capture.
   - `group_holdout` — whole source-IP/host groups held out: host-level
     generalisation.
   - `family_holdout` — whole attack families/labels held out: unseen-family
     generalisation. Because a closed-set classifier cannot *name* a family it
     never saw, the reported family metric is the share of unseen-family flows
     the model still flags as malicious (does not dump into the normal bucket).

3. **Required metrics.** Binary score evaluation must report precision, recall,
   F1, PR-AUC, ROC-AUC, the confusion matrix, false positives per million
   normal flows, and operating points at target FPRs of 1%, 0.1% and 0.01%.
   Multiclass evaluation must report per-class precision/recall/F1/support,
   macro and support-weighted aggregates, the confusion matrix, and
   unknown-family recall. Calibration (isotonic and Platt) reports reliability
   bins, Brier and expected calibration error before/after, and refuses a
   single-class calibration split. Drift reports per-feature PSI and two-sample
   KS with documented effect-size thresholds and an ok/warn/drift status.

4. **Undefined metrics are 未测量, never zero.** Every metric that is not
   defined for the given data (single-class test set, class never predicted,
   target FPR below the sample resolution floor, empty drift input, ...) must
   be the `NOT_MEASURED` sentinel (`None`) with a human-readable reason, and
   must render as **未测量** in Markdown reports. A real measured zero stays
   `0.0`; the two are never confused. Coercing `0/0 → 0.0` is forbidden in
   protocol results.

5. **Existing whole-file artifacts are labelled in-sample.** Evaluating the
   current `full-baseline`/`full-autoencoder` artifacts under any strategy is
   still in-sample evidence for that strategy (their training rows overlap the
   test rows); the report records a qualitative overlap risk per strategy and
   never lets those numbers pose as out-of-sample generalisation. Fresh
   per-strategy training (CLI `--fresh-baseline`) is the honest path and is
   what migration uses.

6. **Reports are self-contained.** `render_report_markdown` deterministically
   renders the exact split manifest, hardware/runtime versions and dataset
   sha256 together with every measured number and 未测量 marker.

## Alternatives considered

- Plain k-fold CV over CICIDS2017: rejected as a *claim* instrument — it is
  still same-distribution and does not exercise temporal, host or unseen-family
  generalisation; it may complement the protocol later.
- Relying on public leaderboard scores: rejected — different preprocessing and
  label sets make them non-comparable to our extraction.
- Autoencoder-only anomaly evaluation: rejected — it cannot answer
  "did the baseline generalise to unseen hosts/families", which the multiclass
  protocol answers.
- p-value-only drift thresholds: rejected — with millions of rows any tiny
  shift becomes statistically significant; protocol thresholds are documented
  effect sizes (PSI 0.10 warn / 0.25 drift, KS D 0.10 warn / 0.20 drift).

## Migration / rollback

No schema change and no rewrite of existing registry rows. Migration path for
the model registry:

1. Existing rows keep their random-split metrics but their quality labels are
   interpreted as **in-sample / legacy**: they do not satisfy the protocol's
   evidence gates and must not be quoted as production evidence.
2. Regenerate evidence with `python scripts/evaluate_model_splits.py` against
   the registered dataset; the CLI writes `evaluation-report.json` +
   `evaluation-report.md` including dataset sha256 and per-strategy manifests.
3. New model rows must record `protocolVersion`, the evaluation report path and
   the evaluated dataset sha256; future training for evidence uses fresh
   per-strategy splits so the test partition is never used in training.

Rollback: delete `app/services/model_evaluation.py`,
`scripts/evaluate_model_splits.py`, `tests/test_model_evaluation.py` and the
two docs; registry rows and artifacts are untouched.

## Cost

One pure service module (~1,500 lines), one CLI script (~700 lines), one test
module (27 fast deterministic tests), two documents. Runtime cost is
proportional to scanning the dataset file (≈ 40–60 s for the 2.1M-row
CICIDS2017 file) plus prediction; fresh per-strategy training is optional and
documented as heavier than artifact reuse.
