# EvoNIDS Model Card

**Project:** EvoNIDS — Adaptive Network Intrusion Detection System
**Model family version:** v0.1 (two delivered channels)
**Card date:** 2026-08-28

## Model Details

EvoNIDS ships two independently trained detection channels. Both are deliberately
conservative, fully reproducible CPU baselines trained on the same derived CICIDS2017
flow dataset. **The planned Flow Transformer (MFM self-supervised pretraining) is not
trained yet and is not part of this release** — see [Planned work](#planned-not-yet-delivered).

### Channel 1 — Known-attack classification: HistGradientBoosting baseline

| Field | Value |
|---|---|
| Model ID | `MODEL-TRN-35C13FB7E99C46B59B82E5E79469FEE7` (registry row for the earlier bootstrap run) |
| Full-dataset run ID | `TRN-FULL-BASE-37E2F1560491` |
| Task | Known attack classification (supervised, 14 classes) |
| Algorithm | `sklearn.ensemble.HistGradientBoostingClassifier` (CPU) |
| Hyperparameters | `max_iter=200` (58 iterations used, early stopping on), `learning_rate=0.08`, `max_leaf_nodes=31`, `l2_regularization=0.2`, `random_seed=20260728` |
| Features | 42 numeric flow features (identifiers dropped: `capture_day`, `source_ip`, `destination_ip`, `start_time`) |
| Dataset | `cicids2017_pcap_flow_full_v1.csv.gz`, SHA-256 `f9ff72b9768e38637c401d287327173f1408c9fbdcacb8a8b82f472abcac5fec` |
| Split | 70/15/15 stratified: train 1,484,437 / validation 318,094 / test 318,094 |
| Artifact SHA-256 | `e07d2efe955eed4b9707a6179fb9725f53dafd1462f11ee83195436c4f0459a6` |

An earlier bootstrap run (2026-07-28) on the 5%-benign `research_v1` table
(250,000 rows, `max_iter=160`) reached test accuracy 0.9928 and macro F1 0.8964;
its artifact SHA-256 is `06821a2d26e1eacfdd71e50a32f7e161412dd55141b095f6bcc26947916c8234`.
The tables below report the newer full-dataset run.

### Channel 2 — Unknown-anomaly detection: PyTorch AutoEncoder

| Field | Value |
|---|---|
| Run ID | `TRN-AE-FULL-C02138437669` |
| Task | Unsupervised anomaly scoring (trained on benign flows only) |
| Algorithm | Symmetric fully connected AutoEncoder, 41 → 32 → 8 → 32 → 41, GELU activations (shoulder/bottleneck sizes follow `train_full_autoencoder.py` defaults: bottleneck 8, shoulder = max(3 × bottleneck, min(32, input size))) |
| Training data | All 1,620,430 benign flows of `cicids2017_pcap_flow_full_v1.csv.gz`; no attack flows used for fitting |
| Hyperparameters | 40 epochs (all 40 completed), batch size 1024, early-stop patience 6, learning rate 0.001, seed 20260728, CPU |
| Threshold | `0.033349` = validation-set reconstruction-error quantile 0.95, chosen for a 5% target FPR |
| Artifact SHA-256 | `fe70ff2653b5774a4cffab4a3736f44cc04b0ca3083a75cef7433b171bed6ac2` |

## Intended Use

- **Intended:** security research, coursework and teaching, local demonstration of the
  EvoNIDS dual-channel detection → evidence → agent → rule-evolution workflow, and as a
  reproducible benchmark that future models (the Flow Transformer in particular) must beat
  under the same dataset identity and split protocol.
- **Out of scope / not intended:** production perimeter protection, replacing a SOC,
  automated blocking of traffic without human review, or any compliance-critical monitoring.
  The models were trained and evaluated on a single 2017 testbed dataset; nothing here
  has been validated on a live network.

## Metrics

All metrics below are measured, logged values from the full-dataset training runs on
`cicids2017_pcap_flow_full_v1.csv.gz` (2,120,625 flows, 14 classes). Evaluation protocol:
stratified 70/15/15 split with fixed seed 20260728; classification metrics are computed on
the held-out test split; AutoEncoder operating-point metrics use the 0.95 validation
quantile threshold.

### Channel 1 — HistGradientBoosting, test split (318,094 flows)

Aggregate: accuracy **0.9912**, balanced accuracy **0.9014**, macro P/R/F1 **0.8772 / 0.9014 / 0.8883**,
weighted F1 **0.9913**, OvR ROC-AUC **0.9997**, OvR PR-AUC **0.9125** (validation macro F1 0.9631).

| Label | Test support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| BENIGN | 243,065 | 0.998 | 0.990 | 0.994 |
| DDoS | 13,823 | 0.996 | 1.000 | 0.998 |
| DoS GoldenEye | 1,318 | 0.977 | 0.998 | 0.988 |
| DoS Hulk | 22,594 | 0.962 | 1.000 | 0.980 |
| DoS Slowhttptest | 872 | 0.970 | 0.998 | 0.984 |
| DoS slowloris | 1,023 | 0.991 | 0.999 | 0.995 |
| FTP-Patator | 594 | 0.992 | 1.000 | 0.996 |
| Heartbleed | 1 | 0.000 | 0.000 | 0.000 |
| Infiltration | 10,102 | 0.883 | 0.959 | 0.920 |
| PortScan | 24,030 | 1.000 | 1.000 | 1.000 |
| SSH-Patator | 370 | 0.992 | 0.995 | 0.993 |
| Web Attack Brute Force | 202 | 0.851 | 0.822 | 0.836 |
| Web Attack SQL Injection | 1 | 1.000 | 1.000 | 1.000 |
| Web Attack XSS | 99 | 0.669 | 0.859 | 0.752 |

Heartbleed has only **10 flows in the entire dataset** (SQL Injection: 9), so its test
support is a single row; the 0.000/1.000 rows for these classes are statistically
meaningless and are reported only for completeness. Macro metrics are dominated by
these near-empty classes; weighted F1 and the per-majority-class rows are more
representative of typical behavior.

### Channel 2 — AutoEncoder, operating point at 5% target FPR

The AutoEncoder is evaluated over every attack flow in the full dataset (supports equal
the full dataset label distribution); the threshold was fixed on the validation split.

| Metric | Value |
|---|---:|
| AUROC | 0.9042 |
| AUPRC | 0.9189 |
| Threshold (reconstruction error) | 0.033349 |
| Attack recall | 27.48% |
| Precision | 91.88% |
| F1 | 0.4230 |
| Normal FPR | 5.00% |
| Epochs completed | 40 / 40 (best val MSE 0.008403), training time 957.3 s CPU |

Per-attack-class recall (threshold 0.033349):

| Attack class | Support | Detected | Recall | Median reconstruction error |
|---|---:|---:|---:|---:|
| DDoS | 92,152 | 30,144 | 32.71% | 0.0244 |
| DoS GoldenEye | 8,786 | 2,908 | 33.10% | 0.0219 |
| DoS Hulk | 150,625 | 14,146 | 9.39% | 0.0121 |
| DoS Slowhttptest | 5,812 | 5,378 | 92.53% | 0.0590 |
| DoS slowloris | 6,819 | 4,094 | 60.04% | 0.0699 |
| FTP-Patator | 3,958 | 11 | 0.28% | 0.0185 |
| Heartbleed | 10 | 10 | 100.00% | 1.4938 |
| Infiltration | 67,347 | 49,902 | 74.10% | 0.0467 |
| PortScan | 160,203 | 30,744 | 19.19% | 0.0251 |
| SSH-Patator | 2,464 | 2 | 0.08% | 0.0229 |
| Web Attack Brute Force | 1,349 | 74 | 5.49% | 0.0052 |
| Web Attack SQL Injection | 9 | 0 | 0.00% | 0.0051 |
| Web Attack XSS | 661 | 20 | 3.03% | 0.0060 |

Heartbleed's 100% recall is on **10 flows** (median reconstruction error 1.4938, an order
of magnitude above threshold); it is a real observation but not a robust estimate.

## Training Data

Both channels were trained on the EvoNIDS-derived CICIDS2017 flow tables extracted from
the official UNB packet captures. Full provenance, extraction methodology, file hashes and
label distributions are documented in [DATA_CARD.md](DATA_CARD.md). In short:
`cicids2017_pcap_flow_full_v1.csv.gz` (2,120,625 flows, all benign flows kept) is the
training source; `cicids2017_pcap_flow_research_v1.csv.gz` (546,628 flows, 5% deterministic
benign sample) is the lightweight variant used by the earlier bootstrap run and replay demos.

## Caveats and Limitations

- **Extreme class imbalance.** BENIGN is 76.4% of full_v1; Heartbleed (10 flows) and Web
  Attack SQL Injection (9 flows) are effectively absent. Per-class numbers for tiny classes
  must not be quoted as evidence of capability.
- **The AutoEncoder has low recall on several major attacks.** PortScan (19.19%), DoS Hulk
  (9.39%), FTP-Patator (0.28%), SSH-Patator (0.08%) and all three web-attack classes
  (< 6%) are largely missed at the 5%-FPR operating point. Reconstruction-based detection
  on these tabular features does not separate subtle or low-and-slow attacks from benign
  traffic; the overall attack recall is 27.48%. The channel is a conservative anomaly
  hint, not a detector.
- **Known-attack channel is a deliberate CPU baseline.** HistGradientBoosting was chosen
  to establish a reproducible benchmark. The planned Flow Transformer (MFM self-supervised
  pretraining) has **not been trained**; no transformer weights exist in this release.
- **Single dataset, single era.** All training and evaluation come from CICIDS2017 (July
  2017 testbed traffic). No cross-dataset, cross-site or modern-traffic (TLS 1.3, QUIC,
  DoH) validation has been performed. Labels are derived from the official UNB attack
  schedule plus documented attacker/victim endpoints, not from the officially released
  labeled CSVs, and should be cross-checked before strong claims.
- **No deployment-time guarantees.** Scoring today is an offline backfill over replayed
  flows; there is no online inference in the ingestion path, no adversarial robustness
  testing, and no drift monitoring.
- **Features are flow-level aggregates.** 42 numeric per-flow statistics only; payload
  content, sequence information and packet-level timing detail are not modeled.

## Ethical Considerations

- **"Unknown anomaly" is not "confirmed zero-day".** A high AutoEncoder reconstruction
  error only means the flow deviates from the benign training distribution. EvoNIDS
  documentation, UI and generated reports must phrase AutoEncoder findings as *unexplained
  or unknown anomalies requiring analyst review* — never as "zero-day attacks", "confirmed
  intrusions" or "novel attack detected". Human confirmation through the replay/validation
  workflow is mandatory before any stronger claim.
- Keep a human in the loop: candidate rules are proposals until an analyst validates and
  confirms them; nothing in this system should auto-block traffic.
- The dataset is a controlled academic testbed. Attack traffic is synthetic/simulated and
  benign traffic reflects one organization's 2017 behavior; conclusions about real-world
  populations are not supported.
- Flow records contain testbed IP addresses and ports. Treat derived datasets like any
  other network telemetry: do not publish captures of real user traffic through this
  pipeline without review.
- Dual-use: the rule-generation and replay components are defensive research tooling. Do
  not use the anomaly thresholds or per-class recall tables to craft evasion without an
  authorized, defensive research context.

## Planned (not yet delivered)

- Flow Transformer with masked-flow-modeling (MFM) self-supervised pretraining — v0.2 goal,
  to be benchmarked against the HGB baseline above under identical dataset identity and splits.
- Vector/hybrid knowledge retrieval (current retrieval is honest keyword fallback).
- Online inference in the ingestion path, real-time packet capture, and a durable training
  job queue.

## Where the numbers come from

- `docs/evidence/training-logs/baseline.log` — HGB full-dataset run log (per-class table, hyperparameters, artifact digest).
- `docs/evidence/training-logs/autoencoder.log` — AutoEncoder run log (threshold, AUROC/AUPRC, per-class recall, artifact digest).
- `backend/model-artifacts/cicids2017-latest-summary.json` — earlier research_v1 bootstrap run record.
- `backend/model-artifacts/full-baseline/full-latest-summary.json` — the full-dataset run record behind the headline table above.
- `backend/datasets/CICIDS2017/*.metadata.json` — dataset extraction provenance and label distributions.
