# E01-E10 实验登记表

> 由 `backend/scripts/run_experiments.py` 生成。**未运行的实验标注为 `not_run` / `blocked`，不写任何猜测数字。** 重新生成：`python scripts/run_experiments.py --check`。

## 环境探测

| 项 | 状态 |
|---|---|
| 数据集 | 已就绪：`backend/datasets/CICIDS2017/cicids2017_pcap_flow_full_v1.csv.gz` |
| PyTorch | 可用 |
| Suricata 二进制 | 未安装 |
| LLM / 嵌入密钥 | 未配置 |

## 实验矩阵

| 编号 | 实验 | 假设 | 指标 | 状态 |
|---|---|---|---|---|
| E01 | Known-attack classification, strong tabular baseline | A tuned gradient-boosted baseline sets the number any deep model must beat. | macro-F1, per-class recall, PR-AUC, confusion matrix | ready |
| E02 | Unknown-anomaly baseline (tabular AutoEncoder) | Reconstruction error trained on benign traffic separates unseen attacks. | AUROC, AUPRC, recall at fixed FPR, normal FPR | ready |
| E03 | Flow Transformer without pretraining | The architecture alone, with no MFM signal, is the honest floor. | macro-F1, per-class recall | ready |
| E04 | MFM pretraining + classification head | Self-supervised pretraining improves the same architecture (E03 vs E04). | macro-F1, per-class recall, delta against E03 | ready |
| E05 | MFM pretraining + anomaly head only | Reconstruction error from the shared encoder is a usable anomaly channel. | AUROC, AUPRC, recall at fixed FPR, normal FPR | ready |
| E06 | Dual-channel risk fusion | Classification and anomaly channels are complementary, not redundant. | fusion precision/recall against each channel alone | ready |
| E07 | Open-set evaluation by attack family | Family holdout is the only defensible measure of 'unknown attack' ability. | unknown-family recall, AUROC, AUPRC, recall at fixed FPR | ready |
| E08 | Out-of-time and cross-host generalisation | Random splits overstate performance; time and host holdouts expose it. | macro-F1, per-class recall per split strategy | ready |
| E09 | Rule replay and benign regression under real Suricata | LLM-authored rules only earn trust by passing a real engine and PCAP replay. | target hits, benign false positives, load-test result | blocked: needs the Suricata binary on PATH |
| E10 | RAG citation correctness | The Agent's rules must cite retrievable, permitted knowledge. | Recall@K, MRR, citation correctness, refusal rate | blocked: needs an LLM/embedding provider key |

## 已测量结果

尚无实验在本机运行；没有可报告的数字。

## 如何运行未完成的实验

- **E01**：`python scripts/train_full_baseline.py --csv <dataset>`
- **E02**：`python scripts/train_full_autoencoder.py --csv <dataset>`
- **E03**：`python scripts/train_flow_transformer.py --csv <dataset> --no-pretrain --d-model 64 --layers 2 --heads 4`
- **E04**：`python scripts/train_flow_transformer.py --csv <dataset> --pretrain-epochs 20 --epochs 10`
- **E05**：`python scripts/train_flow_transformer.py --csv <dataset> --task anomaly --target-fpr 0.05 --pretrain-epochs 20`
- **E06**：`python scripts/backfill_dual_channel_inference.py --dataset <dataset>`
- **E07**：`python scripts/evaluate_model_splits.py --strategy family_holdout`
- **E08**：`python scripts/evaluate_model_splits.py --strategy time_holdout,group_holdout`
- **E09**：`python -m app.services.rule_sandbox --help`
- **E10**：`python -m app.services.knowledge_retrieval --help`
