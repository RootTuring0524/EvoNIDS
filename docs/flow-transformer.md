# Flow Transformer（掩码特征建模）— 架构与消融手册

> 状态：**代码已实现并有单元测试；权重尚未训练**。本文件说明"已实现什么、如何训练、如何做消融、哪些数字目前是未测量"，
> 目的是让后续训练与论文写作有唯一依据，而不是重复已有结论。

## 1. 为什么是字段 Token，而不是把特征拼成一个向量

把 42 列特征拼成一条向量送进 MLP，模型学不到"端口"和"包数"在同一位置上语义不同。
Flow Transformer 把**每个字段变成一个 Token**，Token 同时携带两种信息：

1. **取值**：数值字段做 `x_i · w_i + b_i`（每个字段一组独立投影参数），类别字段用可学习 Embedding；
2. **字段身份**：额外加一个 Field-ID Embedding，让编码器知道"这个 Token 是 dst_port 还是 flow_duration"。

然后在这个 Token 序列前加一个 CLS Token，送进 `TransformerEncoder`（默认 2 层、d=64、4 头）。
CLS 的输出作为流级表示，供下游两个头使用。

代码：`backend/app/ml/flow_transformer.py`。

## 2. 自监督目标：MFM（掩码特征建模）

预训练阶段随机遮蔽 **15% 的字段**（可配置），只对被遮蔽的字段计算重建损失：

- 数值字段 → 均方误差（回归头）
- 类别字段 → 交叉熵（分类头，Embedding 表额外留一个 mask 槽位）

**关键不变量**（有单元测试覆盖）：

- 损失只在被遮蔽字段上累计——没遮蔽就没有损失；
- 每个样本至少保留一个可见字段，否则重建任务无信息；
- 掩码由 `torch.Generator` 决定，同一 seed 完全可复现。

## 3. 下游双头

| 头 | 输入 | 输出 | 用途 |
|---|---|---|---|
| 分类头 | CLS 表示 | 各类别 logits | 已知攻击分类（监督微调，带类别权重以保住稀有类） |
| 异常头 | 逐字段重建误差 | 每样本异常分 | 未知异常检测，**不需要攻击标签** |

异常分复用重建误差，因此不需要为异常通道单独训一个 AutoEncoder——这正是"共享编码器 + 双下游"的设计意图。

## 4. 消融开关（与蓝皮书 §7.5 / 附录 B 对应）

| 训练脚本参数 | 对应实验 | 回答什么问题 |
|---|---|---|
| `--no-pretrain` | E03 / E04 | 自监督预训练到底有没有贡献？ |
| `--no-field-embeddings` | 字段身份消融 | Field-ID 信息是否必要？ |
| `--mask-rate 0.10/0.15/0.20/0.30` | 掩码率扫描 | 掩码比例如何影响重建质量与下游表现？ |
| `--d-model` / `--layers` | 容量扫描 | 更大的模型是否值得它的推理耗时？ |
| `--task anomaly` | E05 | 只用异常通道时表现如何？ |

与 HGB 基线的横向对比（E01 vs 本模型）使用**完全相同的切分协议**：`backend/scripts/evaluate_model_splits.py`（ADR-0009 的四种切分）。

## 5. 如何运行

```bash
cd backend
# 1) 管线自检（合成数据，几秒，不需要数据集和显卡）
python scripts/train_flow_transformer.py --smoke

# 2) 真实数据训练（CPU 可跑小规模；全量建议 GPU）
python scripts/train_flow_transformer.py \
  --csv datasets/CICIDS2017/cicids2017_pcap_flow_full_v1.csv.gz \
  --label-column Label \
  --d-model 64 --layers 2 --heads 4 \
  --pretrain-epochs 20 --epochs 10 \
  --output-dir model-artifacts/flow-transformer

# 3) 消融：例如关掉预训练
python scripts/train_flow_transformer.py --csv ... --no-pretrain --output-dir /tmp/ft-nopretrain
```

产物：`model.joblib`（含 `modelState`、字段列表、标准化参数、消融配置、损失曲线、运行环境）+ `metadata.json`（同样的内容，去掉权重，便于直接读表）。

## 6. 目前**未测量**的内容（不得在论文/演示中当作结论）

- 任何真实数据集上的 Transformer 指标——**权重尚未训练**；
- 与 HGB 基线的对比结论（同协议跑完才有结论）；
- 消融各分支的实际差值；
- 在 `flow-online-v1` 在线契约上的表现（在线可观测字段只有约 16/42，需要单独重训与评估，见 ADR-0010）；
- GPU 训练耗时与显存占用（本文件不提供估算）。

`--smoke` 输出的指标来自**合成数据**，其唯一用途是证明"管线、消融开关与产物格式接通"，`metadata.json` 里会写入 `note` 显式说明这一点。

## 7. 与现有两个通道的关系

| 通道 | 现状 | 与 Transformer 的关系 |
|---|---|---|
| 已知攻击分类 | HGB 基线（已训练，有实测指标） | Transformer 分类头是它的**挑战者**，不是替代品：只有在同协议下打赢才切换 |
| 未知异常检测 | Tabular AutoEncoder（已训练，AUROC 0.9042） | Transformer 异常头复用重建误差，可作为第三条通道或替代 |
| 在线检测 | shadow 模式，`enabled` 需在线契约模型 + ADR-0009 评估 | Transformer 上线前同样要过 ADR-0010 的四道门禁 |
