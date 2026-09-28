# EvoNIDS 模型评估协议 — 操作手册（中文）

> 对应 ADR：`docs/adr/0009-model-evaluation-protocol.md`
> 纯度量模块：`backend/app/services/model_evaluation.py`
> 命令行入口：`backend/scripts/evaluate_model_splits.py`

本手册说明如何对本地的 CICIDS2017 数据集运行模型评估协议、如何理解四种切分
策略、如何阅读评估报告、以及**验收阈值**。协议的核心铁律只有一条：

**任何在数学上无定义的指标都必须写成「未测量」，绝不可以用 0.0 或任何猜出来的数。**

---

## 1. 为什么要做这个协议

仓库里现存的 `full-baseline` / `full-autoencoder` 产物是用**整份文件随机分层
70/15/15**切分训练的：训练行与“测试”行来自同分布、相邻时间近似重复可以同时落
在两侧、并且训练横跨了每个捕获日和每个主机。因此这些随机切分的分数**无法区分
“记住了数据集”与“真的泛化”**——它们只是分布内（in-sample）证据。

协议提供四种切分家族，按证据强度排序：

| 策略 | 做法 | 需要的数据列 | 证据含义 | 强度 |
|---|---|---|---|---|
| `random` | 同分布随机切分 | 标签列 | 只能当基线参照，**不能作为上线证据** | 1（最弱） |
| `time_ordered` | 时间升序：最早→训练，最晚→测试 | 可解析时间列（本库 `start_time`） | 时间泛化（同一采集分布内） | 2 |
| `group_holdout` | 整组留出源 IP/主机 | 主机列（本库 `source_ip`） | 主机级泛化 | 3 |
| `family_holdout` | 整族留出攻击家族/标签 | 家族映射（本库内置 CICIDS 映射） | 未见家族泛化 | 4（最强） |

**random 是四种里最弱的证据**：报告会把每种策略的证据等级写进 manifest，任何
“模型可以上线/合格”的结论都不得只依赖 random。

---

## 2. 运行 CLI

先进入后端目录（后端解释器自带 torch/sklearn）：

```powershell
cd <仓库根目录>\backend
```

### 2.1 冒烟运行（推荐先跑这个，~1–2 分钟）

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_model_splits.py `
  --dataset datasets\CICIDS2017\cicids2017_pcap_flow_full_v1.csv.gz `
  --strategies random,time_ordered `
  --max-rows 20000 `
  --output ..\tmp\eval-smoke
```

`--max-rows 20000` 会从全文件做**逐类确定性配额抽样**（每类至少 10 行、按全量
类别占比配额、固定 seed），并打印抽样后的标签分布；报告会如实注明本次是基于
抽样子集而不是全量 2,120,625 行。

### 2.2 全量运行

```powershell
# 四种策略都跑、读取全部 2.1M 行（内存需求大，建议 >=8GB 空闲）
.\.venv\Scripts\python.exe scripts\evaluate_model_splits.py `
  --dataset datasets\CICIDS2017\cicids2017_pcap_flow_full_v1.csv.gz `
  --strategies random,time_ordered,group_holdout,family_holdout `
  --output ..\tmp\eval-full
```

### 2.3 常用参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--dataset` | 本库 CICIDS 全量 CSV.GZ | 数据集路径（.csv / .csv.gz） |
| `--strategies` | 全部四种 | 逗号分隔 |
| `--max-rows` | 0（全部行） | 确定性逐类配额抽样行数 |
| `--output` | `backend/model-artifacts/evaluation` | 输出目录（写 `evaluation-report.json` + `evaluation-report.md`） |
| `--seed` | 20260814 | 随机种子 |
| `--test-ratio` | 0.3 | 测试行占比目标 |
| `--label-column` | `Label` | 标签列 |
| `--normal-labels` | `BENIGN` | 正常标签（逗号分隔） |
| `--time-column` | `start_time` | 时间列 |
| `--group-column` | `source_ip` | 主机/组列 |
| `--family-map` | 内置 CICIDS 映射 | 可选 JSON `{标签: 家族}` |
| `--baseline-artifact` / `--autoencoder-artifact` | 自动发现 `model-artifacts/full-*/` | 指定产物 |
| `--fresh-baseline` | 关闭 | 每个策略**重新训练**基线（严格 out-of-sample，见 §4 迁移建议） |
| `--max-iter` 等 | 与训练脚本一致 | 仅在 fresh 训练时生效 |

CLI 会**实时打印**扫描行数/速率、每个策略的 train/test 行数、预测耗时与关键
指标，最后把完整报告写到输出目录。

---

## 3. 如何读报告

输出目录包含两个文件：

- `evaluation-report.json` — 机器可读、可审计的完整报告；
- `evaluation-report.md` — 同一份报告的人类可读 Markdown。

报告由以下几部分组成（Markdown 版按相同顺序）：

| 章节 | 内容 |
|---|---|
| 0 概要 | protocolVersion、生成时间、命令行 |
| 1 数据集 | **文件 sha256**、标签列、正常标签、抽样方法与行数、标签分布、家族映射、数值特征/被丢弃特征 |
| 2 运行环境 | Python/平台/CPU/主机名 + numpy/pandas/sklearn/joblib/scipy/torch 版本（**必须随报告一起呈现**） |
| 3 模型 | 每个产物（baseline / autoencoder）的来源（含训练时自报指标，仅供参考）、产物 sha256、是否整文件训练 |
| 3.x 策略 | 每个策略：**切分清单 manifest**（seed、train/test 行数、每类行数、留出组/家族列表、时间边界、sha256）、重叠风险、训练/测试特征漂移（PSI+KS）、评估指标表 |

读表时请特别注意：

- 任何显示 **未测量** 的格子 = 该指标在此数据下数学上无定义，不是 0、不是失败
  的“0 分”。原因会写在旁边或 `reason` 字段。
- `overlap` / `overlapNote`：使用现成整文件产物时，每个策略都标注重叠风险
  （`high`）。**这些数字是 in-sample 证据**，不能宣称“未见主机/未见家族泛化”。
- `unknownFamily.recall`（未知家族召回）：`train_classes` 未提供的测试类别里，
  有多少比例没有被模型丢进正常桶（仍被判为恶意）。这是 family_holdout 的核心指标。
- `featureDrift`：训练/测试之间的特征漂移，帮你看时间切分到底制造了多大分布位移。

### 3.1 二分类（autoencoder）指标的“未测量”情形

- 测试集只剩一个类别（例如全部正常）→ ROC-AUC / PR-AUC / 判定指标全部 未测量。
- 分数为常数（无任何分离能力）→ AUC 未测量。
- 目标 FPR（如 0.01%）低于样本可分辨下限 `1 / 正常行数` → 该运行点 未测量，
  报告会写出分辨率下限。

### 3.2 多分类（baseline）指标的“未测量”情形

- 某类别在测试集中**从未被模型预测** → 该类 precision / f1 未测量（真实 0 行
  预测，不是 0 分）；宏平均 f1 也随之未测量并给出原因。
- 测试集是单类别 → 直接拒绝计算（见 CLI 报错）。

---

## 4. 用现成产物跑 vs 重新训练（迁移建议）

默认行为：CLI 复用仓库里已存在的
`model-artifacts/full-baseline/*/model.joblib` 与
`model-artifacts/full-autoencoder/*/model.joblib`，对每个策略的测试行打分。
由于这些产物是整文件随机分层训练的，报告如实标注每个策略的测试行与模型训练行
**可能重叠** → 全部为 in-sample 证据。

要在协议下拿到真正的 out-of-sample 证据，请对每个策略**重新训练**（迁移路径，
与 ADR 0009 一致）：

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_model_splits.py `
  --dataset datasets\CICIDS2017\cicids2017_pcap_flow_full_v1.csv.gz `
  --strategies time_ordered,group_holdout,family_holdout `
  --max-rows 0 `
  --fresh-baseline `
  --output ..\tmp\eval-fresh
```

此时每个策略都在**该策略自己的 train 切分**上训练，测试行从未参与训练，报告把
重叠风险标为 `none`。注意这会对每个策略各训练一次（2.1M 行上每次约 1–3 分钟），
成本更高但证据可信。

---

## 5. 验收阈值（协议默认值）

下述为 ADR 0009 采纳的**默认验收阈值**。它们不是预测值，是判定规则：报告中必须
同时给出“实测值”与“阈值”，由维护者对照判定。

### 5.1 证据门（Evidence Gates）

| 门槛 | 要求 | 不满足时的结论 |
|---|---|---|
| G0 报告完整性 | 报告含 dataset sha256、切分清单（seed+行数+每类计数）、硬件/运行库版本 | 该模型的任何数字都不能引用 |
| G1 数据可测量性 | 声称用到的每个指标 `measured = true`（未测量数不能被当作达标） | 相应指标作废 |
| G2 非重叠 | 结论使用的策略其 overlap 不是 `high`（fresh 或协议内训练） | 只能写“in-sample 参照”，不得写“泛化” |
| G3 非 random 依据 | “可上线/合格”结论至少基于 `time_ordered`/`group_holdout`/`family_holdout` 之一 | random 单独不足以支撑结论 |

### 5.2 指标阈值（默认，按模型角色）

| 模型角色 | 策略 | 指标 | 默认阈值 |
|---|---|---|---|
| 已知攻击分类（baseline） | `time_ordered` | macro F1 | ≥ 0.85 |
| 已知攻击分类（baseline） | `group_holdout` | macro F1 | ≥ 0.80 |
| 已知攻击分类（baseline） | `family_holdout` | macro F1 | ≥ 0.60 |
| 已知攻击分类（baseline） | `family_holdout` | 未知家族恶意检出召回 | ≥ 0.80 |
| 未知攻击检测（autoencoder） | 任一非 random 策略 | ROC-AUC | ≥ 0.95 且 measured |
| 告警运行点 | 目标 FPR = 0.1%（0.001） | 攻击召回 | ≥ 0.50 且该运行点 measured |

**重要**：默认阈值只是协议启动值，可按模型角色收紧/放宽，但必须在报告中写明
判定阈值与实测值。当前存量产物的数字均为 in-sample 证据，**不会**仅凭本协议直接
满足 G2。

---

## 6. 什么仍然是「未测量」（截至本文件）

以下内容在**本地只有 CICIDS2017** 的情况下没有数据可算，协议如实标注为
未测量，任何数字都不得伪造：

1. **跨数据集泛化**：在 UNSW-NB15、CICIDS2019 等第二份数据集的本地副本可用
   之前，模型在“从未见过的采集环境”上的表现一律是 未测量。
2. **CICIDS2017 之外的零日家族**：family_holdout 只证明“CICIDS2017 内未见家
   族”的处理能力；对 CICIDS 标签体系之外的新攻击类型（例如 UNSW-NB15 的
   Fuzzers/Analysis 类）没有任何证据 → 未测量。
3. **真实线上流量分布漂移**：本地文件是静态回放，真实流量的分布漂移需要用
   `drift_report` 对新采集数据持续监测，当前无线上数据 → 未测量。
4. **延迟/吞吐的生产验收**：本协议只评估检测质量；端到端延迟与吞吐验收属于
   其它基准（training 流程已报告 `test_predict_ms`/`throughput_fps`，但协议
   不做部署结论）。

---

## 7. 常见问题

- **报告里出现大量 未测量，是不是脚本坏了？**
  不是。先看 `reason`/`note`：多为单类别测试集、类别从未被预测、或目标 FPR 低于
  样本分辨率。协议宁可“不报”也绝不编数。
- **为什么用现成产物跑 time_ordered 还是标 in-sample？**
  因为产物训练时横跨了所有捕获日，测试时间段的行在训练时可能出现过。
- **两个模型（baseline 和 autoencoder）都只跑出分类/异常指标？**
  是的：baseline 是已知攻击多分类 → 多分类指标 + 未知家族召回；autoencoder 是
  异常分数 → 二分类指标 + 运行点。两者用同一份切分 manifest，便于对照。
