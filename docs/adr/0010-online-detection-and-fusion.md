# ADR-0010：在线检测与可解释风险融合（Phase 3）

- 状态：已接受（2026-09-09）
- 相关：ADR-0008（采集与热路径存储）、ADR-0009（模型评估协议）、`docs/model-evaluation.md`

## 1. 问题

已发布的基线（HistGradientBoosting，CICIDS2017 全量）与 AutoEncoder 都只在**离线回放脚本**（`scripts/backfill_dual_channel_inference.py`）里跑过：它读取 CICIDS CSV，用 CICIDS 列名构造特征，写 `inferences` 表。在线路径此前**没有任何模型推理**：`Flow.verdict` 恒为 `benign`、`anomaly_score` 恒为 0。

把离线脚本直接搬到在线会引入三个真实风险：

1. **训练/推理特征不一致**：离线用 CICIDS 的 41–42 列（含 IAT 统计、TCP flag 计数、包长 min/max/std），Suricata EVE `flow` 事件只提供端口、协议、时长、包数、字节数。
2. **指标不可迁移**：CICIDS2017 同域随机切分的 0.8883 macro-F1 / 27.48% recall@5%FPR 不能作为在线检测质量证明（ADR-0009）。
3. **不可解释**：原脚本把融合结果写成一段中文文本，无法回溯“哪一路信号、哪个模型版本、哪些特征被插补”。

## 2. 决策

### 2.1 统一特征契约（消除训练/推理偏差）

新增 `app/domain/flow_features.py`，定义 `flow-online-v1` 契约，分两层：

- `ONLINE_MODEL_FEATURES`（16 项）：只包含 EVE `flow` 事件必然可得的量（端口、协议号、时长、双向包数/字节数、速率、平均包长、方向占比、包长不对称度）。**只有这些可以作为模型输入。**
- `ONLINE_CONTEXT_FEATURES`（5 项）：60 秒滑动窗口计数（目的端口数、目的地址数、同源流量数、源端口数、目的端口比）。用于关联、规则上下文与界面展示，**不作为模型输入**，因为离线数据集没有可比窗口。

离线训练若使用在线契约，必须调用同一个 `project_cicids_row()` 投影函数；`tests/test_flow_features.py::test_online_builder_and_cicids_projection_agree_on_model_features` 保证两条路径公式一致。

### 2.2 通道信号与融合评估分开持久化

- `detection_signals`：每通道一行，保存 `channel`、`channel_version`、`model_id`、`raw_score`、`calibrated_score`、`threshold`、`decision`、`uncertainty`、`feature_version`、`imputed_features`、`latency_ms`、`degraded`、`degraded_reason`、`detail`。
- `risk_assessments`：每次融合一行，保存 `signal_ids`、逐通道 `inputs`（含模型版本与原始/校准分数）、`weights`、`final_score`、`uncertainty`、`decision`、`explanation`、`degraded_reasons`、`mode`。

原始事实（flow/evidence）与推断（signal/assessment）永不写入同一字段。

### 2.3 融合规则（与离线路径一致，可回溯）

| 情况 | 权重（基线/AE） | lean | agreement |
| --- | --- | --- | --- |
| 基线命中 且 AE 命中 | 0.65 / 0.35 | dual_confirmed | consistent |
| 仅基线命中 | 0.80 / 0.20 | known_attack | partial |
| 仅 AE 命中 | 0.30 / 0.70 | unknown_anomaly | conflicting |
| 都不命中 | 0.70 / 0.30 | normal | consistent |
| 仅一个通道可用 | 1.00 | single_channel | insufficient |

- **弃权通道不投票**：`decision == "abstain"`（制品缺失、运行时异常）不参与融合，也不被当作“正常票”，否则一个坏通道会稀释真实告警。
- **签名下限**：已部署 Suricata 规则命中时 `final_score = max(融合分, 规则风险)`，并记录 `ruleFloorApplied`。理由：模型尚未在在线域上评估，不能让签名命中被模型稀释。
- **不确定性**：`0.45×分歧 + 0.35×插补比例 + 0.2×降级标志`（insufficient/conflicting 记为 1.0 分歧）。数值写入 `risk_assessments.uncertainty`，前端展示。
- **结论阈值**：≥65 malicious、≥40 suspicious，其余 benign；`abstain` 只在没有任何通道可用时产生。异常 ≠ 攻击：`unknown_anomaly` 是候选，不是定性。

### 2.4 默认 `shadow`，告警需要显式开启

`EVONIDS_DETECTION_MODE` 三档：

- `disabled`：不计算模型信号（仍写证据、仍处理规则告警）。
- `shadow`（默认）：计算并持久化信号与融合评估，**不创建告警、不修改 `Flow.verdict`**。
- `enabled`：按融合结论创建/更新告警并修改流量结论。

**为什么默认 shadow**：当前可用制品是在 CICIDS2017 特征空间训练的，在线推理有 26/42 个特征由模型自带插补填充（`imputed_features` 逐条记录）。在这种状态下直接告警会产出无法解释的误报。开启 `enabled` 的前置条件：

1. 用在线契约训练的基线 + AutoEncoder 制品存在（`ModelVersion.parameters.featureContract == "flow-online-v1"`），且 `detectionStatus.channels.*.contractMatches == true`；
2. 该制品通过 ADR-0009 协议的时间外/主机留出/家族留出评估，并给出在目标 FPR 下的 operating point；
3. 运营方在 `docs/runbooks/` 流程中确认阈值与回滚方式。

### 2.5 失败可控

- 制品缺失、加载失败、推理异常 → 该通道写 `abstain` + `degraded_reason`，**不影响采集与证据写入**（`tests/test_online_detection.py::test_scoring_failure_degrades_to_abstain_without_failing_ingestion`）。
- 所有降级原因同时进入融合评估的 `degraded_reasons` 与 API 响应，前端必须显示。
- 制品按路径 + mtime + size 做进程内缓存，训练完成后自动失效，无需重启。

## 3. 替代方案

1. **直接照搬离线脚本**：被否，训练/推理特征不一致且不可解释。
2. **只在离线回放里评分**：被否，无法满足“在线检测”目标。
3. **引入独立的流处理引擎（Flink/Spark Streaming）**：本期不引入，与 ADR-0008 的触发条件一致；采集端批量上传 + 同事务微批评分在当前吞吐下足够。
4. **默认 `enabled` 直接告警**：被否，等于用未评估的模型产生生产告警，违反“禁止伪造能力”。

## 4. 迁移与回滚

- 迁移：`alembic upgrade head`（`20260909_0011`）新增三张表与传感器身份列；已实测 upgrade→downgrade→upgrade。
- 回滚：`EVONIDS_DETECTION_MODE=disabled` 可立即停止全部在线推理（无需迁移）；`alembic downgrade 20260909_0010` 删除信号/评估/批次表并移除传感器列，采集路径仍可用（`ingestion_batches` 写入会失败，因此回滚前应同时把采集端切回 `POST /ingestion/eve`）。

## 5. 成本

- 每批次一次 pandas 构造 + 一次 `predict_proba`/AE 前向；实测在测试数据上单条 < 2 ms（不含模型冷启动）。真实吞吐未测量——本仓库无生产流量，禁止给出吞吐数字。
- 存储：每条信号一行（约 1 KB JSON），每流量 2 行 + 1 行评估；需要按 `detection_signals(flow_id)`、`(channel, created_at)` 做保留策略（见 `docs/runbooks/queue-backlog.md`）。
