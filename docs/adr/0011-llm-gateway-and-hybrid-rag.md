# ADR-0011：LLM Gateway、Claims 与混合检索（Phase 4）

- 状态：已接受（2026-09-09）
- 相关：ADR-0008（采集与存储）、ADR-0009（模型评估协议）、`docs/adr/0010-online-detection-and-fusion.md`

## 1. 问题

v0.1 的 AI 能力是“单次调用 + 关键词检索 + 自由文本结论”：

- 没有统一的供应商抽象：DeepSeek/OpenAI 兼容端点散落在路由里，没有超时、重试、熔断、并发上限、预算；
- 检索是关键词打分（`mode="keyword_fallback"`，`vector_score` 恒为 0），没有 BM25、没有向量、没有检索快照；
- 结论是自由文本，无法逐条回溯到证据，也没有“证据不足拒答”的强制路径；
- 中文 Prompt Injection 关键词在仓库里是乱码字节，实际等于没有中文检测。

## 2. 决策

### 2.1 单一 LLM Gateway（`app/services/llm_gateway.py`）

- 供应商：`openai-compatible`（覆盖 DeepSeek/OpenAI/vLLM/Ollama）、`mock`（仅测试与明确标注的演示，`production` 启动时直接拒绝）、`disabled`（默认，平台在完全关闭 LLM 时仍可采集、检测、告警、案件、规则验证与审计）。
- 每次调用都有：超时、指数退避 + 抖动重试（仅对可重试错误）、并发信号量、熔断器（连续失败阈值 → 打开 → 冷却后半开）、每轮与每日 USD 预算、Prompt 长度上限。
- 成本：只有价格表内的模型才给 `costUsd` 且 `costEstimated=true`；未知模型返回 0 且 `costEstimated=false`，绝不估算成“真实成本”。
- `GET /llm/status` 暴露供应商/模型/熔断状态/预算/统计；`POST /llm/probe` 用 `/models` 校验配置的模型 ID 是否真实存在。

### 2.2 调查运行与 Claims（`investigation_runs` / `investigation_claims` / `tool_executions`）

- 调查在**后台 Worker** 中执行（与训练 Worker 同构），API 只入队并返回 202；
- 每次运行持久化：供应商、模型 ID、Prompt 模板版本、工具注册表版本、知识版本、检索快照、输入证据白名单、Token 用量、延迟、成本、尝试次数、降级原因；
- 每条结论拆成独立 Claim，必须引用白名单内的 `evidence_id`；引用未知证据的 Claim 会被**保存为 rejected 并记录原因**，而不是被悄悄丢弃；
- 若模型输出 `insufficient_evidence` 或所有 Claim 都被拒绝 → 运行状态为 `insufficient_evidence`，不确定性下限 0.5；
- 未配置供应商 → 状态 `degraded`，只保留只读证据与检索快照，**不产生任何推断**。

### 2.3 工具白名单（`app/services/agent_tools.py`）

七个只读工具：`get_evidence`、`list_alert_evidence`、`get_alert`、`get_flow`、`get_detection_signals`、`get_entity`、`search_knowledge`。没有任意 URL、文件、命令或写操作工具；参数逐字段校验类型与长度，未知参数直接拒绝；`evidenceId` 必须落在本次调查的白名单内；每次调用写入 `tool_executions`（参数与结果均脱敏、截断）。

### 2.4 混合检索（`app/services/knowledge_retrieval.py`）

- BM25（k1=1.5, b=0.75）+ 向量余弦，各自在候选集内 min-max 归一化后按 0.55/0.45 融合，再乘信任权重（high 1.0 / medium 0.85 / low 0.55）；
- 默认嵌入器是**离线确定性签名哈希 n-gram**（`hashing-256-v1`）：它是词法近似，不是语义模型，标签已写入接口与检索快照；配置 `EVONIDS_EMBEDDING_PROVIDER=openai-compatible` 可切换到真实嵌入端点；pgvector 是明确的扩容路径；
- 过滤：`workspace_id` 租户隔离、`allowed`、`prompt_injection_risk != none`、过期时间；
- 每次检索生成 `RetrievalSnapshot`（模式、权重、嵌入模型、知识版本、候选数、返回/被过滤 ID、逐条分数），并随调查持久化，可复现；
- Prompt Injection 检测修复了中文乱码标记，覆盖中英文常见指令覆盖与越狱表达。

## 3. 替代方案

1. 直接在路由里调用 httpx：被否，无法统一预算/熔断/审计。
2. 依赖供应商原生 function-calling：被否，DeepSeek/vLLM/Ollama 兼容性不一致，且需要把工具描述交给不可信上下文；本期用“预取 + 至多一轮补充工具请求”的确定性循环，行为可审计。
3. 只用关键词检索：被否，目标要求真实混合检索；但保留 BM25 作为向量不可用时的降级路径。
4. 用真实嵌入模型作为默认：本机无网络/无凭据，无法验证；默认哈希嵌入是诚实选择，语义质量**未测量**。

## 4. 迁移与回滚

- 迁移：`alembic upgrade head`（`20260909_0012`）新增四张表与知识表嵌入列；`knowledge_evidence.embedding` 用 `none_as_null=True`，未嵌入行为 SQL NULL，可由 `backfill_embeddings()` 补齐；
- 回滚：`EVONIDS_LLM_PROVIDER=disabled` 立即停用 AI（无需迁移）；`alembic downgrade 20260909_0011` 删除四张表与嵌入列（已有检索结果仍在审计日志与调查行中不可用，因此回滚前应导出）。

## 5. 成本与未测量项

- 单次调查 = 1–2 次模型调用 + 最多 6 次只读工具调用；
- **未测量**：真实供应商的端到端延迟、成本、Token 消耗、Prompt Injection 拦截率、Claim 准确性——本仓库没有可用凭据，也没有标注过的调查评测集。`mock` 只用于测试与明确标注的演示，不构成任何质量证据。
