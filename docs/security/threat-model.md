# EvoNIDS 威胁模型（Threat Model）

- 版本：v0.1.1（2026-09-10）
- 范围：单机/中小规模部署（Docker Compose 或 Helm），数据平面（采集）、控制平面（API/控制台）、AI 调查平面
- 方法：按资产列威胁 → 攻击路径 → **现有缓解（引用真实文件/函数）** → 残余风险 → 检测方式 → 未实现项
- 诚实声明：本文只描述**代码里真实存在**的缓解。标注“未实现”的条目就是没有，不要按已缓解对待。

## 0. 资产清单

| 资产 | 位置 |
| --- | --- |
| 原始事件与证据（含可能敏感的载荷） | `evidence_records` / `evidence_artifacts`，原文上限 1 MiB（`app/services/evidence.py`） |
| 检测结论与融合评估 | `detection_signals` / `risk_assessments` |
| 案件、实体、时间线 | `cases` / `case_alerts` / `case_timeline_events` / `entities` |
| 规则与部署状态 | `rule_ir_versions` / `rule_deployments` / `sensor_groups` |
| 模型制品 | `model-artifacts/**`（含 SHA-256） |
| 审计日志 | `audit_events`（哈希链） |
| 凭据 | scoped API Key（哈希存储）、OIDC 令牌、LLM/嵌入供应商密钥（服务端） |
| 知识库 | `knowledge_evidence`（含嵌入向量） |

## 1. 恶意传感器

- **路径**：伪造 sensor 身份上传垃圾/误导事件，污染检测与统计。
- **现有缓解**：scoped `sensor` API Key（`app/services/api_keys.py`，只存 salted SHA-256）；`Authorization: Bearer` 与 scoped header 双通道（`app/api/security.py::_supplied_credential`）；批次幂等键 `(sensor_id, batch_id)` 与内容哈希校验（`ingestion_batches`，内容不同即 409）；事件数/字节数上限（`EVONIDS_COLLECTOR_MAX_BATCH_EVENTS/PAYLOAD_BYTES`）；传感器数据质量指标（拒绝率/重复率/缺口/时钟偏差，`app/services/sensor_health.py`）。
- **残余风险**：单一共享 sensor token 仍是默认引导路径；`sensors.certificate_fingerprint` 已预留但**mTLS 未强制**。
- **检测**：拒绝率/重复率突增、单传感器事件量异常、批次哈希冲突。
- **未实现**：强制 mTLS、传感器级速率配额、密钥自动轮换。

## 2. 伪造 EVE 日志

- **路径**：向摄取端点灌入构造的 EVE JSON，制造虚假告警或掩盖真实活动。
- **现有缓解**：严格解析（`app/ingestion/eve.py`，缺 timestamp 即拒绝）；每条事件写入内容 SHA-256 与解析器版本（`evidenve_records`/`EV-P-`）；`data_missing`/`integrity` 标记；客户端声明的 `actor` 一律忽略，审计 actor 由服务端 principal 决定（`app/api/security.py::request_actor`）。
- **残余风险**：传感器侧时钟与内容真实性无法脱离签名验证；`community_id` 未做交叉校验。
- **检测**：同 flow_id 内容不一致、来源 IP 与传感器资产不匹配、时钟偏差异常。

## 3. Prompt Injection

- **路径**：知识库条目或证据文本中嵌入指令，操纵 LLM 输出。
- **现有缓解**：中英文注入标记检测（`app/services/knowledge_retrieval.py::detect_prompt_injection`，**已修复中文乱码导致中文检测失效的缺陷**）；`prompt_injection_risk=blocked` 的条目不进入模型上下文；检索时按 trust/workspace/过期过滤；工具白名单（`app/services/agent_tools.py`，无任意 URL/文件/命令）；Claim 必须引用白名单内 `evidence_id`（`app/services/investigation.py::validate_claims`），越界引用保存为 rejected。
- **残余风险**：标记检测是启发式的，未知变体可绕过；模型仍可能被间接影响（输出结构受校验，但内容不受）。
- **检测**：rejected claim 比例、`blocked` 知识条目数量、`degraded_reasons`。
- **未实现**：独立注入评测集、内容级系统提示隔离（提示词工程替代不了模型侧隔离）。

## 4. 模型供应链

- **路径**：训练脚本/依赖/制品被替换，导致模型输出被操纵。
- **现有缓解**：制品写入 SHA-256（`TrainingRun.artifact_sha256`、`ModelVersion.parameters.artifactSha256`）；依赖版本区间固定在 `pyproject.toml`；CI 运行 `pip-audit`（continue-on-error，仍为建议态）。
- **残余风险**：**加载制品时不校验 SHA-256**（只记录），torch/sklearn 供应链未做完整性校验。
- **未实现**：制品签名、SBOM 生成与校验、容器镜像签名、模型加载时哈希校验。

## 5. 规则供应链

- **路径**：注入恶意/错误规则，造成漏报或大规模误报。
- **现有缓解**：规则必须以规范化 Rule IR 提交并逐字段校验（`app/domain/rule_ir.py`）；编译确定性且转义（`compile_suricata`，有注入测试）；**部署前置条件是存在 `passed=true` 的沙箱运行**（`app/services/rule_deployment.py::deploy_rule`），否则 409；PCAP 路径必须位于语料根目录内（`app/services/replay_corpus.py`，防本地文件读取）；灰度 → 提升 → 回滚全程审计。
- **残余风险**：本机无 Suricata 时验证为 `blocked`，若运维跳过真实验证直接部署（代码会拒绝，但运维可改配置）。
- **未实现**：SID 冲突检查（部分实现于本地分配段校验）、按规则来源的信任分级。

## 6. 越权部署

- **路径**：非授权用户部署规则、改传感器、回滚模型。
- **现有缓解**：RBAC 权限矩阵默认拒绝（`app/services/rbac.py`，`rule:deploy`/`rule:confirm`/`model:rollout` 等）；admin 专属依赖（`require_admin_token`）；提升需 production 分组（`promote_deployment`）；回滚必须写明 ≥10 字符原因；全部写入审计链。
- **残余风险**：控制台 BFF 持有单一 admin token，浏览器侧一旦被 XSS 即可发起管理动作（见第 12 条）。
- **未实现**：双人复核（four-eyes）、部署审批工作流。

## 7. 数据投毒

- **路径**：向训练数据集注入被污染的样本，使模型对特定攻击失明。
- **现有缓解**：数据集注册含 SHA-256（`DatasetAsset.sha256`）；训练运行记录 `dataset_sha256` 与特征版本；评估协议强制时间外/主机留出/家族留出（ADR-0009，`app/services/model_evaluation.py`）。
- **残余风险**：数据集本身由外部来源提供，无签名校验；无训练数据来源审计链。
- **未实现**：数据集签名、训练样本溯源、异常样本统计检测。

## 8. 训练制品替换

- **路径**：替换 `model-artifacts/**` 中的 joblib，令推理输出被控制。
- **现有缓解**：制品路径记录在注册表；发布状态（shadow/canary/active/retired）由 RBAC 管理并审计（`app/services/model_registry.py`）；`retired` 模型永不被选用；`active` 需制品可读。
- **残余风险**：加载时不校验哈希（同第 4 条）；文件系统权限即边界。
- **未实现**：加载期哈希校验、制品目录只读挂载（Helm 已声明，未实测）。

## 9. 租户数据泄漏

- **路径**：跨工作区读取案件/证据/调查。
- **现有缓解**：`workspace_id` 列 + 强制过滤（迁移 0014，`app/services/rbac.py::workspace_filter`）；写入的工作区由 principal 推导，客户端值被忽略；知识库检索按 `workspace_id` 过滤。
- **残余风险**：只覆盖 5 张表；未做跨租户的自动化隔离测试套件（部分测试存在）；同实例内没有数据库级 RLS。
- **未实现**：PostgreSQL RLS、工作区管理 API、跨租户渗透测试。

## 10. SSRF

- **路径**：通过 LLM 工具或集成连接器请求内网/云元数据地址。
- **现有缓解**：智能体**没有**任意 URL 工具；集成出站目标经过 SSRF 守卫（`app/integrations/url_guard.py`）：仅允许 https（除非显式 opt-in http）、拒绝 loopback/私有/链路本地/元数据地址、allow-list 权威、超时与不跟随重定向；`resolver` 可注入，测试不触网。
- **残余风险**：守卫无法把已解析地址钉死到后续连接（DNS rebinding 窗口），已在该模块文档中标注。
- **未实现**：连接级地址固定（自定义 socket factory）、出站代理白名单。

## 11. 凭据泄漏

- **路径**：密钥进入日志、响应或提交历史。
- **现有缓解**：API Key 只存哈希；LLM/嵌入密钥仅服务端（`SecretStr`），从不返回浏览器；日志走 `JsonFormatter`，只输出结构化字段；工具与集成输出统一脱敏（`app/services/agent_tools.py::redact_text`、`app/integrations/redaction.py`，模式含 `sk-*`、JWT、私钥、`Authorization`）；CI 增加仓库卫生扫描（机器路径与私钥）。
- **残余风险**：脱敏是模式匹配，非常规格式的密钥可能漏网；`backend/.env` 若被误提交（`.gitignore` 已覆盖）。
- **未实现**：集中式密钥管理（Vault/Secrets Manager）、运行时密钥扫描。

## 12. 审计篡改

- **路径**：攻击者修改/删除审计记录以掩盖行为。
- **现有缓解**：每工作区哈希链（`app/services/audit_chain.py`，mapper 层强制入链）；`GET /audit/integrity` 重算并定位断裂（序号缺口/前哈希不符/内容哈希不符）；`GET /audit/export` + `POST /audit/verify` 支持**离线**验证；迁移前历史行明确标记为 `unchained`。
- **残余风险**：链本身存于同一数据库，拥有数据库写权限的攻击者可整体重写链尾（需外部锚定：定期导出并异地保存哈希头）。
- **未实现**：链头外锚定（签名批次/不可变存储/时间戳服务）、审计导出自动归档。

## 13. 其他已知缺口（不在上述 12 类但必须记录）

- **SQL 注入 / XSS**：全部数据访问经 SQLAlchemy ORM 参数化，前端 Vue 默认转义；但**没有针对性的注入测试**。
- **多副本限流**：`app/core/security.py` 的限流是进程内的，多副本下额度按副本数放大（已文档化）。
- **推理/检测吞吐**：SQLite 上实测单进程约 140–300 事件/秒（关闭检测），4 并发采集写会导致单文件库锁竞争直至不可用（见 ADR-0008 实测记录）。这是**容量风险**，不是安全风险，但在 DDoS 场景下会退化为拒绝服务。

## 14. 复核清单（每次发布前）

1. `GET /api/v1/audit/integrity` 返回 `valid: true`；
2. `GET /api/v1/detections/status` 的 `contractMatches` 与 `mode` 符合预期；
3. `GET /api/v1/rule-governance/sandbox-capability` 的本机结论与部署环境一致（无 Suricata 时不得声称已验证）；
4. 仓库卫生扫描无机器路径/私钥；
5. `.env` 未入库、生产环境凭据齐备（`validate_production_settings` 会在启动时拒绝不符的配置）。
