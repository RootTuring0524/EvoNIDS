# ADR-0008：采集传输与热路径存储决策（Phase 3）

- 状态：已接受（2026-09-09）
- 相关：ADR-0004（进程内训练 Worker）、ADR-0010（在线检测与风险融合）

## 1. 问题

生产化目标建议引入 NATS JetStream（可靠事件流）、ClickHouse（高容量分析）与 S3/MinIO（原始证据对象存储）。当前代码只有一条路径：

- 传感器通过 `POST /api/v1/ingestion/eve` 提交 NDJSON；
- FastAPI 请求进程直接解析、写 SQLite/PostgreSQL，并在同一事务内写入证据与实体；
- 没有本地缓冲、没有幂等批次、没有断线续传、没有背压、没有采集端指标；
- 传感器身份只有共享的 `sensor_ingest_token`，无法区分具体探针。

同时本仓库当前环境**无法运行 Docker/NATS/ClickHouse/MinIO**（无 Docker、无网络拉取镜像），因此“引入组件”这一决策既无法验证，也无法给出真实负载测试数据。按工程原则（禁止伪造、禁止用展示替代实现），不能把未验证的分布式组件写进架构声称。

## 2. 决策

### 2.1 本期实现（已落地）

1. **采集端（`app/collector/`）承担可靠性**：
   - 批次先原子落盘（`os.replace` + `fsync`）再发送，只有服务端确认后才删除；
   - 指数退避 + 抖动 + 最大重试次数；`Retry-After` 优先；
   - 稳定批次号 `X-Evonids-Batch-Id`，服务端按 `(sensor_id, batch_id)` 幂等；
   - gzip 压缩、事件数/字节数/速率上限、磁盘 spool 上限（超限拒绝新数据而不是覆盖旧数据）；
   - 心跳上报 agent 版本、能力、spool 深度、丢弃计数、时钟偏差；
   - 4xx（除 408/429）与批次号冲突进入 `dead-letter/` 并附原因文件，绝不静默丢弃。
2. **服务端（`ingestion_batches` 表）承担幂等与审计**：每个批次一行，记录内容 SHA-256、编码、字节数、事件数、接受/重复/拒绝计数、首末事件时间、时钟偏差与状态。
3. **PostgreSQL 作为本期唯一事实来源**：控制面数据、证据、批次账本、检测信号与融合评估同库，事务边界清晰；`detection_signals` / `risk_assessments` 为追加写入。
4. **传感器身份**：`sensors.enrolled_key_id` 绑定 scoped API key（ADR-0003），`certificate_fingerprint` 为 mTLS 预留；生产环境要求 TLS 终止并配置 mTLS（见 `docs/deployment.md`）。

### 2.2 本期**不**引入（并说明触发条件）

| 组件 | 本期决策 | 引入触发条件（任一满足即重新评审） |
| --- | --- | --- |
| NATS JetStream | 不引入，采集端 spool + 服务端批次账本承担缓冲 | 持续入站 > 5,000 事件/秒；或需要多消费者/多下游（检测、归档、重放各自消费）；或采集端 spool 深度在 1 小时内无法回落 |
| ClickHouse | 不引入，事件明细存 PostgreSQL（含 JSON 特征） | 事件表 > 5 亿行；或分析查询 p95 > 3 秒；或需要保留 > 30 天全量事件 |
| MinIO/S3 | 不引入，证据原文存 `evidence_artifacts`（单条 ≤ 1 MiB） | 需要保存原始 PCAP/大对象；或证据总量 > 50 GiB；或需要对象级生命周期与不可变保留 |
| Redis | 不引入（也不作为事实来源） | 仅当需要跨进程共享限流/缓存，且可随时丢弃 |

**未测量的部分必须明说**：本仓库当前没有 NATS/ClickHouse/MinIO 的负载测试数据，也没有 Docker 环境可运行它们，因此“现有方案足以满足目标”这一结论只在单机/中小规模（≤ 5,000 事件/秒、≤ 30 天热数据）范围内成立；超出该范围时以本 ADR 的触发条件为准。

### 2.3 实测记录（2026-09-10，v0.1.1）

ADR 的容量判断必须有测量支撑。本机实测（Windows 10 / 16 逻辑 CPU / Python 3.11.1 / SQLite / 单进程 / **关闭在线检测**）：

| 场景 | 结果 |
| --- | --- |
| 直接调用 `ingest_eve_batch`，400 事件/批 | 1.35 s → **≈296 事件/秒** |
| 同上，800 事件/批 | 5.01 s → ≈160 事件/秒 |
| 同上，2000 事件/批 | 14.51 s → ≈138 事件/秒 |
| 批量实体/证据路径优化前的基线（400 事件/批） | 1.96 s → ≈204 事件/秒（优化后提升约 45%） |
| HTTP 采集器，4 并发连接，500 事件/批 | **退化到每批 77 秒，API 一度无响应**（SQLite 单文件写锁竞争） |

结论（如实）：

1. **PostgreSQL 下的真实容量未测量**（本机无 Docker/PostgreSQL）；上表是 SQLite 单文件库的数字，不能当作生产容量。
2. 当前单进程摄取吞吐（≈140–300 事件/秒）**远低于**触发条件里的 5,000 事件/秒，因此“不引入 JetStream/ClickHouse”的结论在本机数据上**尚未被证明**，只是尚未被证伪。
3. 4 并发写导致 API 不可用说明：**SQLite 不适合作为采集热路径**，生产必须使用 PostgreSQL（`validate_production_settings` 已在 production 拒绝 SQLite）。
4. 触发条件不变：一旦在 PostgreSQL 上测得持续入站超过 5,000 事件/秒、或采集端 spool 深度无法回落，即按第 3 节路径引入 JetStream/ClickHouse/MinIO。

## 3. 迁移路径（当触发条件满足时）

1. 采集端不变（仍然按批次上传）；新增 `EVONIDS_INGEST_TRANSPORT=jetstream` 时采集端改为发布到 `evonids.events` 主题，服务端消费者写入同一 `ingestion_batches` 账本（幂等键不变）。
2. PostgreSQL 保留控制面与最近 N 天热数据；ClickHouse 通过同一批次号回填历史事件，读路径按查询类型分流（明细 → ClickHouse，控制面 → PostgreSQL）。
3. 证据原文迁移到 S3/MinIO，`evidence_records.source_ref_*` 不变，新增 `artifact_uri`；对象名 = 证据 ID，校验用现有 `content_sha256`。
4. 每一步都要求：影子写入双跑 ≥ 1 周、批次号幂等校验一致、回滚时能退回 PostgreSQL 单库（见下）。

## 4. 回滚

- 采集端：`--spool` 目录保留全部未确认批次，可直接改回 HTTP 直传；服务端批次账本不删除。
- 服务端：本期所有变更都是一次性 Alembic 迁移（`20260909_0011`），`alembic downgrade 20260909_0010` 可完整回退（已实测 upgrade→downgrade→upgrade 通过）。
- 未来引入 JetStream/ClickHouse/MinIO 时，回滚 = 关闭消费者、保留主题/表/桶数据，切回 PostgreSQL 单库读取。

## 5. 成本与代价

- 采集端落盘引入一次 `fsync`/批次（约 1–5 ms），换来崩溃不丢数据；可用 `--batch-max-events` 调整。
- 服务端窗口特征（60 秒目的端口/目的地址/流量计数）每批次一次聚合查询，按 `(sensor_id, source)` 缓存；单批次内同源流量只查一次。
- 未引入 JetStream/ClickHouse 意味着**没有**跨进程多消费者与列式分析能力，这是明确接受的现状，不是已完成能力。
