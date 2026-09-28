# EvoNIDS Documentation Index

| Document | Language | Contents |
|---|---|---|
| [architecture.md](architecture.md) | English | As-implemented v0.1 system: EVE ingestion → FastAPI → dual-channel scoring → fused alerts → RAG → Agent → rule evolution, with component responsibilities and an explicit "Planned (not yet implemented)" list. |
| [operations.md](operations.md) | English | Task-oriented operations guide: modes, demo launcher, EVE import, dataset registration, training runs, baseline reproduction, container stack. |
| [adr/0001-keep-project-backend-layout.md](adr/0001-keep-project-backend-layout.md) | English | Architecture decision record: why v0.1 keeps the `backend/` + `project/` layout instead of an apps/packages monorepo, and when to revisit. |
| [learning-notes.zh.md](learning-notes.zh.md) | 中文 | The author's personal learning notes on NIDS concepts and the project idea, preserved as written (not maintained as project documentation). |
| [deployment.md](deployment.md)（含"集群部署与备份恢复"章节）、[runbooks/](runbooks/) | 中文 | 单机 Compose 生产部署；Kubernetes/Helm chart（`deploy/helm/evonids/`）、备份脚本（`scripts/backup/`）与中文故障/演练手册（`docs/runbooks/`）的统一入口。 |
| [collector.md](collector.md) | 中文 | Suricata EVE 采集器的部署、幂等批次、spool/dead-letter 失败语义、指标与安全要求。 |
| [model-evaluation.md](model-evaluation.md) | 中文 | 模型评估协议操作手册（时间外/主机留出/家族留出/随机切分、校准、漂移、未测量清单）。 |
| [adr/0008-ingestion-transport-and-hot-path-storage.md](adr/0008-ingestion-transport-and-hot-path-storage.md) | 中文 | 采集传输与热路径存储决策：本期 spool + 批次账本，NATS JetStream/ClickHouse/MinIO 的引入触发条件与迁移路径。 |
| [adr/0009-model-evaluation-protocol.md](adr/0009-model-evaluation-protocol.md) | 中文 | 模型评估协议：CICIDS2017 随机切分不构成生产证据，强制四种切分与未测量禁 0。 |
| [adr/0010-online-detection-and-fusion.md](adr/0010-online-detection-and-fusion.md) | 中文 | 在线检测与可解释风险融合：`flow-online-v1` 特征契约、通道信号/融合评估分离、shadow 默认与开启条件。 |
| [adr/0012-rule-ir-and-suricata-sandbox.md](adr/0012-rule-ir-and-suricata-sandbox.md) | 中文 | 规则 IR、确定性 Suricata 编译、真实沙箱回放与灰度/回滚门禁。 |
| [releases/v0.1.1.md](releases/v0.1.1.md) | 中文 | v0.1.1 生产化发布说明（候选）：真实测量结果、未测量清单、升级与回滚步骤。 |
| [adr/0013-oidc-rbac-and-tenants.md](adr/0013-oidc-rbac-and-tenants.md) | 中文 | OIDC 身份验证、RBAC 权限矩阵、租户/工作区隔离与审计哈希链（含离线校验）。 |
| [security/threat-model.md](security/threat-model.md) | 中文 | 正式威胁模型：12 类威胁 × 资产/路径/现有缓解/残余风险/未实现项。 |
| [integrations.md](integrations.md) | 中文 | 出站集成连接器（Webhook / Syslog-CEF / STIX 2.1 / 工单）的环境变量、API 与安全边界。 |
| Root model/data cards: [MODEL_CARD.md](../MODEL_CARD.md) and [DATA_CARD.md](../DATA_CARD.md) | English | Measured metrics for the delivered HGB baseline and AutoEncoder channels, and the CICIDS2017 derived dataset provenance, hashes and label distributions. |
