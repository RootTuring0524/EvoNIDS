# EvoNIDS Runbooks（中文故障与演练手册）

每篇均按统一结构编写：症状 / 影响面 / 立即处置步骤（可复制命令）/ 验证恢复 /
根因分析 / 预防措施 / 责任人与升级路径。命令基于仓库真实路径与环境变量名
（`docker-compose(.prod).yml`、`backend/app/core/config.py`、`scripts/backup/`、
`deploy/helm/evonids/`）。

> 环境声明：仓库开发机无 Docker/Helm/kubectl/可用 bash，也无可连接的数据
> 库/集群，因此各篇命令**均未在本环境执行（未验证）**。请先在非生产环境演练；
> 与备份/恢复相关的以 `backup-restore-drill.md` 为准。

| Runbook | 场景 | 关键引用 |
|---|---|---|
| [sensor-offline.md](sensor-offline.md) | 探针离线/降级 | `POST /api/v1/sensors/{id}/heartbeat`、`/api/v1/readiness` |
| [ingestion-backlog.md](ingestion-backlog.md) | EVE 采集积压/慢 | `POST /api/v1/ingestion/eve`、web BFF `/api/ingestion/eve` |
| [queue-backlog.md](queue-backlog.md) | 训练队列（`training_runs` queued）积压 | ADR 0004、进程内 worker |
| [database-migration-failure.md](database-migration-failure.md) | Alembic 迁移失败 | `alembic upgrade head`、Helm hook Job |
| [llm-provider-outage.md](llm-provider-outage.md) | DeepSeek/上游 LLM 故障 | `NUXT_DEEPSEEK_*`、NetworkPolicy 出网 |
| [model-rollback.md](model-rollback.md) | 模型制品/版本回滚 | `EVONIDS_MODEL_ARTIFACT_ROOT`、backup.sh |
| [rule-rollback.md](rule-rollback.md) | 规则下线/重建 | `rule_lifecycle.py`、`/rules/{id}/deprecate` |
| [backup-restore-drill.md](backup-restore-drill.md) | 备份恢复演练（季度） | `scripts/backup/*` |
| [security-incident-response.md](security-incident-response.md) | 凭据泄露/异常访问 | `/api/v1/audit`、API key revoke |
| [key-rotation.md](key-rotation.md) | 密钥轮换（常规/应急） | `EVONIDS_*_TOKEN`、`POSTGRES_PASSWORD` |

配套文档：单机部署 [docs/deployment.md](../deployment.md)（含“集群部署与备份恢复”）、
运维指南 [docs/operations.md](../operations.md)、Helm chart
[deploy/helm/evonids/README.md](../../deploy/helm/evonids/README.md)、备份工具
[scripts/backup/README.md](../../scripts/backup/README.md)。
