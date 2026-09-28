# EvoNIDS 备份与恢复工具（scripts/backup）

面向单机 Compose 生产栈与本地开发/实验机的备份、校验与恢复工具；Kubernetes
（Helm chart，`deploy/helm/evonids/`）环境可通过端口转发复用同一套脚本，
见下文“Kubernetes 用法”。

| 文件 | 作用 |
|---|---|
| `backup.sh` | PostgreSQL 逻辑备份（`pg_dump -Fc`）+ 模型产物归档 + 数据集元数据清单，产物带 SHA-256 校验和与保留策略（POSIX/Linux） |
| `restore.sh` | 先校验校验和，`--dry-run` 预览，`--confirm` 才真正恢复（POSIX/Linux） |
| `verify-backup.sh` | 校验和 + `pg_restore --list` 目录可读性 + tar/gzip 完整性检查 |
| `backup.ps1` | Windows 单节点（SQLite 演示库或 Compose PostgreSQL）备份等价物 |
| `README.md` | 本文档 |

> **验证状态（诚实声明）**：本仓库开发机没有 Docker/Helm/kubectl，且没有可用的
> bash（WSL 未安装发行版），因此这些脚本**未在本机执行过**，`bash -n` 无法运行。
> 首次使用前请先在 POSIX 主机上执行 `bash -n backup.sh restore.sh verify-backup.sh`，
> 并按 `docs/runbooks/backup-restore-drill.md` 做一次演练。

## 备份内容

1. **数据库**：`pg_dump -Fc`（自定义格式，含数据集注册元数据 `dataset_assets`、
   模型版本元数据 `model_versions`、审计日志等全部表）。Windows 的
   `backup.ps1` 在本地 SQLite 演示模式下改为复制 `backend/evonids.db`
   （含 `-wal`/`-shm`）。
2. **模型产物**：`EVONIDS_MODEL_ARTIFACT_DIR`（Compose 单机默认对应
   `evonids-models` 卷；本地默认 `backend/model-artifacts`）打成
   `model-artifacts-<ts>.tar.gz`。
3. **数据集元数据**：数据库中 `dataset_assets` 的登记清单导出为
   `datasets-manifest-<ts>.txt`（侧车文件；权威数据仍在 dump 内）。
   CSV 文件本身体积可能很大，默认**不**备份；需要时加 `--include-datasets`
   （或 `backup.ps1 -IncludeDatasets`）。

## 环境变量

脚本只认环境变量，不写死任何路径：

| 变量 | 说明 |
|---|---|
| `PGHOST` / `PGPORT` / `PGUSER` / `PGPASSWORD` / `PGDATABASE` | PostgreSQL 连接。`backup.sh` / `restore.sh` 缺任一个即拒绝运行 |
| `POSTGRES_*` | 备选：配合 `--env-file <repo>/.env` 自动映射为 PG* |
| `EVONIDS_BACKUP_DIR` | 备份根目录（默认 `<repo>/backups`，请加入 `.gitignore`） |
| `EVONIDS_MODEL_ARTIFACT_DIR` | 模型产物目录（默认 `<repo>/backend/model-artifacts`） |
| `EVONIDS_DATASETS_DIR` | 数据集文件目录（默认 `<repo>/backend/datasets`） |
| `EVONIDS_BACKUP_RETENTION_DAYS` | 按天裁剪旧备份（默认 30；0=关闭） |
| `EVONIDS_BACKUP_KEEP_LATEST` | 至少保留的最新备份数（默认 14） |

## 用法（Linux / POSIX）

```bash
cd <repo-root>

# 1) Compose 栈：数据库发布在 127.0.0.1:5432（POSTGRES_* 在根 .env）
PGPASSWORD='...' ./scripts/backup/backup.sh --env-file .env --backup-dir ./backups
# 或显式 PG*：
export PGHOST=127.0.0.1 PGPORT=5432 PGUSER=evonids PGPASSWORD='...' PGDATABASE=evonids
./scripts/backup/backup.sh --include-datasets

# 2) 校验最新备份
./scripts/backup/verify-backup.sh
# 或指定目录
./scripts/backup/verify-backup.sh backups/evonids-20260101-120000

# 3) 恢复前演练（只校验 + 打印计划，不写库）
./scripts/backup/restore.sh --dry-run

# 4) 真正恢复（先看 dry-run 输出；--clean 会重建目标库中的对象）
./scripts/backup/restore.sh --confirm
# 数据库 + 模型产物一起恢复：
./scripts/backup/restore.sh --confirm --restore-files
```

产物目录结构（每个备份一个目录，便于原子复制到异地）：

```
backups/evonids-20260101-120000/
├── evonids-db-20260101-120000.dump
├── datasets-manifest-20260101-120000.txt
├── model-artifacts-20260101-120000.tar.gz
├── datasets-files-20260101-120000.tar.gz   # 仅 --include-datasets
├── SHA256SUMS.txt
└── backup.json
```

## 用法（Windows 开发/实验机）

```powershell
cd <repo-root>
# Compose PostgreSQL 模式（读取 .env 的 POSTGRES_*）
powershell -ExecutionPolicy Bypass -File .\scripts\backup\backup.ps1
# 本地 SQLite 演示模式（后端 backend\evonids.db）
#   停止演示后复制最一致：.\stop-demo.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\backup\backup.ps1
# 参数：-IncludeDatasets -Keep 14 -SkipDb（仅文件）
```

## 定时备份建议

- Linux cron（每天 02:00，保留策略在脚本内）：
  ```cron
  0 2 * * * cd /srv/evonids && ./scripts/backup/backup.sh --env-file .env >> backups/backup.log 2>&1
  ```
- Windows 任务计划程序调用 `backup.ps1`。
- Compose 卷级（`docker volume ls --filter label=org.evonids.backup=required`）
  的离线快照见 `docs/deployment.md` 第 5 节；Kubernetes 卷快照是集群侧职责。

## Kubernetes（Helm）用法

```bash
# 端口转发后把 PGHOST/PGPORT 指过去，复用同一脚本
kubectl -n evonids port-forward svc/evonids-postgres 5432:5432 &
export PGHOST=127.0.0.1 PGPORT=5432 PGUSER=evonids PGPASSWORD='...' PGDATABASE=evonids
./scripts/backup/backup.sh

# 卷级数据（postgres 数据 / api 的 datasets+models）也可用存储快照：
#   kubectl -n evonids get pvc evonids-postgres evonids-data
```

## 限制与注意事项

- 逻辑备份不是 WAL/卷级备份：RPO 取决于备份频率。需要更小 RPO 时请叠加
  `pg_basebackup`/卷快照/托管数据库。
- 恢复会**覆盖**目标库现有对象（`pg_restore --clean --if-exists`），目标库需先存在。
- `restore.sh` 默认不含 `--restore-files`（避免意外覆盖模型产物）。
- 数据库密码中的 URL 保留字符与 Compose 同规则：请使用可直接用于连接串的取值。
- `backup.ps1` 的 PostgreSQL 模式要求本机有 `pg_dump`（PATH）或可用 Docker
  （`docker compose exec`），SQLite 模式只复制文件，无 SQLite 一致性保证
  （演示暂停后复制最稳妥）。
