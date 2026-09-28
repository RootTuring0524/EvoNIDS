# Runbook：数据库迁移失败（database-migration-failure）

> 适用环境：Compose 单机（api 镜像启动即 `alembic upgrade head`，见
> `backend/Dockerfile` 的 CMD）与 Kubernetes（Helm hook Job
> `evonids-migration`，`pre-install,pre-upgrade`）。
> **本机无 Docker/集群/库，命令未在本环境执行（未验证）。**

## 症状

- Compose：`docker compose ps` 中 api 处于 `restarting`/非 healthy；`logs api`
  显示 Alembic 异常（`alembic upgrade head` 步骤失败）。
- Kubernetes：`helm install/upgrade` 停在迁移 Job，Job Pod 失败（
  `kubectl get jobs -n evonids` 显示失败/重试）；api Pod 就绪前反复 CrashLoop
  （镜像启动仍会再跑一次迁移）。
- 迁移脚本中途报错：列已存在、约束冲突、`ValueError`、不可逆变更等。

## 影响面

- 发布被阻塞；若迁移已部分写入（Alembic 单迁移在事务内，但多迁移串行），
  新代码可能面对半迁移 schema。
- 生产配置下启动前校验（`validate_production_settings`）也会拒启，需先排除
  配置类原因（缺 `EVONIDS_ADMIN_API_TOKEN` / `EVONIDS_SENSOR_INGEST_TOKEN` /
  非 PostgreSQL URL）。

## 立即处置步骤（可复制命令）

```bash
# 1) 备份数据库（任何迁移动作前必做，见 scripts/backup/README.md）
PGPASSWORD="$POSTGRES_PASSWORD" ./scripts/backup/backup.sh --env-file .env
./scripts/backup/verify-backup.sh

# 2) 读日志定位失败点
docker compose logs api --tail 200            # 迁移栈 + 具体 SQL/异常
# 3) 判断失败点落在哪个 revision：backend/alembic/versions/ 下按文件名时间排序，
#    或容器内查询当前版本（api 可能起不来，用 postgres 容器）
docker compose exec -T postgres psql -U evonids -d evonids -c \
  "SELECT version_num FROM alembic_version;"

# 4) 配置类错误（缺令牌/URL）：修正 .env 后重启，无需动迁移
#    EVONIDS_ENVIRONMENT=production 下必须同时有 EVONIDS_ADMIN_API_TOKEN、
#    EVONIDS_SENSOR_INGEST_TOKEN 且 EVONIDS_DATABASE_URL 为 postgresql://
docker compose up -d

# 5) 迁移脚本本身失败：先用一次性容器手工重跑，看能否恢复（不覆盖线上数据）
docker compose run --rm api alembic upgrade head

# 6) 若不可原地恢复且存在 down_revision 支持回退，才考虑回退一格：
#    （先确认该 revision 写了 down_revision；无 down 脚本 = 不可回退，别硬来）
docker compose run --rm api alembic downgrade -1
```

Kubernetes 变体（未验证）：

```bash
kubectl -n evonids logs job/evonids-migration --tail=200
kubectl -n evonids describe job/evonids-migration
# 修复配置/代码后重新触发（helm hook 每次 upgrade 会先删旧 Job 再跑）
helm upgrade --install evonids deploy/helm/evonids -f deploy/helm/evonids/values-production.yaml \
  --set secrets.adminApiToken='...' --set secrets.sensorIngestToken='...' \
  --set secrets.postgresPassword='...' --set secrets.consolePassword='...'
```

## 验证恢复

```bash
docker compose exec -T postgres psql -U evonids -d evonids -c \
  "SELECT version_num FROM alembic_version;"        # 等于最新 versions 文件名前缀
docker compose ps                                    # 三服务 healthy
curl -s http://127.0.0.1:8000/api/v1/health          # {"status":"ok","database":"ok",...}
curl -s http://127.0.0.1:8000/api/v1/readiness | python -m json.tool
# Kubernetes：helm test evonids -n evonids；kubectl -n evonids get pods
```

## 根因分析

1. 迁移与代码/数据现状不一致（旧数据不满足新约束、重复键等）。
2. 多副本/重复执行并发迁移（Alembic 无分布式锁；Compose 单副本安全，
   集群靠 hook Job 串行 + api 启动幂等空跑）。
3. 配置错误（生产校验拒绝启动，症状类似迁移失败）。
4. 不可逆迁移缺 down_revision，回退只能靠恢复备份。

## 预防措施

- 每次升级前强制 `scripts/backup/backup.sh`（deployment.md 第 6 节同样要求）。
- 迁移先在小数据副本上演练；大版本升级执行 `docs/runbooks/backup-restore-drill.md`。
- 新迁移必须自带幂等/可回退评估；标注“不可逆”并写进 CHANGELOG。
- 集群场景始终让 hook Job 串行负责迁移，api 副本保持 1（见 chart README）。

## 责任人与升级路径

- 一线：值班运维按上文 1–3 判断“配置类 vs 迁移脚本类”并备份。
- 升级：迁移脚本缺陷 → 后端负责人出修复 revision 后重新发布；
  需恢复数据 → 按 `scripts/backup/restore.sh`（`--confirm`）回滚到最近良好备份，
  同时升级应用负责人核对“代码版本 + schema 版本”组合。
