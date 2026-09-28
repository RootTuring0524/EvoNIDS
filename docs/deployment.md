# EvoNIDS 单机部署手册（Docker Compose）

面向实验室、企业蓝队与小型安全运营团队的单机生产部署档案。集群（Kubernetes/Helm）属
后续版本，不在本文范围。

## 1. 前置条件

- Docker Engine ≥ 24 + Compose v2（`docker compose version` 验证）
- 至少 4 vCPU / 8 GB RAM 供容器使用（训练任务在 API 容器内执行，见资源限制）
- 可写目录与磁盘空间：模型卷默认持久化在命名卷内
- 一个未提交的 `.env`（见下）

## 2. 初始化（一键启动）

```bash
cd <repo-root>
cp .env.example .env      # 填写全部 change-me
# 本地只读数据挂载（默认 ./backend/datasets 只读挂进 API 容器）
docker compose up -d --build
```

- `docker compose ps`：三个服务 healthy 后即可访问
- 控制台：http://127.0.0.1:3000/overview
- OpenAPI：http://127.0.0.1:8000/docs
- 健康检查：`curl http://127.0.0.1:8000/api/v1/health`

## 3. 生产覆盖（docker-compose.prod.yml）

```bash
cp .env.example .env
# 必填：EVONIDS_ADMIN_API_TOKEN / EVONIDS_SENSOR_INGEST_TOKEN /
#       POSTGRES_PASSWORD / NUXT_CONSOLE_PASSWORD
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

覆盖文件使以下配置**缺失即拒启**（Compose `${VAR:?}` 插值）：

- `EVONIDS_ENVIRONMENT=production`——后端启动期校验会拒绝
  无凭据 / 非 PostgreSQL 的启动（`validate_production_settings`）
- admin/sensor 令牌与 PostgreSQL 密码、console 口令全部必填
- console 会话 Cookie 的 `Secure` 属性由 `NUXT_CONSOLE_COOKIE_SECURE` 显式控制

基础文件同时提供：web 健康检查（Node fetch /api/auth/status）、日志轮转
（json-file 10m×3）、资源限制（postgres 2g/2cpu、api 8g/6cpu、web 1g/2cpu）、
重启策略、备份标签（`org.evonids.backup=required`）。

## 4. TLS（反向代理终止）

Compose 只绑定 `127.0.0.1`。TLS 由前置反向代理终止，示例（Caddy）：

```
evonids.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

HTTPS 就绪后把 `.env` 中的 `NUXT_CONSOLE_COOKIE_SECURE=true`，重新 `up -d`。

## 5. 数据备份与恢复

备份标签标注的持久数据：命名卷 `evonids-postgres`（数据库）与 `evonids-models`
（模型产物）；`./backend/datasets` 为宿主只读数据源（自行纳入备份/版本管理）。

```bash
# 逻辑备份（推荐每日）
docker compose exec -T postgres pg_dump -U evonids -d evonids -Fc \
  > evonids-$(date +%F).dump

# 模型卷备份（卷名按 compose 项目名前缀，用标签过滤最稳）
docker volume ls --filter label=org.evonids.backup=required
docker run --rm -v "$(docker volume ls -q --filter label=org.evonids.backup=required | grep models)":/data -v "$PWD":/backup \
  alpine tar czf /backup/evonids-models-$(date +%F).tgz -C /data .

# 恢复（示例）
docker compose exec -T postgres pg_restore -U evonids -d evonids --clean \
  < evonids-YYYY-MM-DD.dump
```

## 6. 升级 / 回滚 / 卸载

```bash
# 升级：先备份，再重建
docker compose up -d --build          # 生产：加 -f docker-compose.prod.yml
# 回滚：改回上一版镜像 tag/代码并 up -d（数据库迁移不可逆的版本需先恢复备份）
# 卸载（保留数据）：仅停止并移除容器网络
docker compose down                    # 命名卷保留
# 彻底删除（含数据）：
docker compose down -v
```

注意：API 容器启动时自动执行 `alembic upgrade head`；迁移不可逆的大版本升级请先
`pg_dump`。

## 7. 密钥轮换

1. `.env` 中更换目标令牌（admin/sensor 或 console 口令）
2. `docker compose up -d` 重建受影响容器
3. 验证：旧令牌应 401；console 需重新登录
4. 数据库型 API key 在控制台/API `POST /api/v1/admin/api-keys/{id}/revoke` 吊销，
   再新建（详见 backend/README.md "Authentication and API keys"）

## 8. 运维与故障排查

| 症状 | 排查 |
|---|---|
| API 反复重启 | `docker compose logs api`——生产覆盖下缺令牌/PG 会拒启并打印原因 |
| 训练中断标 failed | 进程退出即标失败（设计如此）；重试训练 |
| web 不健康 | `docker compose logs web`；确认 api healthy（depends_on 门禁） |
| 磁盘膨胀 | 日志已限 10m×3；模型卷与 PG 卷按需清理/扩容 |

## 9. 安全注意事项（诚实声明）

- 容器内以非 root（uid 10001）运行；Dockerfile 已多阶段构建 + `--no-cache-dir`
- 本文档与覆盖文件**未在本仓库 CI 中做过容器级验证**（本地无 Docker Engine），
  YAML 已通过解析校验；首次部署请在非生产机演练
- `read_only` 根文件系统、镜像签名、SBOM、容器扫描等属供应链阶段（Phase 1 收尾/
  Phase 7），届时补齐并在此更新

## 10. 集群部署与备份恢复（Kubernetes/Helm 与备份脚本）

本仓库同时提供 Kubernetes/Helm 部署工件与备份/恢复/灾难恢复工具（均为新增文件，
**未在真实集群验证**，见下）。

- **Helm chart**：`deploy/helm/evonids/`——api / web / postgres / 迁移 Job
  （`pre-install,pre-upgrade` hook 执行 `alembic upgrade head`）、NetworkPolicy、
  HPA、PDB 等；使用说明见 `deploy/helm/evonids/README.md`。镜像需自行构建并推送：
  先 `docker compose build api web`，再按 chart 的 `image.*` 值打 tag 推送。
  注意 API 镜像默认在启动时也会执行一次 `alembic upgrade head`（幂等），
  chart 的迁移 Job 负责串行化首次安装/升级的迁移。
- **备份脚本**：`scripts/backup/`（`backup.sh` / `restore.sh` / `verify-backup.sh` /
  Windows 用 `backup.ps1`），对 PostgreSQL 逻辑备份、模型产物与数据集元数据归档，
  含校验和与保留策略；见 `scripts/backup/README.md`。Compose 环境的备份命令仍见
  上文第 5 节。
- **故障手册**：`docs/runbooks/`（中文），覆盖传感器离线、采集积压、训练队列积压、
  迁移失败、LLM 提供商故障、模型/规则回滚、备份恢复演练、安全事件响应与密钥轮换。

诚实声明：本仓库开发机没有 Docker / Helm / kubectl 二进制，也没有可用的 bash
（WSL 未安装发行版），因此 chart 未经过 `helm lint` / `helm template` / `kubectl
apply`，bash 脚本未经过 `bash -n`。首次使用请在非生产集群按
`deploy/helm/evonids/README.md` 与 `docs/runbooks/backup-restore-drill.md` 演练。

## 11. 建表路径与限流注意事项（v0.1.1 新增）

- **唯一建表路径是 Alembic**。EVONIDS_AUTO_CREATE_DB=true 只适用于一次性本地演示：它调用 Base.metadata.create_all，**不会**给已存在的表补列。本仓库的开发库就因此出现过 sensors.agent_version 缺列导致 500 的漂移（修复脚本与教训见 docs/releases/v0.1.1.md）。任何非一次性环境都必须 lembic upgrade head。
- 升级后请确认：select * from alembic_version 为 20260909_0013，且 sensors 含 gent_version、knowledge_evidence 含 workspace_id。
- **限流是进程内的**：EVONIDS_RATE_LIMIT_WRITE_PER_MINUTE / EVONIDS_RATE_LIMIT_INGEST_PER_MINUTE 由每个 API 副本各自计数。多副本部署时实际额度 = 副本数 × 配置值；如需全局额度，应在 Ingress/网关层实现或引入共享计数器（尚未实现，属于未测量/未交付项）。
- 生产环境会自动启用 HSTS 与安全响应头（pp/core/security.py）；EVONIDS_ENVIRONMENT=production 时若 EVONIDS_LLM_PROVIDER=mock 或数据库为 SQLite，进程会拒绝启动。
