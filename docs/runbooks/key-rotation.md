# Runbook：密钥轮换（key-rotation）

> 适用：常规轮换（建议每 90 天）或泄露应急（配合
> `security-incident-response.md`）。涉及真实凭据：
> `EVONIDS_ADMIN_API_TOKEN`、`EVONIDS_SENSOR_INGEST_TOKEN`、
> `EVONIDS_ANALYST_API_TOKEN`（可选）、`NUXT_CONSOLE_PASSWORD`、
> `POSTGRES_PASSWORD`、`NUXT_DEEPSEEK_API_KEY`（可选），以及数据库 API key。
> **本机无 Docker/集群/库，命令未在本环境执行（未验证）。**

## 症状

- 到达轮换周期 / 疑似泄露 / 人员离岗，需要吊销旧凭据。
- 观察到旧凭据的意外使用（见 security-incident-response runbook）。

## 影响面

- 轮换期间短暂的双写窗口可避免中断：先让服务端接受新值，再切换客户端，
  最后吊销旧值。PostgreSQL 口令轮换需两步（改库 + 改配置），存在瞬时连接
  失败窗口，建议低峰执行。

## 立即处置步骤（可复制命令）

```bash
# ---------------------------------------------------------------------------
# A) 后台/管理令牌（EVONIDS_ADMIN_API_TOKEN == NUXT_BACKEND_ADMIN_TOKEN）
# ---------------------------------------------------------------------------
openssl rand -hex 32          # 生成新值（示例；任选强随机源）
# 更新根 .env 两个同名值：EVONIDS_ADMIN_API_TOKEN 与 NUXT_BACKEND_ADMIN_TOKEN
#   先改服务端：新值生效后，旧值仍可用的窗口内通知客户端（脚本/采集）切换
docker compose up -d api web
# 验证：旧令牌应 401，新令牌 200（-w 打印状态码）
curl -s -o /dev/null -w 'old=%{http_code}\n' -H "X-EvoNIDS-Admin-Token: <旧值>" \
  http://127.0.0.1:8000/api/v1/rules
curl -s -o /dev/null -w 'new=%{http_code}\n' -H "X-EvoNIDS-Admin-Token: <新值>" \
  http://127.0.0.1:8000/api/v1/rules

# ---------------------------------------------------------------------------
# B) 采集令牌（EVONIDS_SENSOR_INGEST_TOKEN == NUXT_SENSOR_INGEST_TOKEN）
# ---------------------------------------------------------------------------
openssl rand -hex 32
# 更新 .env 后重启 api、web；随后逐台切换探针（先新后旧），再验证旧值 401
docker compose up -d api web
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  "http://127.0.0.1:8000/api/v1/sensors/<sensorId>/heartbeat" \
  -H "X-EvoNIDS-Sensor-Token: <新值>" -H "Content-Type: application/json" \
  -d '{"name":"<sensorId>"}'

# ---------------------------------------------------------------------------
# C) 控制台口令（NUXT_CONSOLE_PASSWORD）
# ---------------------------------------------------------------------------
# 改 .env 后重启 web；会话 HMAC 由口令派生，改口令 = 全量登出（session.ts）
docker compose up -d web

# ---------------------------------------------------------------------------
# D) PostgreSQL 口令（POSTGRES_PASSWORD）
# ---------------------------------------------------------------------------
# 1) 先在库里改口令（PostgreSQL 不读 .env；容器变量只在首次 initdb 生效）
docker compose exec -T postgres psql -U evonids -d evonids \
  -c "ALTER USER evonids WITH PASSWORD '<新口令>';"
# 2) 再改 .env 的 POSTGRES_PASSWORD 并重建 api（api 的 DATABASE_URL 由它拼出）
docker compose up -d --force-recreate api
# 3) K8s：改 secrets.postgresPassword 后 upgrade，postgres 容器也会滚动——
#    但其数据目录口令已由第 1 步改好，新 env 与库内口令一致即不会断连

# ---------------------------------------------------------------------------
# E) 数据库型 API key（作用域 admin/sensor/analyst）
# ---------------------------------------------------------------------------
curl -s -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/admin/api-keys          # 列出
curl -s -X POST -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/admin/api-keys/<key_id>/revoke   # 吊销旧
# 再按最小权限创建新 key（见 backend/README.md "Authentication and API keys"）

# ---------------------------------------------------------------------------
# F) DeepSeek Key（可选）
# ---------------------------------------------------------------------------
# 只改 NUXT_DEEPSEEK_API_KEY 并重启 web（server-only，见 llm-provider-outage runbook）
docker compose up -d web
```

Kubernetes 变体（未验证）：`helm upgrade --install evonids ... --set
secrets.<x>=<新值>`；使用 `secrets.existingSecret` 时先更新 Secret（external-secrets
同步后）再 `kubectl -n evonids rollout restart deploy/evonids-api deploy/evonids-web`。

## 验证恢复

- 旧值一律 401（管理/采集/API key）；新值业务调用 200。
- 控制台重新登录成功且会话可保持；探针全部回 online（sensor-offline runbook）。
- Postgres 口令：`docker compose exec -T postgres pg_isready -U evonids -d evonids`；
  api 日志无认证错误。
- 审计可见轮换期间的写操作留痕。

## 根因分析（常见轮换事故）

1. 只改了服务端、未切客户端 → 旧客户端 401 批量失败（应先切客户端再吊销）。
2. PG 口令只改 .env 未 ALTER USER（或反之）→ 配置与库内不一致，api 反复重连失败。
3. 多副本/多环境遗漏某处配置副本。
4. 明文落入 git/日志（轮换应配合泄露排查）。

## 预防措施

- 把密钥集中在单个 `.env`/Secret，禁止散落；CI 用托管 secret。
- 轮换纳入日历（90 天）+ 变更工单；DB API key 走最小权限与定期扫描。
- 依赖外部密钥管理（external-secrets/Vault）的部署，轮换只改 Secret 源，
  触发器负责 rollout。

## 责任人与升级路径

- 一线：值班运营按 A–F 执行并填验证清单。
- 升级：批量客户端切换困难 → 发布负责人协调灰度；
  疑似泄露 → 立即升级安全负责人（security-incident-response runbook）。
