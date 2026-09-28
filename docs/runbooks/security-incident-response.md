# Runbook：安全事件响应（security-incident-response）

> 适用：检测到凭据泄露/异常访问/审计异常时的响应流程。围绕真实端点：管理令牌
> `EVONIDS_ADMIN_API_TOKEN`（`X-EvoNIDS-Admin-Token`）、采集令牌
> `EVONIDS_SENSOR_INGEST_TOKEN`（`X-EvoNIDS-Sensor-Token`）、数据库 API key
> （`POST /api/v1/admin/api-keys/{key_id}/revoke`）、审计流
> `GET /api/v1/audit`。**本机无 Docker/集群/库，命令未在本环境执行（未验证）。**

## 症状

- 日志出现来源可疑的管理员写操作（规则/数据集/告警处置/证据写入）。
- API key 或令牌在非预期地点/时间被使用；控制台出现异常登录或大量 401/429。
- 探针批量离线或行为异常（疑似采集令牌被滥用）。
- 外部通报/扫描发现本服务凭据泄露。

## 影响面

- 若 admin 令牌泄露：攻击者可写规则、改告警处置、注册数据集、写知识证据、
  吊销 API key——先假定“已发生未授权写操作”并按全量审计排查。
- 若 sensor 令牌泄露：可伪造探针数据/心跳，污染数据集与训练，需隔离并重放。

## 立即处置步骤（可复制命令）

```bash
# 1) 止损——立即轮换受影响令牌（详见 docs/runbooks/key-rotation.md）
#    生成新值并替换 .env / 集群 secret，然后重启受影响服务
docker compose up -d --force-recreate api web

# 2) 吊销所有疑受影响的数据库型 API key（逐个；无法批量枚举时先全量吊销再重建）
curl -s -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/admin/api-keys
curl -s -X POST -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/admin/api-keys/<key_id>/revoke

# 3) 控制台口令泄露：改 NUXT_CONSOLE_PASSWORD 并重启 web
#    （会话 HMAC 依赖口令，改口令即全量登出旧会话，见 project/server/utils/session.ts）

# 4) 审计取证（时间窗口内全部事件 + 控制台登录事件）
curl -s -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  "http://127.0.0.1:8000/api/v1/audit" > /tmp/audit-dump-$(date +%F).json
docker compose logs api web --since 24h > /tmp/logs-$(date +%F).log

# 5) 若事件影响规则库/证据：冻结自动演进（停止 agent 提交与规则 deploy），
#    只读模式复核规则库（GET /api/v1/rules 与各 timeline），必要时按
#    docs/runbooks/rule-rollback.md 回滚
```

Kubernetes 变体（未验证）：凭据在 `secrets.*` 或 `secrets.existingSecret`；
轮换后 `kubectl -n evonids rollout restart deploy/evonids-api deploy/evonids-web
statefulset/evonids-postgres`（DB 口令轮换见 key-rotation runbook）；取证用
`kubectl -n evonids logs`；怀疑横向时收紧 NetworkPolicy（web 出网默认关）。

## 验证恢复

- 旧令牌/API key 全部返回 401；新令牌正常。
- 审计时间线完整（actor/object/outcome/request_id），无新的未知写操作。
- 控制台要求重新登录；探针用新 sensor 令牌恢复在线（参考 sensor-offline runbook）。
- 若曾回滚规则/模型，执行相应 runbook 的验证恢复步骤。

## 根因分析

1. 令牌以明文存储/传输、误提交到代码仓库或日志（`.env` 被提交、CI 变量泄露）。
2. 数据库 API key 权限过宽（analyst/sensor 用 admin 作用域）。
3. 控制台弱口令/暴力破解（限流是进程内、按 IP；反代场景按代理 IP 聚合，
   见 docs/operations.md Console authentication）。
4. 依赖组件（上游/日志平台）被攻破导致凭据旁路泄露。

## 预防措施

- 密钥分层 + 短生命周期：后台令牌定期轮换，数据库 API key 按最小权限签发。
- 敏感操作全量审计（现状已覆盖规则/数据集/证据/告警处置/API key/console 登录）。
- 告警规则：异常时间窗口写操作、连续 401、API key 大批量创建。
- 禁止把 `.env`/密钥写入 git、CI 日志与镜像层；对 Secret 用外部密钥管理。
- 演练：每半年做一次“令牌泄露”桌面推演（本 runbook + key-rotation）。

## 责任人与升级路径

- 一线：值班安全运营执行 1–5，1 小时内完成止损与取证。
- 升级：确认未授权写入 → 安全负责人 + 合规（保留审计 dump 与日志，必要时
  离线封存）；涉及数据库/主机被入侵 → 基础设施应急小组；对外通报按
  SECURITY.md 流程。
