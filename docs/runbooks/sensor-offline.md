# Runbook：传感器离线（sensor-offline）

> 适用环境：Compose 单机生产栈（`docker-compose.yml` + `docker-compose.prod.yml`）或
> Kubernetes（`deploy/helm/evonids/`）。以下命令基于仓库真实路径与环境变量名。
> **本机无 Docker/集群，命令未在本环境执行（未验证）**——先在任何非生产机演练。

## 症状

- 控制台「传感器」页或 `GET /api/v1/sensors` 显示某探针 `offline`（或长期 `degraded`）。
- `/api/v1/readiness` 的 `collection-plane` 检查项从 `pass` 变为 `warn`：
  `0/1 个探针在线`。
- 该探针不再产生新 flow/alert；其本地 EVE 文件持续增大（积压）。

后端判在线逻辑（`backend/app/services/sensor_operations.py`）：距 `last_seen_at`
≤ 120 秒为 `online`，≤ 900 秒为 `degraded`，超过 900 秒或从未上报为 `offline`。

## 影响面

- 单一探针覆盖的网络段失去检测/告警数据，攻击面出现盲区（中等，取决于该段资产）。
- 若探针同时是唯一 EVE 源，告警、规则演进数据集将缺源。

## 立即处置步骤（可复制命令）

```bash
# 1) 确认离线范围与最近上报时间
curl -s http://127.0.0.1:8000/api/v1/sensors | python -m json.tool
curl -s http://127.0.0.1:8000/api/v1/readiness | python -m json.tool   # collection-plane

# 2) 若探针进程/转发器在宿主机，先确认其存活与网络可达 API
#    （按你的采集部署调整；示例为 systemd/进程检查）
ssh sensor-host 'systemctl status eve-forwarder; tail -n 50 /var/log/eve-forwarder.log'

# 3) API 侧日志：确认近期没有收到该 sensorId 的请求
docker compose logs api --since 30m | grep -i '<sensorId>'

# 4) 立即重注册/手动心跳（sensorId 不存在时该端点会自动创建探针）
curl -s -X POST "http://127.0.0.1:8000/api/v1/sensors/<sensorId>/heartbeat" \
  -H "X-EvoNIDS-Sensor-Token: ${EVONIDS_SENSOR_INGEST_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"<sensorId>","version":"1.0","metadata_json":{}}'

# 5) 若令牌/时钟可疑，检查时钟偏差字段并校准（clock_skew_seconds 在 /sensors 响应中）
# 6) 恢复数据流后重放积压 EVE（≤10MiB/批，重复行幂等去重）
split -b 8M /var/log/suricata/eve.json /tmp/eve-chunk-
for f in /tmp/eve-chunk-*; do
  curl -s -X POST "http://127.0.0.1:8000/api/v1/ingestion/eve?sensorId=<sensorId>" \
    -H "X-EvoNIDS-Sensor-Token: ${EVONIDS_SENSOR_INGEST_TOKEN}" \
    -H "Content-Type: application/x-ndjson" --data-binary "@$f"
done
```

Kubernetes 变体（未验证）：`kubectl -n evonids logs deploy/evonids-api --tail=200 |
grep <sensorId>`；探针到集群的入口若是 `web` 的 BFF，则为
`POST https://console.example.com/api/ingestion/eve?sensorId=...`；确认
NetworkPolicy 未阻断入口（ingress controller → web:3000）。

## 验证恢复

```bash
curl -s http://127.0.0.1:8000/api/v1/sensors            # 该探针 state 回到 online
curl -s http://127.0.0.1:8000/api/v1/readiness | python -m json.tool   # collection-plane = pass
# 新数据可见：flows/alerts 计数随时间增长
curl -s "http://127.0.0.1:8000/api/v1/flows?limit=5"
curl -s "http://127.0.0.1:8000/api/v1/alerts?limit=5"
```

## 根因分析

1. 探针进程崩溃 / 采集器（Suricata 等）未运行 → 检查探针侧日志。
2. 网络路径：探针 → API 被防火墙/NetworkPolicy 阻断。
3. 鉴权：`EVONIDS_SENSOR_INGEST_TOKEN` 轮换后探针仍用旧令牌 → 401。
4. 时钟漂移导致时间戳判断异常（`clock_skew_seconds`）。
5. API 侧过载/重启：看 `docker compose logs api`、磁盘/CPU。

## 预防措施

- 探针侧配置心跳周期（≤120s）并接入监控告警：`X 分钟无心跳即告警`。
- 在控制台/API 侧对探针打 `maintenance` 状态（`PATCH /api/v1/sensors/{sensorId}`），
  避免维护期间误报离线。
- 令牌轮换走 `docs/runbooks/key-rotation.md`，先切探针再切服务端。
- 对探针与 API 之间启用超时/重试（生产叠加后端与超时配置）。

## 责任人与升级路径

- 一线：值班安全运营 / 平台运维，按上文 1–4 处置并在 30 分钟内恢复或上报。
- 升级：若探针侧无法登录或属第三方设备，升级至网络/基础设施负责人；
  若怀疑令牌泄露或批量离线，升级至安全负责人并启动
  `docs/runbooks/security-incident-response.md`。
