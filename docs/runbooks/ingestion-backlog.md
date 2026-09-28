# Runbook：采集积压（ingestion-backlog）

> 适用环境：EVE NDJSON 采集链路（探针 → web BFF `POST /api/ingestion/eve` 或
> FastAPI `POST /api/v1/ingestion/eve?sensorId=...`）。命令基于仓库真实路径。
> **本机无 Docker/集群/库，命令未在本环境执行（未验证）。**

## 症状

- 探针本地 EVE 文件/转发队列持续增长，最新事件的入库时间明显滞后于采集时间。
- 控制台流量/告警页数据陈旧；`GET /api/v1/overview` 的计数不随时间增长。
- API 访问日志中 `/api/v1/ingestion/eve` 慢请求增多（`duration_ms` 升高）。

## 影响面

- 检测与告警延迟：攻击发生后到告警的时延 = 积压时长（取决于积压深度）。
- 单文件超过 10 MiB 会被整体拒绝（`backend/app/ingestion/eve.py` 的上限），
  大批量积压若一次性推送会失败并继续积压。

## 立即处置步骤（可复制命令）

```bash
# 1) 确认积压规模与方向（API 侧近 30 分钟 ingest 统计）
docker compose logs api --since 30m | grep 'ingestion/eve' | tail -n 100
docker compose logs web --since 30m | grep -i 'eve\|ingest' | tail -n 100

# 2) 探针侧暂停继续叠积压，只保留缓冲（示例）
#    探针上：停止转发器，避免旧文件与重放并发
#    systemctl stop eve-forwarder

# 3) 单条探活：用小文件验证链路与令牌（生产必须携带令牌）
head -n 20 /var/log/suricata/eve.json > /tmp/probe.ndjson
curl -s -o /dev/null -w '%{http_code} %{time_total}s\n' \
  -X POST "http://127.0.0.1:8000/api/v1/ingestion/eve?sensorId=lab-core-01" \
  -H "X-EvoNIDS-Sensor-Token: ${EVONIDS_SENSOR_INGEST_TOKEN}" \
  -H "Content-Type: application/x-ndjson" --data-binary "@/tmp/probe.ndjson"
# 期望 2xx；401=令牌问题；5xx/超时=后端问题，先修后端再重放

# 4) 分批重放（≤10MiB/批，后端按行解析 + 去重，重复批次安全）
split -b 8M /var/log/suricata/eve.json /tmp/eve-chunk-
for f in /tmp/eve-chunk-*; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    "http://127.0.0.1:8000/api/v1/ingestion/eve?sensorId=lab-core-01" \
    -H "X-EvoNIDS-Sensor-Token: ${EVONIDS_SENSOR_INGEST_TOKEN}" \
    -H "Content-Type: application/x-ndjson" --data-binary "@$f")
  echo "$f -> $code"
done

# 5) 重放期间观察 API 负载；Compose 下 CPU 受限（api 6 CPU）
docker stats --no-stream api web postgres
```

Kubernetes 变体（未验证）：`kubectl -n evonids logs deploy/evonids-api -c api
--tail=200 | grep ingestion`；确认 HPA/副本未把 api 扩到 >1（训练 worker 进程内、
数据卷 RWO，见 chart README）；NetworkPolicy 放行 web→api:8000。

## 验证恢复

```bash
curl -s "http://127.0.0.1:8000/api/v1/flows?limit=5"    # 返回最近 flow
curl -s "http://127.0.0.1:8000/api/v1/overview"          # 计数接近采集侧行数
# 积压收敛：探针缓冲文件归零/接近零，最新事件时延 < 1 分钟
```

## 根因分析

1. 瞬时高峰 > 单进程解析能力（NDJSON 逐行解析 + 去重查询）。
2. 后端/DB 慢：连接池饱和、锁等待、磁盘 IO（看 `docker compose logs api` 与 PG 慢日志）。
3. 网络策略/代理限速或 BFF（web）到 api 超时（`fetchBackend` 超时 10s、重试 0）。
4. 单文件超 10MiB 被整体拒绝，探针未分片导致反复重推。
5. 时钟/时区或 dedupe 键问题造成部分行长期滞留 `pending` 语义（以日志为准）。

## 预防措施

- 探针侧按 8–10 MiB 分片 + 顺序重放 + 断点续传，幂等（后端重复行去重）。
- 容量规划：流量翻倍预警（CPU/内存/磁盘），参考 `docs/deployment.md` 资源表。
- 给 ingest 端点加监控（P99 时延、失败率、行数/秒），超阈值告警。
- 长期多探针高吞吐方案：迁移到持久化任务队列/独立采集服务（见
  `backend/app/services/training_worker.py` 顶部注释中的 Phase 3 规划）。

## 责任人与升级路径

- 一线：值班运营按上文分片重放并监控收敛；若 API 过载，协调应用负责人。
- 升级：数据库/容量问题 → 平台运维；需要队列化架构 → 应用架构负责人立项
  （当前为进程内串行 worker，多节点需先迁移，见 `docs/adr/0004-*`）。
