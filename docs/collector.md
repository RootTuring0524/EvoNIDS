# 采集器部署与运维（Suricata EVE）

采集器代码位于 `backend/app/collector/`，与 API 同一个 Python 包，无需单独安装依赖即可运行。

## 1. 数据流

```
Suricata eve.json ──► collector（tail + 批次 + gzip）
                        │ 批次先原子落盘（spool）
                        ▼
             POST /api/v1/ingestion/eve/batch?sensorId=<id>
                        │  (X-Evonids-Batch-Id 幂等)
                        ▼
   ingestion_batches（幂等账本）→ flows / alerts / evidence_records / entities
                        ▼
             detection_signals + risk_assessments（在线检测，默认 shadow）
```

## 2. 启动

```bash
# 建议用 systemd/supervisor 托管；token 从环境变量读取，不要写进命令行历史
export EVONIDS_SENSOR_TOKEN='<sensor scope api key>'
python -m app.collector.cli \
  --eve-file /var/log/suricata/eve.json \
  --endpoint https://evonids.example.com/api/v1 \
  --sensor-id lab-core-01 \
  --spool /var/lib/evonids/collector-spool \
  --state-file /var/lib/evonids/collector-state.json \
  --batch-max-events 2000 \
  --heartbeat-interval 60
```

`--once` 只读取当前可用内容后退出（适合 cron/测试）。Windows 实验室可用同一 CLI（路径换成 `C:\...`）。

### 关键参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--batch-max-events` | 2000 | 单批事件上限（服务端 `EVONIDS_COLLECTOR_MAX_BATCH_EVENTS` 默认 50000） |
| `--flush-interval` | 2.0 | 无新行时的循环间隔，同时用于重试 spool |
| `--heartbeat-interval` | 60 | 心跳间隔，决定 `sensors.last_heartbeat_at` |
| `--rate-limit-events-per-second` | 0（不限） | 采集端限速，防止上游被打满 |
| `--max-attempts` | 5 | 单批次最大尝试次数（指数退避 + 抖动，遵守 `Retry-After`） |
| `--spool` | `./collector-spool` | 磁盘缓冲目录，**必须持久化** |
| `--state-file` | `./collector-state.json` | 读取偏移与 inode，支持重启续传与轮转检测 |
| `--client-cert/--client-key` | 无 | mTLS 客户端证书（生产建议开启） |
| `--insecure-skip-verify` | 关 | 仅限自签实验环境 |

## 3. 可靠性与失败语义

| 情况 | 行为 | 数据是否丢失 |
| --- | --- | --- |
| 网络超时 / 5xx / 429 | 指数退避重试，最多 `--max-attempts` 次 | 否，批次仍在 spool |
| 重试耗尽 | 批次保留在 spool，下轮循环继续投递 | 否 |
| 服务端已收过该批次 | 返回 `replayed: true`，不重复入库 | 否（幂等） |
| 同批次号不同内容 | 服务端 409 → 采集端移入 `spool/dead-letter/` 并写 `.reason.txt` | 否，人工处理 |
| 400/413（格式或大小非法） | 不重试，移入 dead-letter | 否 |
| spool 超过上限 | 拒绝新批次（`status: spool_full`），**不覆盖旧数据** | 新数据未落盘，会出现在日志 |
| EVE 文件轮转/截断 | 通过 inode + 偏移检测，自动从 0 重新读取 | 否 |
| 进程被杀 | 已落盘批次仍在 spool，重启后 `flush_spool` 投递 | 否 |

## 4. 指标与健康

- 采集端日志每批次输出 `batchId/status/attempts/accepted/duplicates/rejected/elapsedMs/error`；
- 退出前与心跳中输出 `collectorMetrics`（提交/投递/重复/spool/dead-letter/重试/时钟偏差）；
- 服务端：`GET /api/v1/sensors/health?sensorId=<id>` 提供拒绝率、重复率、入库延迟 p50/p95、时钟偏差、数据缺口、spool 深度、丢弃计数；未测量的指标返回 `measured: false`；
- `GET /api/v1/sensors/{id}/batches` 查看批次账本（含内容 SHA-256）。

## 5. 安全

- 只使用 `sensor` scope 的 API key（`POST /api/v1/admin/api-keys`，见 ADR-0003），不要复用 admin token；
- 生产必须 TLS；建议 mTLS（`sensors.certificate_fingerprint` 预留绑定，启用后服务端会校验客户端证书指纹）；
- spool 目录包含原始 EVE 事件，需 `0700` 权限并纳入磁盘加密/备份策略；
- dead-letter 内容可能含敏感载荷，按 `docs/runbooks/security-incident-response.md` 处理，禁止提交到版本库。

## 6. 故障处置

见 `docs/runbooks/sensor-offline.md` 与 `docs/runbooks/ingestion-backlog.md`。
