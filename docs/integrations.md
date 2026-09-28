# 出站集成连接器（Phase 10）

- 位置：`backend/app/integrations/`
- 状态：**实验特性，默认关闭**（`EVONIDS_INTEGRATIONS_ENABLED=false`）。关闭时连接器全部注册为 disabled，`GET /integrations` 会如实说明原因。

## 1. 连接器

| 名称 | 能力 | 说明 |
| --- | --- | --- |
| `webhook-1..N` | alert / evidence / test | JSON POST + HMAC-SHA256 签名（`X-Evonids-Signature: v1=<hex>`）+ 时间戳 + 幂等键；指数退避重试；熔断；SSRF 守卫 |
| `syslog` | alert / evidence / test | RFC 5424 帧 + CEF 格式化；UDP/TCP；**UDP 无法探测**，健康报告如实标为 degraded |
| `ticket-http` | case / test | 建单/更新单，载荷先脱敏；凭据仅服务端 |
| `stix` | alert / case | STIX 2.1 bundle 本地导出（`identity`/`indicator`/`observed-data`/`sighting`），确定性序列化 |

每个连接器都实现 `health()`，未知状态不会被猜测：无法探测时报告 `degraded` 并给出原因。

## 2. 环境变量

```bash
EVONIDS_INTEGRATIONS_ENABLED=true
EVONIDS_WEBHOOK_URLS=https://soc.example/hooks,https://backup.example/hooks
EVONIDS_WEBHOOK_SECRET=<签名密钥>
EVONIDS_WEBHOOK_MAX_ATTEMPTS=3
EVONIDS_WEBHOOK_CIRCUIT_FAILURES=5
EVONIDS_WEBHOOK_ALLOW_HTTP=false          # 默认拒绝明文
EVONIDS_WEBHOOK_ALLOWED_HOSTS=            # 逗号分隔；配置后成为权威白名单
EVONIDS_SYSLOG_HOST=soc.example
EVONIDS_SYSLOG_PORT=514
EVONIDS_SYSLOG_PROTOCOL=udp               # udp | tcp
EVONIDS_SYSLOG_FORMAT=rfc5424             # rfc5424 | cef
EVONIDS_TICKET_BASE_URL=https://tickets.example/api
EVONIDS_TICKET_TOKEN=<凭据>
EVONIDS_TICKET_PROJECT=SOC
EVONIDS_STIX_EXPORT_DIR=/var/lib/evonids/stix
```

## 3. API

- `GET /api/v1/integrations` — 连接器清单：enabled/disabled、能力、签名状态、健康报告（**不包含任何凭据**）
- `POST /api/v1/integrations/{name}/test`（admin）— 发送合成事件并返回**真实**投递结果
- `POST /api/v1/integrations/events`（admin）— 对某个告警/案件手动分发（可指定 `connectors`）
- `GET /api/v1/integrations/deliveries?connector=&state=&page=`（admin）— 投递台账

## 4. 安全边界

- **SSRF**：`url_guard.validate_target_url` 拒绝 loopback/私有/链路本地/云元数据地址与非 https（除非显式 opt-in）；不跟随重定向；`resolver` 可注入，测试不触网。
- **脱敏**：所有出站载荷经 `redact_mapping`（掩码 `sk-*`、JWT、私钥、Authorization、password/token 类键）；ticket 载荷会直接**丢弃**凭据类键。
- **失败隔离**：一个连接器失败不影响其他连接器；失败信息只记录原因与状态码，不记录载荷明文。
- **残余风险**：守卫无法把解析后的地址钉死到实际连接（DNS rebinding 窗口）；未实现出站代理白名单。

## 5. 未实测

本机无可用外部端点，也没有网络：连接器的**真实投递**（除本地 mock transport 外）未验证；`GET /integrations` 与手动分发在测试中通过注入的假 transport 验证了失败与成功两条路径。生产启用前请在预生产环境跑一次真实投递并核对台账。
