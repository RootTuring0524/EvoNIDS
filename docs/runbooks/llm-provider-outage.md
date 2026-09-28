# Runbook：LLM 提供商故障（llm-provider-outage）

> 适用环境：web（Nuxt 4 BFF）通过 `project/server/services/deepseek.ts` 调用
> OpenAI 兼容上游（`NUXT_DEEPSEEK_API_BASE/API_KEY/MODEL`，仅服务端持有）。
> 当前后端 `RAG` 读取本就诚实回退关键词（keyword_fallback），向量通道为 0；
> LLM 故障只影响分析与建议类体验，不影响 EVE 采集、检测与告警主链路。
> **本机无 Docker/集群/网络，命令未在本环境执行（未验证）。**

## 症状

- 控制台 Agent 分析、知识问答、规则建议等返回上游错误/超时或“服务不可用”。
- web 日志出现 deepseek/upstream 相关错误（HTTP 4xx/5xx、连接超时、模型不存在）。
- 「平台设置 → 验证上游 /models」动作失败。

## 影响面

- 低：检测、告警、训练、规则回放均不依赖 LLM。
- 中：需要 LLM 的分析型功能不可用或降级；若平台侧有用户等待分析，体验受损。

## 立即处置步骤（可复制命令）

```bash
# 1) 确认影响面：看 web 日志与上游连通性
docker compose logs web --since 15m | grep -i 'deepseek\|upstream' | tail -n 100

# 2) 区分“上游整体故障” vs “配置错误/欠费/限流”：
#    在 web 容器内对 base URL 做连通性检查（示例 base https://api.deepseek.com）
docker compose exec -T web node -e \
  "fetch(process.env.NUXT_DEEPSEEK_API_BASE + '/models', {headers:{authorization:'Bearer '+process.env.NUXT_DEEPSEEK_API_KEY}}).then(r=>{console.log(r.status);return r.text()}).then(t=>console.log(t.slice(0,400))).catch(e=>{console.error(e.message);process.exit(1)})"

# 3) 若上游整体故障：临时关闭对外的“分析可用”宣传/开关（产品侧），
#    保留关键词回退，不阻塞主链路；等待上游恢复

# 4) 若模型名错误：核对 .env 中的 NUXT_DEEPSEEK_MODEL 与账号可用模型一致后重启 web
docker compose up -d web

# 5) 若怀疑密钥轮换/泄露：按 docs/runbooks/key-rotation.md 轮换 NUXT_DEEPSEEK_API_KEY
```

Kubernetes 变体（未验证）：`kubectl -n evonids logs deploy/evonids-web -c web
--tail=100 | grep -i deepseek`；若 BFF 需访问公网 LLM，确认 NetworkPolicy 已设
`networkPolicy.allowWebExternalEgress: true`（web 出网 443），否则 BFF 到上游一律
超时——这是集群环境最常见的“LLM 故障”根因。

## 验证恢复

```bash
# 用第 2 步的探活命令；HTTP 200 且返回模型列表即恢复
docker compose logs web --since 5m | grep -i deepseek   # 无新错误
# 控制台执行一次最小分析/问答，确认正常返回
```

## 根因分析

1. 上游服务故障/限流/欠费（无法在本环境复现，以探活返回为准）。
2. 集群内被 NetworkPolicy 阻断出网（`allowWebExternalEgress` 默认 false）。
3. 配置：`NUXT_DEEPSEEK_API_BASE` 指向错误、模型名不在账号内、密钥过期。
4. 代理/防火墙只允许特定域名。

## 预防措施

- 明确 LLM 为可选增强：`.env.example` 注释与部署文档均声明 mock/无 Key 可运行；
  保持检测主链路零 LLM 依赖。
- 监控 web 到上游的探活与错误率；为上游配置重试/超时（当前 `fetchBackend` 侧
  重试为 0，深水区调用在上游服务内实现，改动需回归）。
- 密钥轮换与探针/后台令牌解耦，避免一次泄露全量轮换。
- 集群：默认不开 web 出网，开启时用 `webExternalEgressCidrs` 收敛到 LLM 服务商
  出口网段。

## 责任人与升级路径

- 一线：值班运营按 1–3 分类并更新对外状态。
- 升级：上游账户/欠费 → 采购/财务；代码侧超时重试与回退增强 → BFF 负责人；
  若 LLM 故障期间出现安全事件依赖 LLM 分析，运营负责人给出人工研判替代流程。
