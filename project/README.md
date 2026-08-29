# EvoNIDS Console

EvoNIDS 是面向安全运营团队的网络入侵检测、证据研判与规则演进平台。当前仓库已具备可运行的 Nuxt BFF、FastAPI 持久化后端、真实数据资产登记、可复现 CPU 分类基线和受控规则生命周期；它仍不是已经完成 Flow Transformer、AutoEncoder、生产流量接入和组织级身份系统的最终生产版本。

## 当前真实能力

- 告警、Flow、探针、规则、知识证据、审计、模型登记和数据集登记使用 FastAPI + SQLAlchemy 持久化。
- Suricata EVE JSON/NDJSON 可以通过受控接口导入，事件按外部 ID 幂等写入。
- 规则支持创建、验证、驳回、确认、部署、修复和废弃状态机，并记录审计事件。
- RAG 证据具有来源、授权、Agent 使用许可和 Prompt Injection 风险字段；不安全证据不会进入 Agent 上下文。
- DeepSeek 凭据只存在于 Nuxt Server Runtime Config。连接测试会真实请求上游 `/models`，8 秒超时，不向浏览器返回密钥、真实 Base URL 或上游响应体。
- 数据集登记只接受 `EVONIDS_DATASET_ROOT` 内的 CSV/CSV.GZ 相对路径。后台真实计算 SHA-256、总行数、缺失值、标签列和标签分布，不生成虚假训练指标。
- 已登记且画像完成的数据集可启动真实的 CPU 分类基线训练。训练前重新校验源文件 SHA-256，结果记录精确拆分规模、逐类别指标、混淆矩阵、实际特征、运行耗时和制品 SHA-256。
- 模型页只把实际存在的本地文件标记为可用制品；未训练、未评估、文件缺失和远程制品未验证都会原样显示。
- 告警处置、规则写操作、数据集登记和知识写入均受管理员令牌保护；浏览器不会持有管理员令牌。

## 明确未完成的能力

- 尚未实现锁定目标中的 Flow Transformer、Masked Feature Modeling、Flow AutoEncoder、在线推理、模型服务编排或漂移监控；当前真实训练能力是用于对照实验的 HistGradientBoosting CPU 基线。
- 没有 PCAP 实时抓取、Kafka/Redpanda 流水线或海量 Flow 性能验证。
- “规则部署”当前完成数据库状态和审计闭环，不会向真实 Suricata 探针下发配置。
- 没有组织级登录、会话、RBAC、SSO 和租户隔离；当前管理员令牌是服务间保护，不是最终用户认证方案。
- 持久化 RAG 当前是透明关键词检索，不是向量数据库。
- 开发环境默认 SQLite；正式交付应使用 PostgreSQL、密钥管理、反向代理、TLS、备份和监控。

## 本地启动

### 1. 启动后端

```powershell
Set-Location "<repo-root>\backend"
.\.venv\Scripts\Activate.ps1
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

详细后端配置见 `..\backend\README.md`。

### 2. 启动前端开发服务器

在另一个 PowerShell 窗口中执行：

```powershell
Set-Location "<repo-root>\project"
$env:NUXT_PUBLIC_USE_MOCK_API='false'
$env:NUXT_BACKEND_API_BASE='http://127.0.0.1:8000/api/v1'
corepack pnpm dev
```

打开 `http://localhost:3000/overview`。

真实写操作还需要同时配置以下同值令牌：

```dotenv
# backend/.env
EVONIDS_ADMIN_API_TOKEN=使用随机长字符串
EVONIDS_SENSOR_INGEST_TOKEN=使用另一条随机长字符串

# project/.env
NUXT_BACKEND_ADMIN_TOKEN=与后端管理员令牌相同
NUXT_SENSOR_INGEST_TOKEN=与后端采集令牌相同
```

不要把 `.env`、API Key 或令牌提交到仓库。

## DeepSeek 配置

```dotenv
NUXT_DEEPSEEK_API_BASE=https://api.deepseek.com
NUXT_DEEPSEEK_API_KEY=仅保存在未提交的服务端环境变量中
NUXT_DEEPSEEK_MODEL=账户实际可用的模型 ID
```

配置后先在“平台设置”点击“验证上游 `/models`”。成功只证明网络、认证和模型可见性正常，不代表告警研判质量已经通过验收。

## 登记真实数据集

1. 把 CSV 或 CSV.GZ 放到后端的 `datasets` 目录，或把 `EVONIDS_DATASET_ROOT` 指向受控只读数据目录。
2. 打开“模型运行” → “登记数据集”。
3. 填写稳定资产 ID、正式名称、版本、相对路径、来源和标签配置。
4. 等待后台画像完成，核对 SHA-256、行数、缺失值和标签分布。
5. 在“真实 CPU 基线训练”区选择数据集、样本上限和迭代次数，确认后启动任务。
6. 任务完成后核对数据集 SHA-256、训练/验证/测试规模、测试集 Macro-F1、逐类别指标、特征清单和模型制品 SHA-256。

源文件不会被网页上传、修改或删除；删除操作只删除登记记录。数据版本一旦产生训练记录，文件摘要即成为不可变血缘：内容变化必须登记新的资产版本，原登记记录也会受到引用保护。

## 生产构建与启动

```powershell
Set-Location "<repo-root>\project"
corepack pnpm validate
corepack pnpm build

$env:NITRO_HOST='127.0.0.1'
$env:NITRO_PORT='3000'
$env:NUXT_PUBLIC_USE_MOCK_API='false'
$env:NUXT_BACKEND_API_BASE='http://127.0.0.1:8000/api/v1'
node .output\server\index.mjs
```

当前 Windows + Node 24 环境中，Vite 客户端与 SSR 构建很快，但 Nitro 最终打包可能持续数分钟并占用约 2GB 内存；只要进程仍有 CPU 活动，应等待出现 `Build complete` 和 `.output/server/index.mjs`。部署环境建议固定 Node 22 LTS 并在 CI 中记录构建时间。

## 质量检查

```powershell
corepack pnpm validate  # typecheck + ESLint + Vitest
corepack pnpm build     # 生产产物
```

后端：

```powershell
Set-Location "<repo-root>\backend"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check app tests
```

本轮验收结果：前端 25 项测试通过，后端 11 项测试通过，Ruff、TypeScript 和 ESLint 通过。上线就绪页仍会如实提示 SQLite/示例密码、未配置管理员令牌、进程内训练执行器、探针离线、无真实数据集、无模型制品和开发环境等条件；这些条件不会被演示数据自动消除。
