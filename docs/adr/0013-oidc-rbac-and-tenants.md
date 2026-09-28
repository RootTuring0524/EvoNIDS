# ADR-0013：OIDC 身份、RBAC 与租户/工作区隔离

- 状态：已接受（2026-09-10）
- 相关：ADR-0003（scoped 哈希 API Key）、ADR-0012（规则治理）

## 1. 问题

v0.1 的身份体系只有两类凭据：环境变量里的共享 admin/sensor token，以及 ADR-0003 引入的 scoped 哈希 API Key。这有三个真实缺口：

1. **没有正式身份系统**：无法对接企业 IdP（OIDC/OAuth2、Keycloak），人员账号只能靠共享 token 模拟；
2. **RBAC 只有三个 scope**：admin 过宽、reviewer 角色缺失（规则确认、案件关闭本应由复核人执行），没有最小权限矩阵；
3. **没有租户隔离**：案件、证据、检测信号、调查运行都在同一命名空间，多团队共用实例时互相可见。

## 2. 决策

### 2.1 OIDC 验证（`app/services/oidc.py`）

- 使用 `Authorization: Bearer <jwt>` 携带访问令牌，按 **RS256/ES256 + JWKS** 校验；
- 校验 `iss`/`aud`/`exp`/`nbf`/`iat`（含可配置 leeway）与 `kid`；**拒绝 `alg: none` 与 HMAC 算法**（算法混淆）；
- JWKS 通过可注入 transport 获取并带 TTL 缓存，遇到未知 `kid` 刷新一次；
- 声明到角色的映射支持 Keycloak `realm_access.roles` 与自定义 roles claim；
- **失败即拒绝**：任何校验失败都不返回 principal，不会退化成默认角色。
- 由 `EVONIDS_OIDC_ENABLED` 控制；生产开启时强制要求 issuer/audience/jwks_url 齐备。

> 诚实说明：本环境无 `cryptography` 依赖且无网络，无法对真实 IdP 令牌做端到端验证；
> 该模块的正确性目前由单元测试覆盖（密钥与签名在测试内生成），真实 IdP 联调**未测量**。

### 2.2 RBAC（`app/services/rbac.py`）

- 角色：`admin`、`reviewer`、`analyst`、`sensor`、`viewer`；
- 权限矩阵显式声明、默认拒绝：规则部署与密钥管理属 admin；规则确认/驳回、案件关闭属 reviewer 或 admin；调查启动、反馈、案件备注属 analyst 或 admin；摄取属 sensor；读属任意已认证角色；
- 提供 `require_permission("rule:deploy")` / `require_role("reviewer")` 依赖；
- **admin 是 analyst 的超集**：控制台只持有单一服务端 admin token，管理员执行分析员动作是合理 RBAC 语义，解析出的 principal 仍保留真实 scope 以便审计区分；
- 既有 `require_admin_token` / `require_sensor_token` / `require_analyst_token` 行为保持不变。

### 2.3 租户/工作区隔离（迁移 `20260909_0014`）

- `cases`、`evidence_records`、`detection_signals`、`risk_assessments`、`investigation_runs` 增加 `workspace_id`（默认 `default`），并建立 `(workspace_id, ...)` 索引；
- 读取必须带工作区过滤，写入的工作区**由 principal 推导**，客户端提交的 `workspaceId` 一律忽略；
- 历史数据在迁移时统一打上 `default`，不会因升级而不可见；
- `EVONIDS_RBAC_STRICT_READS` 是**可选**加固开关而非生产强制项：强制它会破坏文档中明确的无认证只读面（控制台 BFF、健康探针），因此改为文档化能力。

### 2.4 审计防篡改（迁移 `20260909_0017`，见 `app/services/audit_chain.py`）

- `audit_events` 增加 `workspace_id`、`sequence`、`prev_hash`、`content_hash`，每个工作区一条独立哈希链；
- 链在 **mapper 层强制**（`before_insert` 监听器），因此每个直接构造 `AuditEvent(...)` 的服务都自动入链，不依赖各调用点自觉；
- `GET /audit/integrity` 重算并报告断裂点（序号缺口、前哈希不符、内容哈希不符）；
- `GET /audit/export`（admin）导出可离线校验的文档，`POST /audit/verify` 与 `app.services.audit_chain.verify_export` 可**脱离数据库**验证，审计员只需文件与校验函数；
- 迁移前的历史行没有链，验证时明确计为 `unchained`，**不当作已验证**。

## 3. 替代方案

1. 继续用共享 token：被否，无法最小权限、无法审计到人。
2. 自建用户名/密码：被否，凭据管理风险高且企业统一由 IdP 负责。
3. 每租户独立数据库：本期不采用；列级隔离 + 强制过滤足够，且迁移成本更低。
4. 只做签名批次而不做哈希链：被否，链能定位到具体行，签名批次只能证明整体。

## 4. 迁移与回滚

- `alembic upgrade head`（0014 → 0016 → 0017）；已实测 upgrade → downgrade → upgrade。
- 回滚：`alembic downgrade 20260909_0013` 会移除工作区列与审计链列（导出后执行）；OIDC 可通过 `EVONIDS_OIDC_ENABLED=false` 立即停用，无需迁移。

## 5. 未测量 / 未实现

- 真实 IdP 联调（无凭据、无网络）；
- 多租户下的性能影响（未做负载测试）；
- 工作区级的管理 API（创建/改名/成员管理）尚未提供，目前工作区由 IdP claim 或默认值决定。
