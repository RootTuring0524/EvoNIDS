# ADR-0012：规则 IR、Suricata 沙箱验证与灰度发布（Phase 5）

- 状态：已接受（2026-09-09）
- 相关：ADR-0008（采集与存储）、`docs/adr/0010-online-detection-and-fusion.md`

## 1. 问题

v0.1 的规则治理有三个真实缺陷：

1. 候选规则是“内部特征条件”（`StructuredRule.conditions` 作用于 `flow-v1` 特征），只能由进程内的 **predicate replay** 求值；它没有规则文本，也没有经过 Suricata，任何“已验证”的说法都名不副实；
2. 没有 SID/rev 管理、没有语法校验、没有真实 PCAP 回放、没有每百万正常流误报；
3. 没有灰度与回滚：`confirmed → deployed` 是一次状态跳转，没有传感器分组、没有观察期、没有回滚记录。

## 2. 决策

### 2.1 规范化 Rule IR（`app/domain/rule_ir.py`）

- 不接受自由规则文本：所有规则先转成 IR（header/contents/flow/pcre/threshold/meta），逐字段校验后才编译；
- 校验范围：action/protocol/direction 白名单、CIDR/变量/端口表达式、SID 必须落在本地段 `1000000–1999999`、rev ≥ 1、msg 1–200 字符、classtype 白名单、priority 1–255、reference 形如 `cve,CVE-…`、MITRE 形如 `T1046`、content 修饰符白名单、pcre 禁止递归/代码执行构造、flow/threshold 语法；
- 编译是**确定性**的：同一 IR 永远产生同一行 Suricata 文本，`"`、`\`、`;` 全部转义，注入的 `sid:`/`msg:` 不会变成真实选项（有专门测试）；
- 每条编译结果持久化到 `rule_ir_versions`（IR 文档、digest、Suricata 文本、SID、rev、作者），可逐字节复现。

### 2.2 真实沙箱（`app/services/rule_sandbox.py`）

验证分四步并逐项记录 `checks`：

1. 检测 `suricata` 可执行文件并读取版本；
2. `suricata -T -S <rules>` 语法校验；
3. 恶意 PCAP 回放（`suricata -r … -l …`，解析 `eve.json` 告警）；
4. 正常 PCAP 回放，计算 precision/recall/F1、误报率、**每百万正常流误报**、回放耗时与峰值内存（不可测时写 `null` 并标 `measured:false`）。

**诚实性约束**：

- 本机未安装 Suricata 时，运行记录为 `blocked`，`metrics` 为空，`passed=false`，并写明原因；接口与前端都显示“未执行 Suricata”；
- 只做语法校验（缺少标注 PCAP）时记录为 `partial`，仍然 `passed=false`；
- 只有语法通过且召回 ≥ `recallFloor`（默认 0.8）、每百万误报 ≤ 上限（默认 1000）才 `validated`；
- predicate replay 仍然保留用于分诊，但在文档与接口中一律称为 predicate replay，不与 Suricata 验证混用。

### 2.3 灰度与回滚（`app/services/rule_deployment.py`）

- 传感器分组 `sensor_groups`（`canary` / `production`）与部署记录 `rule_deployments`；
- **部署前置条件**：该修订必须存在 `passed=true` 的沙箱运行，否则 409 并返回最近一次运行的状态与原因；
- 全量部署只允许指向 `stage=production` 的分组；
- 提升（promote）必须指定 production 分组，并**新增一条生产部署记录**，保留灰度记录用于追溯；
- 回滚必须填写 ≥10 字符的原因，记录 `rolled_back_at`、原因，并把 `rules.active_version_id` 恢复到 `previous_version_id`；
- 规则状态机扩展为：`candidate → validating → validated / validation_failed / rejected → repaired → confirmed → canary → deployed → rolled_back / deprecated`；
- 所有状态变化写入审计日志（`rule.compiled`、`rule.canary`、`rule.promoted`、`rule.rolled_back`）。

## 3. 替代方案

1. 让模型直接输出 Suricata 文本：被否，无法校验、易注入、无法复现。
2. 只做 predicate replay：被否，不能声称 Suricata 验证。
3. 在没有 Suricata 的机器上直接部署：被否，等于用未验证规则打生产流量。
4. 用 Scapy 自己解析 PCAP 来“模拟 Suricata”：被否，模拟结果不能代表 Suricata 行为。

## 4. 回滚与未验证项

- 回滚：`alembic downgrade 20260909_0012` 删除四张表（版本、沙箱运行、分组、部署）；规则本身的 `rules.stage` 由应用层管理，回滚前应先 `deprecated`。
- **未验证**：本机没有 Suricata 二进制，也没有标注的正常/恶意 PCAP 语料，因此真实语法校验、真实回放指标、真实每百万误报**全部未测量**。`tests/test_rule_governance.py` 使用注入式假执行器验证了指标计算、阈值判定、门禁与回滚逻辑，但这**不是** Suricata 验证证据。
- 运维方在有 Suricata 的机器上应执行 `docs/runbooks/rule-rollback.md` 中的流程，并把真实回放报告归档。
