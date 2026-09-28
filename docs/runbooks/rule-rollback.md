# Runbook：规则回滚（rule-rollback）

> 适用环境：规则生命周期在 `backend/app/services/rule_lifecycle.py`：
> candidate → confirmed → deployed → deprecated（另有 validate/reject/repair），
> 每条迁移在审计日志留痕，`GET /api/v1/rules/{id}/timeline` 可查。
> 所有写操作需要 `X-EvoNIDS-Admin-Token`（= `EVONIDS_ADMIN_API_TOKEN`）。
> **本机无 Docker/集群/库，命令未在本环境执行（未验证）。**

## 症状

- 某规则上线/变更后回放验证或线上命中表现异常（误报集中、覆盖异常、规则建议质量下降）。
- 控制台规则页显示规则已 `deployed` 但指标/回放不达标。
- Agent/分析师对同一攻击的规则建议被劣质规则抢占或误导。

## 影响面

- 规则演进闭环质量受损；误报率上升会增加研判成本；误下线又会漏报。
- 规则本身不直接下发给 Suricata 等探针（当前版本为演进闭环内规则），
  回滚影响面集中于回放验证、Agent 建议与产品内“规则库”可信度。

## 立即处置步骤（可复制命令）

```bash
# 1) 记录现状与证据（导出当前规则与时间线，供复盘）
curl -s -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/rules > /tmp/rules-before-rollback.json
curl -s -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/rules/<rule_id> > /tmp/rule-<rule_id>.json
curl -s -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/rules/<rule_id>/timeline

# 2) 止血：立即下线问题规则（deprecate）
curl -s -X POST -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"actor":"sec-ops-oncall","reason":"rollback: 上线后误报/指标劣化","note":"见工单 <id>"}' \
  http://127.0.0.1:8000/api/v1/rules/<rule_id>/deprecate

# 3) 若要恢复“上一个良好定义”：
#    a) 若上版定义保存在 DB 规则版本表/时间线之外（导出 JSON 快照、git 或备份），
#       用旧 structured 定义重建候选并走完整生命周期（先回放验证再 deploy）：
#       POST /api/v1/rules  请求体参考 docs/operations.md 的数据集/训练章节的规则格式
#    b) 若只有 DB 备份里的旧行：优先整体库回滚会牵连其他数据——应先导出该行到临时
#       库核对，再按 a) 重建（无“恢复任意历史 revision”API，属当前版本限制）
# 4) 重建后的规则先 validate 再 deploy（带回放指标门禁）：
curl -s -X POST -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"actor":"sec-ops-oncall","note":"rollback 重建"}' \
  http://127.0.0.1:8000/api/v1/rules/<new_rule_id>/validate
curl -s -X POST -H "X-EvoNIDS-Admin-Token: ${EVONIDS_ADMIN_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"actor":"sec-ops-oncall"}' \
  http://127.0.0.1:8000/api/v1/rules/<new_rule_id>/deploy
```

## 验证恢复

```bash
curl -s http://127.0.0.1:8000/api/v1/rules | python -m json.tool
# 问题规则 stage=deprecated；重建规则 stage=deployed 且回放指标达标
curl -s http://127.0.0.1:8000/api/v1/audit | python -m json.tool   # 全部操作留痕
# 观察后续回放/告警指标回到基线
```

## 根因分析

1. 规则定义本身有缺陷（条件组合误匹配、正则/数值边界）。
2. 上线门禁不足：未跑回放验证或验证数据集覆盖不足（缺
   `unknown_holdout`/攻击样本）。
3. 数据驱动失准：训练/回放数据漂移后规则过拟合。
4. 流程问题：跳过 confirm/deploy 前的验证直接上线。

## 预防措施

- 强制 deploy 前 validate（回放指标门禁），指标不达标禁止 deploy。
- 规则变更走变更评审并在审计留痕（actor/reason/note 必填）。
- 对规则库做定期导出快照（纳入版本管理或备份），便于重建历史版本。
- 若“历史版本恢复”成为高频诉求，向后端团队提需求：暴露
  RuleVersion 历史的读取/回滚端点（当前仅有 repair 生成新版本）。

## 责任人与升级路径

- 一线：值班运营按第 2 步 deprecate 止血并导出证据。
- 升级：规则定义质量/回放指标异常 → 检测算法负责人；
  需要版本化回滚能力 → 后端负责人评估（涉及 `rule_lifecycle.py` 与 schema）。
