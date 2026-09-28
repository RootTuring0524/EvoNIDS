# Runbook：模型回滚（model-rollback）

> 适用环境：模型制品目录 `EVONIDS_MODEL_ARTIFACT_ROOT`（Compose：
> `evonids-models` 卷 → `/data/evonids/models`；本地：`backend/model-artifacts`），
> 版本登记在 `model_versions` 表（`GET /api/v1/models`），制品可用性由
> `artifact_state` 文件检查判定（`backend/app/services/model_registry.py`）。
> 双通道回放打分由 `backend/scripts/backfill_dual_channel_inference.py` 等脚本完成。
> **本机无 Docker/集群/库，命令未在本环境执行（未验证）。**

## 症状

- 新基线/模型上线后误报率显著上升或漏报回归（观察告警与回放指标）。
- `GET /api/v1/models` 中某版本制品 `missing`（文件丢失/损坏），readiness 的
  `model-artifacts` 项告警。
- 训练产物 SHA-256 校验失败（后端写制品时自校验，异常会被记为失败运行）。

## 影响面

- 检测质量下降（误报/漏报）可能引发告警疲劳或漏检——按事件等级判断是否需
  立即回滚。
- `model_versions`/制品不一致会让后续训练与回放基于错误基线。

## 立即处置步骤（可复制命令）

```bash
# 1) 快照现状（用于复盘与必要时“再回滚”）
curl -s http://127.0.0.1:8000/api/v1/models > /tmp/models-before-rollback.json
curl -s http://127.0.0.1:8000/api/v1/readiness | python -m json.tool   # model-artifacts 项

# 2) 确认最近一次良好备份（含制品 tar 与 DB dump）
ls -lt backups/evonids-*/ | head
./scripts/backup/verify-backup.sh <backups/evonids-最近一次>

# 3) 快速止血 A：制品文件回滚（若只是文件损坏/误替换，上一版制品在备份里）
#    先复制现有制品目录留证，再从备份解包覆盖
cp -a backend/model-artifacts backend/model-artifacts.corrupt-$(date +%F)
tar -xzf <backups/evonids-...>/model-artifacts-*.tar.gz -C backend/
docker compose restart api        # readiness model-artifacts 重新检查文件存在性

# 4) 完整回滚 B：DB 与制品一起回退到上次良好备份（--confirm 覆盖目标库）
#    （模型注册元数据、数据集元数据、审计均随库回退；先备份当前库再执行）
./scripts/backup/restore.sh <backups/evonids-上次良好> --confirm --restore-files

# 5) 若选择“保留现状数据、仅切回旧算法结论”，用上一版制品重跑双通道回放打分
cd backend && ./.venv/Scripts/python.exe scripts/backfill_dual_channel_inference.py --help
# 按脚本参数对历史 replay flow 重打分，新结论会写入 inferences 表（覆盖式重算需先确认幂等性）
```

Kubernetes 变体（未验证）：制品与数据集在同一 PVC `evonids-data`
（subPath 无，挂 `/data/evonids`）；回滚 = 从卷快照恢复该 PVC 或按第 3 步在
Pod 内替换制品后 `kubectl -n evonids rollout restart deploy/evonids-api`。

## 验证恢复

```bash
curl -s http://127.0.0.1:8000/api/v1/models | python -m json.tool    # 目标版本 artifact 存在
curl -s http://127.0.0.1:8000/api/v1/readiness | python -m json.tool  # model-artifacts=pass
# 回放/告警指标回落至回滚前基线；抽查样本告警人工比对
```

## 根因分析

1. 训练数据漂移/标注问题导致新基线劣化（检查数据集 profile 与验证集指标）。
2. 制品发布流程缺陷：文件被覆盖/未原子替换/权限问题（uid 10001 写权限）。
3. 依赖/运行时版本变化（sklearn/joblib 版本与训练时不一致）导致行为漂移。
4. 误将“训练成功”当作“可上线”：缺乏上线前回放门禁。

## 预防措施

- 上线前对候选模型执行回放验证（规则/告警回放指标），低于阈值禁止 deploy。
- 制品目录与 DB 版本登记采用“写新不覆盖旧 + SHA-256 校验”，保留 N 个可回退点。
- 备份策略覆盖 `model_versions`（在 DB dump 中）与制品目录（backup.sh），
  并定期演练（`docs/runbooks/backup-restore-drill.md`）。
- 任何回滚都要先备份“当前坏状态”，便于事后复盘与二次回滚。

## 责任人与升级路径

- 一线：值班运营按 3/4 快速回滚并记录 `model_versions` 变化前后的制品哈希。
- 升级：判断为数据/特征问题 → ML 负责人；发布流程缺陷 → 平台负责人；
  涉及多轮上线对照 → 走正式变更评审并在审计日志留痕（所有写操作需 admin 令牌）。
