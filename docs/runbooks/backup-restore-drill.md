# Runbook：备份恢复演练（backup-restore-drill）

> 目标：周期性验证 `scripts/backup/` 全链路可用——备份可校验、恢复可执行、
> 恢复后的库可被应用正常使用。建议每季度至少一次，并在大版本升级前执行。
> **本机无 Docker/集群/库，命令未在本环境执行（未验证）——本文即演练脚本本身。**

## 症状（何时触发本演练）

- 计划内：每季度例行；任何存储/镜像/迁移大变更前。
- 计划外：发生过“备份存在但恢复失败”教训后的一次复盘演练；或备份产物从未
  被真正恢复过（备份 = 没验证过的备份）。

## 影响面

- 演练使用独立目标库/临时目录，不触碰生产数据；演练失败不产生生产影响，
  但暴露“真实灾难时无法恢复”的风险。

## 演练步骤（可复制命令）

```bash
cd <repo-root>
# ---------------------------------------------------------------------------
# 阶段 0：准备（Compose 生产栈在跑；本机可访问 127.0.0.1:5432 或先 port-forward）
# ---------------------------------------------------------------------------
export PGHOST=127.0.0.1 PGPORT=5432 PGUSER=evonids PGPASSWORD="$POSTGRES_PASSWORD" PGDATABASE=evonids

# ---------------------------------------------------------------------------
# 阶段 1：真实备份（含模型产物；数据集文件可选 --include-datasets）
# ---------------------------------------------------------------------------
./scripts/backup/backup.sh --env-file .env
LATEST=$(ls -dt backups/evonids-* | head -1)
echo "备份目录: $LATEST"

# ---------------------------------------------------------------------------
# 阶段 2：校验（校验和 + pg_restore --list + tar/gzip）
# ---------------------------------------------------------------------------
./scripts/backup/verify-backup.sh "$LATEST"        # 退出码 0 = 通过

# ---------------------------------------------------------------------------
# 阶段 3：隔离环境恢复（演练目标库，绝不直接覆盖生产库）
# ---------------------------------------------------------------------------
# 3a) 建演练库
psql -h 127.0.0.1 -U evonids -d postgres -c \
  "DROP DATABASE IF EXISTS evonids_drill;"
psql -h 127.0.0.1 -U evonids -d postgres -c \
  "CREATE DATABASE evonids_drill OWNER evonids;"

# 3b) 恢复到演练库（PGDATABASE 指演练库 + --confirm）
PGDATABASE=evonids_drill ./scripts/backup/restore.sh "$LATEST" --confirm --restore-files
# 若模型产物恢复到临时目录：EVONIDS_MODEL_ARTIFACT_DIR 指临时目录再跑一次

# 3c) dry-run 也应演练（不改任何东西的预览路径）
PGDATABASE=evonids_drill ./scripts/backup/restore.sh "$LATEST" --dry-run

# ---------------------------------------------------------------------------
# 阶段 4：应用侧冒烟（临时把演练库挂给一个一次性 api 容器）
# ---------------------------------------------------------------------------
# 生成临时令牌（任意随机串，仅演练用）
ADMIN=$(openssl rand -hex 24); SENSOR=$(openssl rand -hex 24)
docker compose run --rm --no-deps \
  -e EVONIDS_ENVIRONMENT=development \
  -e EVONIDS_DATABASE_URL="postgresql+psycopg://evonids:${POSTGRES_PASSWORD}@127.0.0.1:5432/evonids_drill" \
  -e EVONIDS_ADMIN_API_TOKEN="$ADMIN" -e EVONIDS_SENSOR_INGEST_TOKEN="$SENSOR" \
  -p 18000:8000 api uvicorn app.main:app --host 0.0.0.0 --port 8000 &
sleep 8
curl -s http://127.0.0.1:18000/api/v1/health          # database:"ok"
curl -s http://127.0.0.1:18000/api/v1/sensors | python -m json.tool   # 数据存在
curl -s http://127.0.0.1:18000/api/v1/readiness | python -m json.tool
kill %1   # 清理演练容器

# ---------------------------------------------------------------------------
# 阶段 5：清理演练库 + 记录结果
# ---------------------------------------------------------------------------
psql -h 127.0.0.1 -U evonids -d postgres -c "DROP DATABASE evonids_drill;"
echo "演练完成: $(date -Is) 备份=$LATEST" >> backups/drill-log.txt
```

Kubernetes 变体（未验证）：先 `kubectl -n evonids port-forward svc/evonids-postgres
5432:5432 &`，其余命令相同；`--restore-files` 的目标目录用临时 PVC/Pod 挂载点，
避免直接写生产 `evonids-data`。

## 验证恢复（演练成功判据）

- 阶段 2 退出码 0；阶段 3 无报错；阶段 4 中 `/api/v1/health` database=ok、
  `/api/v1/sensors` 能看到备份时刻的数据行、readiness 关键项 pass。
- 数据一致性抽查：`/api/v1/sensors` 数量、`/api/v1/datasets` 数量与备份前一致。
- 记录了 RTO（从故障到恢复完成的时间）与 RPO（最近一次备份与故障时刻的差距）。

## 根因分析（演练失败时）

1. 备份目录被裁剪/移动（retention 策略与异地复制没覆盖）。
2. 校验和文件缺失或内容与文件名不匹配（手工拷贝损坏）。
3. 目标库不存在/权限不足（restore.sh 不会自动建库）。
4. 制品路径在目标机不同（`EVONIDS_MODEL_ARTIFACT_DIR` 未指向正确位置）。

## 预防措施

- 把本演练纳入发布流程与值班交接：备份 → 校验 → 隔离恢复冒烟。
- 异地/多副本存放备份（backup.sh 产物目录可整体同步）。
- 在 CI/沙箱脚本化阶段 1–2（有 bash 的机器上执行 `bash -n *.sh` 并跑校验）。

## 责任人与升级路径

- 一线：值班运营执行演练并记录 RTO/RPO。
- 升级：演练失败说明灾难恢复能力缺失 → 平台/存储负责人限期修复并复演；
  备份策略调整 → 安全与平台共同评审（RPO 需求决定备份频率与是否叠加卷快照）。
