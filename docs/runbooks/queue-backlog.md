# Runbook：训练队列积压（queue-backlog）

> 适用环境：训练任务队列 = `training_runs` 表（`state='queued'`），由 API 进程内
> 单 worker 线程执行（`backend/app/services/training_worker.py`，轮询 2s；
> 见 `docs/adr/0004-in-process-training-worker.md`）。请求路径只插入 queued 行并返回
> 202。**本机无 Docker/集群/库，命令未在本环境执行（未验证）。**

## 症状

- `GET /api/v1/training/runs` 出现大量 `queued` 行且长时间不变。
- API 日志不再出现 `training worker picked up queued run ...`，或某条运行持续
  `running` 很久（CPU 被训练占满）。
- 控制台「模型」/训练入口提示排队时间变长。

## 影响面

- 新基线/新数据集训练延迟 → 模型演进、规则回放验证（replay validation）推迟。
- 若 API 进程重启，`running` 中的运行会被启动期逻辑标记为 `failed`
  （`recover_interrupted_training_runs`，见 `backend/app/main.py`），需要人工重提，
  而非自动重试。

## 立即处置步骤（可复制命令）

```bash
# 1) 看队列深度与运行状态分布
curl -s http://127.0.0.1:8000/api/v1/training/runs | python -m json.tool

# 2) 确认 worker 是否在跑 / 卡在哪条运行
docker compose logs api --since 15m | grep 'training worker'
# 定位某条运行后，看它对应数据集是否 ready、磁盘/内存是否够

# 3) 若只是慢（CPU 满载），等它完成并监控收敛
docker stats --no-stream api

# 4) 若 worker 消失/进程反复重启：重启 api 容器，启动期会把中断运行标为 failed
docker compose restart api
# 5) 标为 failed 的运行按需重新提交（不会自动重试）：
#    POST /api/v1/training/runs  请求体同 docs/operations.md "Train the known-attack baseline"

# 6) 只读巡检 SQL（容器内，勿手工改 state，除非确知后果）
docker compose exec -T postgres psql -U evonids -d evonids -c \
  "SELECT state, count(*) FROM training_runs GROUP BY state ORDER BY state;"
docker compose exec -T postgres psql -U evonids -d evonids -c \
  "SELECT id, state, created_at FROM training_runs WHERE state IN ('queued','running') ORDER BY created_at LIMIT 20;"
```

Kubernetes 变体（未验证）：`kubectl -n evonids logs deploy/evonids-api -c api
--tail=100 | grep 'training worker'`；保持 `api.replicas=1`（多副本会并发抢同一
queued 行，当前实现无行锁）。若 API 反复重启，参考
`docs/runbooks/database-migration-failure.md` 之外的配置排障。

## 验证恢复

```bash
curl -s http://127.0.0.1:8000/api/v1/training/runs | python -m json.tool   # queued 归零
# 日志出现 succeeded 且制品 sha256 校验通过（后端写入时自校验）
curl -s http://127.0.0.1:8000/api/v1/readiness | python -m json.tool        # training-runs/executor 检查
```

## 根因分析

1. 单 worker 串行 + 大训练集（如 CICIDS2017 全量）单条运行耗时长，队列自然积压。
2. 前一条运行异常挂起（缺依赖、OOM、数据集缺失）阻塞后续。
3. 进程重启把 running 标 failed，未自动重试导致“看起来排队但实际没在推进”。
4. `EVONIDS_TRAINING_CPU_THREADS` 配置不当（0=用满默认线程，与 API 请求抢 CPU）。

## 预防措施

- 训练窗口化：把重训练排到低峰，避免与采集/查询高峰期重叠。
- 监控 `training_runs` 状态分布与 worker 心跳日志；queued 超过阈值即告警。
- 关键运行提交前先确认数据集 `ready`（`GET /api/v1/datasets` 与
  `/api/v1/readiness` 的 dataset-assets/ml-runtime 项）。
- 明确预期：重启后 running → failed 是设计行为，提交侧做“失败可重试”文案/重提按钮。
- 多节点/高并发场景立项迁移到持久化任务队列 + 分布式 worker（ADR 0004 已记录）。

## 责任人与升级路径

- 一线：值班运营按上文重提 failed 运行并监控收敛。
- 升级：单条运行反复失败（缺依赖/数据问题）→ ML/后端负责人；
  需要队列化架构 → 应用架构负责人（涉及 `backend/app/services/training_worker.py`
  与 API 生命周期改造，非值班可处理范围）。
