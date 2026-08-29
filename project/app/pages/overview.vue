<script setup lang="ts">
import { ArrowRight, CheckCircle2, Clock4, Filter, RefreshCw, ShieldAlert, Zap } from '~/utils/icons'
import {
  alertsResponseSchema,
  datasetsResponseSchema,
  overviewMetricsSchema,
  trainingRunsResponseSchema,
} from '~~/shared/schemas/security'
import type { Alert } from '~~/shared/types/security'

const { data, refresh, status, error } = await useAsyncData('overview-alerts', () => validatedFetch('/alerts', alertsResponseSchema))
const { data: operations, refresh: refreshOperations, error: operationsError } = await useAsyncData('overview-metrics', () => validatedFetch('/overview', overviewMetricsSchema))
const { data: trainingRuns, refresh: refreshTrainingRuns } = await useAsyncData('overview-training-runs', () => validatedFetch('/training/runs', trainingRunsResponseSchema))
const { data: datasets, refresh: refreshDatasets } = await useAsyncData('overview-datasets', () => validatedFetch('/datasets', datasetsResponseSchema))
const useMockApi = useRuntimeConfig().public.useMockApi
const onlyUnassigned = ref(false)
const recentAlerts = computed(() => (data.value?.items.filter((item)=>!onlyUnassigned.value||!item.owner) ?? []).slice(0, 5))
const metrics = computed(() => [
  { label: '待研判告警', value: String(operations.value?.pendingAlerts ?? '—'), delta: `${operations.value?.unassignedAlerts ?? '—'} 条未分派`, tone: 'critical' as const },
  { label: '高风险告警', value: String(operations.value?.highRiskAlerts ?? '—'), delta: '高危及严重且未关闭', tone: 'high' as const },
  { label: '采集节点', value: `${operations.value?.sensors.online ?? '—'} / ${operations.value?.sensors.total ?? '—'}`, delta: `${operations.value?.sensors.degraded ?? '—'} 个降级`, tone: 'good' as const },
  { label: '异常 Flow', value: String(operations.value?.anomalousFlows ?? '—'), delta: `累计 ${operations.value?.flows ?? '—'} 条`, tone: 'info' as const },
  { label: '规则闭环', value: `${operations.value?.deployedRules ?? '—'} / ${(operations.value?.deployedRules ?? 0) + (operations.value?.candidateRules ?? 0)}`, delta: `${operations.value?.candidateRules ?? '—'} 条处理中`, tone: 'accent' as const },
])
const latestBaseline = computed(() => trainingRuns.value?.items.find((item) =>
  item.task === 'known_attack_classification_baseline'
  && item.state === 'succeeded'
  && item.metrics
  && 'macroF1' in item.metrics,
))
const baselineMacroF1 = computed(() => {
  const metrics = latestBaseline.value?.metrics
  return metrics && 'macroF1' in metrics ? metrics.macroF1 : null
})
const baselineDataset = computed(() => datasets.value?.items.find((item) => item.id === latestBaseline.value?.datasetId))
const shortHash = computed(() => latestBaseline.value?.artifactSha256?.slice(0, 12) || '—')

const detectorHealth = computed(() => {
  const current = operations.value
  const sensorTotal = current?.sensors.total || 0
  const onlineWidth = sensorTotal ? Math.round(((current?.sensors.online || 0) / sensorTotal) * 100) : 0
  return [
    { label: 'Suricata 采集节点', value: `${current?.sensors.online ?? '—'} / ${current?.sensors.total ?? '—'}`, width: onlineWidth, state: current?.sensors.offline ? 'degraded' : 'healthy' },
    { label: '持久化 Flow', value: String(current?.flows ?? '—'), width: current?.flows ? 100 : 0, state: current?.flows ? 'healthy' : 'degraded' },
    { label: '告警研判队列', value: `${current?.pendingAlerts ?? '—'} 待处理`, width: current?.pendingAlerts ? 72 : 100, state: current?.pendingAlerts ? 'degraded' : 'healthy' },
    { label: '已部署规则', value: String(current?.deployedRules ?? '—'), width: current?.deployedRules ? 100 : 0, state: current?.deployedRules ? 'healthy' : 'degraded' },
  ]
})

async function refreshAll() {
  await Promise.all([refresh(), refreshOperations(), refreshTrainingRuns(), refreshDatasets()])
}

function rowToAlert(row: Alert) {
  navigateTo(`/alerts/${row.id}`)
}
function onAlertKeydown(event:KeyboardEvent,row:Alert){if(event.key==='Enter'||event.key===' '){event.preventDefault();rowToAlert(row)}}
</script>

<template>
  <div class="overview-page">
    <PageHeader eyebrow="Security Operations" title="运营态势" description="从实时检测到规则沉淀的全链路运行视图">
      <button class="header-button" @click="refreshAll"><RefreshCw :size="14" :class="{ spinning: status === 'pending' }" />刷新数据</button>
      <NuxtLink to="/alerts" class="header-button primary"><ShieldAlert :size="14" />进入告警队列</NuxtLink>
    </PageHeader>

    <section class="metric-strip" aria-label="关键运行指标">
      <MetricCard v-for="metric in metrics" :key="metric.label" v-bind="metric" />
    </section>

    <NuxtLink v-if="latestBaseline?.metrics" to="/models" class="baseline-rail" aria-label="查看 CICIDS2017 真实训练结果">
      <span class="baseline-state"><CheckCircle2 :size="15"/><b>真实基线已验证</b><small>{{ baselineDataset?.name || latestBaseline.datasetName }}</small></span>
      <dl>
        <div><dt>数据行</dt><dd>{{ (baselineDataset?.totalSamples || latestBaseline.samplesSeen).toLocaleString() }}</dd></div>
        <div><dt>有效特征</dt><dd>{{ latestBaseline.metrics.featureCount }}</dd></div>
        <div><dt>测试 Macro F1</dt><dd>{{ baselineMacroF1 === null ? '—' : `${(baselineMacroF1 * 100).toFixed(2)}%` }}</dd></div>
        <div><dt>模型制品</dt><dd class="mono">{{ shortHash }}</dd></div>
      </dl>
      <span class="baseline-action">查看数据血缘与分类结果 <ArrowRight :size="13"/></span>
    </NuxtLink>

    <LoadingState v-if="status==='pending'&&!data" :rows="8" label="正在加载运营态势"/>
    <ErrorState v-else-if="error || operationsError" title="无法加载运营态势" description="检测数据暂时不可用，请重试。" @retry="refreshAll"/>
    <EmptyState v-else-if="!data?.items.length" title="当前范围暂无告警" description="检测管道保持在线，所选时间范围内没有安全事件。"/>
    <template v-else>
    <section class="operations-grid">
      <div class="trend-section surface-panel">
        <div class="section-head">
          <div><h2>威胁活动趋势</h2><p>{{ useMockApi ? '固定演示数据 · 用于界面验收' : '真实时序聚合尚未接入 · 不展示虚构曲线' }}</p></div>
          <div class="legend"><span><i class="accent" />全部告警</span><span><i class="high" />高危及以上</span></div>
        </div>
        <ClientOnly v-if="useMockApi"><ChartsThreatTrend /><template #fallback><div class="chart-skeleton" /></template></ClientOnly>
        <div v-else class="honest-placeholder"><ShieldAlert :size="22"/><div><b>等待真实时序聚合接口</b><span>当前指标与告警队列均来自数据库；趋势图暂不以静态样本冒充实时结果。</span></div></div>
        <div class="trend-foot"><span><b>{{ useMockApi ? '演示模式' : '真实模式' }}</b> · {{ useMockApi ? '趋势为固定可复现样本' : '所有可见数字来自持久化记录' }}</span><button @click="navigateTo('/alerts')">查看队列 <ArrowRight :size="13" /></button></div>
      </div>

      <aside class="work-queue surface-panel">
        <div class="section-head compact"><div><h2>分析师工作队列</h2><p>按业务风险与处置时效排序</p></div><span class="sla">SLA 24m</span></div>
        <div class="queue-items"><button v-for="(item,index) in recentAlerts.slice(0,3)" :key="item.id" @click="navigateTo(`/alerts/${item.id}`)"><span :class="['queue-rank',item.severity,'mono']">{{String(index+1).padStart(2,'0')}}</span><span><b>{{item.title}}</b><small>{{item.id}} · {{item.owner || '尚未分派'}}</small></span><ArrowRight :size="14" /></button></div>
        <div class="handover"><Clock4 :size="14" /><span><b>当前待办</b><small>{{ operations?.unassignedAlerts ?? '—' }} 条告警尚未分派，优先处理高风险记录</small></span></div>
      </aside>
    </section>

    <section class="lower-grid">
      <div class="alerts-section surface-panel">
        <div class="section-head table-head"><div><h2>优先告警</h2><p>实时队列 · {{recentAlerts.length}} 条当前结果</p></div><button class="filter-button" :class="{active:onlyUnassigned}" :aria-pressed="onlyUnassigned" @click="onlyUnassigned=!onlyUnassigned"><Filter :size="13" />仅看未分派</button></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>等级</th><th>告警 / 检测器</th><th>通信实体</th><th>风险</th><th>状态</th><th>时间</th></tr></thead>
            <tbody>
              <tr v-for="row in recentAlerts" :key="row.id" tabindex="0" @click="rowToAlert(row)" @keydown="onAlertKeydown($event,row)">
                <td><SeverityBadge :level="row.severity" compact /></td>
                <td><b>{{ row.title }}</b><small class="mono">{{ row.id }} · {{ row.detector }}</small></td>
                <td class="mono"><span>{{ row.sourceIp }}</span><small>→ {{ row.destinationIp }}:{{ row.destinationPort }}</small></td>
                <td><RiskScore :value="row.riskScore" :severity="row.severity" compact /></td>
                <td><StatusIndicator :status="row.status" :label="({ new: '待研判', investigating: '调查中', contained: '已遏制', closed: '已关闭' } as Record<string,string>)[row.status]" /></td>
                <td class="mono subtle">{{ formatTimestamp(row.timestamp) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <aside class="health-section surface-panel">
        <div class="section-head compact"><div><h2>检测管道</h2><p>基于持久化运行状态</p></div><CheckCircle2 :size="16" class="success" /></div>
        <div class="health-list">
          <div v-for="item in detectorHealth" :key="item.label">
            <p><span><i :class="item.state" />{{ item.label }}</span><b class="mono">{{ item.value }}</b></p>
            <div class="health-track"><span :style="{ width: `${item.width}%` }" :class="item.state" /></div>
          </div>
        </div>
        <NuxtLink to="/sensors" class="health-link"><Zap :size="13" />查看探针与采集质量 <ArrowRight :size="13" /></NuxtLink>
      </aside>
    </section>
    </template>
  </div>
</template>

<style scoped>
.overview-page { padding: 20px 22px 28px; }
.header-button { display: inline-flex; align-items: center; gap: 6px; height: 34px; padding: 0 10px; border: 1px solid var(--border-default); border-radius: 8px; background: var(--surface-1); color: var(--text-secondary); cursor: pointer; text-decoration: none; font-size: 12px; }.header-button:hover { color: var(--text-primary); background: var(--surface-2); }.header-button.primary { border-color: color-mix(in srgb, var(--accent) 55%, var(--border-default)); background: var(--accent-muted); color: var(--accent-strong); }.spinning { animation: spin .8s linear infinite; } @keyframes spin { to { transform: rotate(360deg); } }
.metric-strip { display: grid; grid-template-columns: repeat(5, 1fr); margin-bottom: 14px; border-block: 1px solid var(--border-default); background: var(--surface-1); }.metric-item { min-width: 0; padding: 11px 14px; border-right: 1px solid var(--border-subtle); }.metric-item:last-child { border-right: 0; }.metric-item p { margin: 0 0 3px; color: var(--text-tertiary); font-size:13px; font-weight: 600; letter-spacing: .03em; }.metric-item div { display: flex; align-items: baseline; gap: 8px; }.metric-item strong { font-size: 19px; font-weight: 650; }.metric-item span { overflow: hidden; color: var(--text-tertiary); font-size:13px; text-overflow: ellipsis; white-space: nowrap; }.tone-critical { color: var(--severity-critical); }.tone-high { color: var(--severity-high); }.tone-good { color: var(--status-success); }.tone-info { color: var(--severity-info); }.tone-accent { color: var(--accent-strong); }
.baseline-rail{display:grid;grid-template-columns:minmax(210px,.9fr) minmax(440px,1.6fr) auto;align-items:center;gap:18px;min-height:66px;margin:-2px 0 14px;padding:9px 13px;border:1px solid color-mix(in srgb,var(--status-success) 28%,var(--border-default));border-left:3px solid var(--status-success);border-radius:7px;background:color-mix(in srgb,var(--status-success) 4%,var(--surface-1));color:inherit;text-decoration:none}.baseline-state{display:grid;grid-template-columns:18px 1fr;align-items:center;min-width:0}.baseline-state svg{grid-row:1/3;color:var(--status-success)}.baseline-state b,.baseline-state small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.baseline-state b{font-size:13px}.baseline-state small{color:var(--text-tertiary);font-size:12px}.baseline-rail dl{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin:0}.baseline-rail dl div{padding:0 12px;border-left:1px solid var(--border-subtle)}.baseline-rail dt{color:var(--text-tertiary);font-size:11px}.baseline-rail dd{margin:3px 0 0;color:var(--text-primary);font-size:13px;font-weight:650}.baseline-action{display:flex;align-items:center;gap:5px;color:var(--accent-strong);font-size:12px;white-space:nowrap}
.operations-grid { display: grid; grid-template-columns: minmax(0, 1.8fr) minmax(310px, .8fr); gap: 14px; margin-bottom: 14px; }.trend-section, .work-queue, .alerts-section, .health-section { overflow: hidden; }.section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 13px 15px 0; }.section-head h2 { margin: 0; font-size: 14px; font-weight: 650; }.section-head p { margin: 2px 0 0; color: var(--text-tertiary); font-size:13px; }.legend { display: flex; gap: 12px; color: var(--text-tertiary); font-size:13px; }.legend span { display: flex; align-items: center; gap: 5px; }.legend i { width: 14px; height: 2px; }.legend .accent { background: var(--accent); }.legend .high { background: var(--severity-high); }.chart-skeleton { height: 206px; margin: 12px; background: var(--surface-2); }.honest-placeholder{display:flex;align-items:center;justify-content:center;gap:10px;height:206px;margin:12px;background:var(--surface-2);color:var(--text-tertiary)}.honest-placeholder b,.honest-placeholder span{display:block}.honest-placeholder b{color:var(--text-secondary);font-size:13px}.honest-placeholder span{margin-top:3px;max-width:440px;font-size:12px}.trend-foot { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 39px; padding: 8px 14px; border-top: 1px solid var(--border-subtle); background: var(--surface-2); color: var(--text-secondary); font-size:13px; }.trend-foot b { color: var(--text-primary); }.trend-foot button { display: flex; align-items: center; gap: 4px; border: 0; background: none; color: var(--accent-strong); cursor: pointer; white-space: nowrap; }
.section-head.compact { padding-bottom: 10px; border-bottom: 1px solid var(--border-subtle); }.sla { padding: 2px 6px; border-radius: 4px; background: color-mix(in srgb, var(--severity-high) 10%, transparent); color: var(--severity-high); font-size:13px; }.queue-items button { display: grid; grid-template-columns: 30px 1fr 18px; gap: 8px; align-items: center; width: 100%; min-height: 57px; padding: 7px 12px; border: 0; border-bottom: 1px solid var(--border-subtle); background: transparent; color: var(--text-tertiary); cursor: pointer; text-align: left; }.queue-items button:hover { background: var(--surface-2); color: var(--text-primary); }.queue-items span:nth-child(2) { min-width: 0; }.queue-items b, .queue-items small { display: block; }.queue-items b { overflow: hidden; color: var(--text-primary); font-size:14px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }.queue-items small { margin-top: 2px; color: var(--text-tertiary); font-size:13px; }.queue-rank { display: grid; width: 26px; height: 26px; place-items: center; border-radius: 6px; font-size:13px; }.queue-rank.critical { background: color-mix(in srgb, var(--severity-critical) 10%, transparent); color: var(--severity-critical); }.queue-rank.high { background: color-mix(in srgb, var(--severity-high) 10%, transparent); color: var(--severity-high); }.queue-rank.medium { background: color-mix(in srgb, var(--severity-medium) 10%, transparent); color: var(--severity-medium); }.handover { display: flex; gap: 8px; align-items: center; margin: 10px 12px; padding: 8px 9px; border-left: 2px solid var(--severity-medium); background: color-mix(in srgb, var(--severity-medium) 7%, transparent); color: var(--severity-medium); }.handover b, .handover small { display: block; }.handover b { color: var(--text-primary); font-size:13px; }.handover small { color: var(--text-tertiary); font-size:13px; }
.lower-grid { display: grid; grid-template-columns: minmax(0, 1.8fr) minmax(310px, .8fr); gap: 14px; }.table-head { align-items: center; padding-bottom: 10px; border-bottom: 1px solid var(--border-subtle); }.filter-button { display: flex; align-items: center; gap: 4px; padding: 5px 7px; border: 1px solid var(--border-subtle); border-radius: 6px; background: var(--surface-2); color: var(--text-tertiary); font-size:13px; cursor: pointer; }.filter-button.active { border-color: var(--accent); background: var(--accent-muted); color: var(--accent-strong); }.table-wrap { overflow-x: auto; } table { width: 100%; border-collapse: collapse; } th { height: 30px; padding: 0 10px; background: var(--surface-2); color: var(--text-tertiary); font-size:13px; font-weight: 650; text-align: left; white-space: nowrap; } td { height: 44px; padding: 5px 10px; border-top: 1px solid var(--border-subtle); color: var(--text-secondary); font-size:13px; white-space: nowrap; } tbody tr { cursor: pointer; transition: background 120ms ease; } tbody tr:hover, tbody tr:focus-visible { background: var(--surface-2); } td b, td small { display: block; } td b { max-width: 260px; overflow: hidden; color: var(--text-primary); font-size:13px; font-weight: 600; text-overflow: ellipsis; } td small { margin-top: 2px; color: var(--text-tertiary); font-size:13px; }.risk { display: inline-grid; width: 26px; height: 23px; place-items: center; border-radius: 5px; font-size:13px; font-weight: 700; }.risk-critical { color: var(--severity-critical); background: color-mix(in srgb, var(--severity-critical) 10%, transparent); }.risk-high { color: var(--severity-high); background: color-mix(in srgb, var(--severity-high) 10%, transparent); }.risk-medium { color: var(--severity-medium); background: color-mix(in srgb, var(--severity-medium) 10%, transparent); }.risk-low, .risk-info { color: var(--severity-info); background: color-mix(in srgb, var(--severity-info) 9%, transparent); }.subtle { color: var(--text-tertiary); }
.success { color: var(--status-success); }.health-list { display: grid; gap: 12px; padding: 13px 15px 14px; }.health-list p { display: flex; justify-content: space-between; margin: 0 0 4px; color: var(--text-secondary); font-size:13px; }.health-list p span { display: flex; align-items: center; gap: 5px; }.health-list p i { width: 5px; height: 5px; border-radius: 50%; }.health-list p i.healthy { background: var(--status-success); }.health-list p i.degraded { background: var(--status-warning); }.health-list p b { color: var(--text-tertiary); font-size:13px; font-weight: 500; }.health-track { height: 3px; overflow: hidden; background: var(--surface-3); }.health-track span { display: block; height: 100%; background: var(--status-success); }.health-track span.degraded { background: var(--status-warning); }.health-link { display: flex; align-items: center; justify-content: center; gap: 5px; min-height: 35px; border-top: 1px solid var(--border-subtle); color: var(--accent-strong); font-size:13px; text-decoration: none; }
@media (max-width: 1120px) { .operations-grid, .lower-grid { grid-template-columns: 1fr; }.metric-strip { grid-template-columns: repeat(3, 1fr); }.baseline-rail{grid-template-columns:1fr auto}.baseline-rail dl{grid-column:1/-1;order:3}.baseline-rail dl div:first-child{border-left:0;padding-left:0} }
@media (max-width: 700px) { .overview-page { padding: 16px 12px 24px; }.metric-strip { grid-template-columns: 1fr 1fr; }.metric-strip :deep(.metric-card:last-child) { grid-column: 1 / -1; }.baseline-rail{grid-template-columns:1fr}.baseline-rail dl{grid-template-columns:1fr 1fr}.baseline-rail dl div:nth-child(odd){border-left:0;padding-left:0}.baseline-action{justify-self:start}.section-head { flex-direction: column; }.legend { flex-wrap: wrap; } }
</style>
