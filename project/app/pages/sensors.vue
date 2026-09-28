<script setup lang="ts">
import { AlertTriangle, DatabaseZap, FileUp, MapPin, Radar, RefreshCw, Search, ServerCog, ShieldCheck, XCircle } from '~/utils/icons'
import { detectionStatusSchema, eveIngestionResponseSchema, ingestionBatchesResponseSchema, sensorHealthResponseSchema, sensorsResponseSchema } from '~~/shared/schemas/security'
import type { DetectionMode, IngestionBatchStatus, SensorRecord, SensorState } from '~~/shared/types/security'
import { formatSensorMetric } from '~/utils/formatSensorMetric'

const isMock = useRuntimeConfig().public.useMockApi

const { data, status, error, refresh } = await useAsyncData('sensor-registry', () => validatedFetch('/sensors', sensorsResponseSchema))
const search = ref('')
const state = ref<'all' | SensorState>('all')
const selectedId = ref<string | null>(null)
const importSensorId = ref('lab-core-01')
const importFile = ref<File | null>(null)
const importing = ref(false)
const importMessage = ref('')
const importTone = ref<'success' | 'error'>('success')
const stateLabels: Record<SensorState, string> = { online: '在线', degraded: '降级', offline: '离线', maintenance: '维护中' }

const filtered = computed(() => (data.value?.items ?? []).filter((item) =>
  (state.value === 'all' || item.state === state.value) &&
  (!search.value || `${item.id} ${item.name} ${item.location ?? ''}`.toLowerCase().includes(search.value.toLowerCase())),
))
const selected = computed(() => filtered.value.find((item) => item.id === selectedId.value) ?? filtered.value[0] ?? null)
const readiness = computed(() => {
  const summary = data.value?.summary
  if (!summary?.total) return 0
  return Math.round(((summary.online + summary.degraded * 0.5) / summary.total) * 100)
})

function formatNumber(value: number) { return new Intl.NumberFormat('zh-CN').format(value) }
function formatTime(value: string | null) {
  if (!value) return '从未上报'
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(value))
}
function formatTs(value: string | null) { return value ? formatTime(value) : '—' }
function formatBytes(value: number) {
  if (value < 1024) return `${formatNumber(value)} B`
  if (value < 1024 * 1024) return `${formatNumber(Math.round(value / 1024))} KB`
  return `${formatNumber(Math.round(value / (1024 * 1024)))} MB`
}
function selectSensor(row: SensorRecord) { selectedId.value = row.id; importSensorId.value = row.id }
function onFile(event: Event) { importFile.value = (event.target as HTMLInputElement).files?.[0] ?? null }
async function importEve() {
  if (!importFile.value || !importSensorId.value.trim()) { importTone.value = 'error'; importMessage.value = '请选择 EVE JSON/NDJSON 文件并填写探针 ID。'; return }
  importing.value = true; importMessage.value = ''
  try {
    const result = await validatedFetch(`/ingestion/eve?sensorId=${encodeURIComponent(importSensorId.value.trim())}`, eveIngestionResponseSchema, {
      method: 'POST', body: await importFile.value.text(), headers: { 'content-type': 'application/x-ndjson' },
    })
    importTone.value = result.rejectedEvents ? 'error' : 'success'
    importMessage.value = `已接收 ${result.acceptedEvents} 条：新增 Flow ${result.createdFlows}、告警 ${result.createdAlerts}、重复 ${result.duplicateEvents}、拒绝 ${result.rejectedEvents}。`
    await refresh()
  } catch { importTone.value = 'error'; importMessage.value = '导入失败。真实后端模式下请检查采集令牌、文件编码和 API 状态。' }
  finally { importing.value = false }
}

// --- 在线检测状态横幅（GET /detections/status） ---
const { data: detectionStatus, status: detectionStatusState, error: detectionStatusError, refresh: refreshDetectionStatus } = await useAsyncData('sensor-detection-status', () => validatedFetch('/detections/status', detectionStatusSchema))
const detectionStatusLoading = computed(() => detectionStatusState.value === 'pending' && !detectionStatus.value)
const modeMeta: Record<DetectionMode, { label: string; hint: string }> = {
  disabled: { label: '在线告警已关闭', hint: '在线检测未启用：新摄入流量不会经过模型评分，也不会产生在线告警。' },
  shadow: { label: '在线告警：影子模式', hint: '影子模式下模型只评分并留存检测证据，即使命中风险也不会自动生成模型告警。' },
  enabled: { label: '在线告警已启用', hint: '启用模式下，模型命中风险流将自动生成在线告警并计入告警队列。' },
}
const channelLabels: Record<string, string> = { baseline: '已知攻击基线', autoencoder: '未知异常 AE', suricata: '规则通道' }

// --- 选中探针的数据质量与批次台账 ---
const healthWindowSeconds = ref(3600)
const activeSensorId = computed(() => selected.value?.id ?? null)
const windowLabels: Record<number, string> = { 3600: '最近 1 小时', 21600: '最近 6 小时', 86400: '最近 24 小时', 604800: '最近 7 天' }
const { data: quality, status: qualityStatus, error: qualityError, refresh: refreshQuality } = await useAsyncData('sensor-data-quality', async () => {
  const sensorId = activeSensorId.value
  if (!sensorId) return { items: [] }
  return validatedFetch(`/sensors/health?sensorId=${encodeURIComponent(sensorId)}&windowSeconds=${healthWindowSeconds.value}`, sensorHealthResponseSchema)
}, { watch: [activeSensorId, healthWindowSeconds] })
const qualityItem = computed(() => (quality.value?.items ?? []).find((row) => row.sensorId === activeSensorId.value) ?? null)

type QualityMetricKey = 'rejectRate' | 'duplicateRate' | 'ingestLatencyP50Ms' | 'ingestLatencyP95Ms' | 'clockSkewSeconds' | 'gapCount' | 'estimatedMissingSeconds'
const metricDefinitions: Array<{ key: QualityMetricKey; label: string }> = [
  { key: 'rejectRate', label: '事件拒绝率' },
  { key: 'duplicateRate', label: '事件重复率' },
  { key: 'ingestLatencyP50Ms', label: '摄取延迟 P50' },
  { key: 'ingestLatencyP95Ms', label: '摄取延迟 P95' },
  { key: 'clockSkewSeconds', label: '时钟偏差' },
  { key: 'gapCount', label: '数据缺口次数' },
  { key: 'estimatedMissingSeconds', label: '估计缺失时长' },
]
const metricViews = computed(() => {
  const row = qualityItem.value
  if (!row) return []
  return metricDefinitions.map((def) => ({ label: def.label, view: formatSensorMetric(row[def.key]) }))
})

const channelList = computed(() => Object.entries(detectionStatus.value?.channels ?? {}).map(([key, value]) => ({ key, value })))

const batchPage = ref(1)
const batchPageSize = ref(25)
const { data: batches, status: batchesStatus, error: batchesError, refresh: refreshBatches } = await useAsyncData('sensor-batch-ledger', async () => {
  const sensorId = activeSensorId.value
  if (!sensorId) return { items: [], total: 0, page: 1, pageSize: batchPageSize.value }
  return validatedFetch(`/sensors/${encodeURIComponent(sensorId)}/batches?page=${batchPage.value}&pageSize=${batchPageSize.value}`, ingestionBatchesResponseSchema)
}, { watch: [activeSensorId, batchPage, batchPageSize] })
watch(activeSensorId, () => { batchPage.value = 1 })
const batchRows = computed(() => batches.value?.items ?? [])
const batchTotal = computed(() => batches.value?.total ?? 0)
const batchStatusLabels: Record<IngestionBatchStatus, string> = { accepted: '已接收', partial: '部分处理', rejected: '已拒绝' }
const canPrevious = computed(() => batchPage.value > 1)
const canNext = computed(() => batchPage.value * batchPageSize.value < batchTotal.value)
</script>

<template>
  <div class="sensors-page">
    <PageHeader eyebrow="Collection Plane" title="探针与数据源" description="管理 Suricata 采集节点、上报健康度与 EVE 数据质量">
      <button class="page-button" :disabled="status === 'pending'" @click="() => refresh()"><RefreshCw :size="14" :class="{ spin: status === 'pending' }" />刷新状态</button>
    </PageHeader>

    <section v-if="detectionStatus" class="detection-banner surface-panel" :class="`mode-${detectionStatus.mode}`" aria-label="在线检测状态横幅">
      <Radar :size="18" aria-hidden="true" />
      <div class="banner-copy">
        <b>在线检测<span v-if="isMock" class="demo-tag">演示</span></b>
        <strong>{{ modeMeta[detectionStatus.mode].label }}</strong>
        <p>{{ modeMeta[detectionStatus.mode].hint }}</p>
        <ul v-if="detectionStatus.notes.length" class="banner-notes">
          <li v-for="(note, index) in detectionStatus.notes" :key="index">{{ note }}</li>
        </ul>
      </div>
      <div class="banner-side">
        <div class="channel-pills" role="list" aria-label="模型通道状态">
          <span v-for="item in channelList" :key="item.key" role="listitem" :class="item.value.available ? 'up' : 'down'">
            <i aria-hidden="true" />{{ channelLabels[item.key] ?? item.key }}<em v-if="item.value.available && item.value.version" class="mono">{{ item.value.version }}</em><em v-else>未加载</em>
          </span>
        </div>
        <button class="icon-button" aria-label="刷新在线检测状态" title="刷新在线检测状态" @click="() => refreshDetectionStatus()"><RefreshCw :size="13" :class="{ spin: detectionStatusLoading }" /></button>
      </div>
    </section>
    <section v-else-if="detectionStatusLoading" class="detection-banner surface-panel pending" aria-label="在线检测状态">
      <Radar :size="18" aria-hidden="true" /><div class="banner-copy"><b>在线检测</b><p>正在读取在线检测状态…</p></div>
    </section>
    <section v-else-if="detectionStatusError" class="detection-banner surface-panel error" role="alert" aria-label="在线检测状态加载失败">
      <Radar :size="18" aria-hidden="true" /><div class="banner-copy"><b>在线检测</b><p>状态不可用：{{ detectionStatusError.message }}。真实后端模式下将展示模型通道与告警开关状态。</p></div>
      <div class="banner-side"><button class="icon-button" aria-label="重试加载在线检测状态" title="重试" @click="() => refreshDetectionStatus()"><RefreshCw :size="13" /></button></div>
    </section>

    <section v-if="data" class="metric-strip" aria-label="采集平面摘要">
      <div><span>已登记探针</span><b class="mono">{{ data.summary.total }}</b><small>具备独立节点身份</small></div>
      <div><span>在线 / 降级</span><b class="mono good">{{ data.summary.online }} / {{ data.summary.degraded }}</b><small>120 秒内视为在线</small></div>
      <div><span>离线 / 维护</span><b class="mono" :class="{ danger: data.summary.offline }">{{ data.summary.offline }} / {{ data.summary.maintenance }}</b><small>需排查或已计划变更</small></div>
      <div><span>累计 Flow / 告警</span><b class="mono">{{ formatNumber(data.summary.flows) }} / {{ formatNumber(data.summary.alerts) }}</b><small>来自已持久化记录</small></div>
      <div><span>采集就绪度</span><b class="mono" :class="readiness < 80 ? 'warning' : 'good'">{{ readiness }}%</b><small>在线节点按 100% 计</small></div>
    </section>

    <section class="toolbar surface-panel">
      <label><Search :size="14" /><input v-model="search" placeholder="探针 ID、名称或部署位置…"></label>
      <select v-model="state" aria-label="探针状态"><option value="all">全部状态</option><option value="online">在线</option><option value="degraded">降级</option><option value="offline">离线</option><option value="maintenance">维护中</option></select>
      <span>健康状态由最后上报时间计算，不接受前端伪造</span>
    </section>

    <LoadingState v-if="status === 'pending' && !data" :rows="8" label="正在读取探针注册表" />
    <ErrorState v-else-if="error" title="无法加载探针注册表" description="请确认 FastAPI 服务和数据库连接正常。" @retry="refresh" />
    <section v-else class="sensor-layout">
      <div class="registry surface-panel">
        <header><div><h2>采集节点注册表</h2><p>{{ filtered.length }} 个当前结果 · 单击节点查看采集质量</p></div><ServerCog :size="17" /></header>
        <EmptyState v-if="!filtered.length" title="没有匹配的探针" description="调整名称或状态筛选条件。" />
        <div v-else class="table-wrap"><table><thead><tr><th>状态</th><th>探针</th><th>部署位置</th><th>最后上报</th><th>Flow / 告警</th><th>拒绝事件</th><th>版本</th></tr></thead><tbody>
          <tr v-for="row in filtered" :key="row.id" :class="{ selected: selected?.id === row.id }" tabindex="0" @click="selectSensor(row)" @keydown.enter="selectSensor(row)">
            <td><span :class="['state', row.state]"><i />{{ stateLabels[row.state] }}</span></td><td><b>{{ row.name }}</b><small class="mono">{{ row.id }}</small></td><td>{{ row.location || '未登记' }}</td><td><span class="mono">{{ formatTime(row.lastSeenAt) }}</span><small>{{ row.healthReason }}</small></td><td class="mono">{{ formatNumber(row.flowCount) }} / {{ formatNumber(row.alertCount) }}</td><td><b class="mono" :class="{ warning: row.rejectedEvents }">{{ formatNumber(row.rejectedEvents) }}</b></td><td class="mono subtle">{{ row.version || '未知' }}</td>
          </tr>
        </tbody></table></div>
      </div>

      <aside class="sensor-side">
        <section v-if="selected" class="detail surface-panel">
          <header><div><h2>{{ selected.name }}</h2><p class="mono">{{ selected.id }}</p></div><span :class="['state', selected.state]"><i />{{ stateLabels[selected.state] }}</span></header>
          <div v-if="selected.lastError" class="health-alert"><AlertTriangle :size="14" /><span><b>需要处理</b>{{ selected.lastError }}</span></div>
          <dl><div><dt>健康判断</dt><dd>{{ selected.healthReason }}</dd></div><div><dt>部署位置</dt><dd><MapPin :size="12" />{{ selected.location || '未登记' }}</dd></div><div><dt>采集来源</dt><dd class="mono">{{ selected.ingestSource }}</dd></div><div><dt>累计接收</dt><dd class="mono">{{ formatNumber(selected.acceptedEvents) }}</dd></div><div><dt>高危告警</dt><dd class="mono" :class="{ danger: selected.criticalAlerts }">{{ selected.criticalAlerts }}</dd></div><div><dt>注册时间</dt><dd class="mono">{{ formatTime(selected.createdAt) }}</dd></div></dl>
          <footer><ShieldCheck :size="13" /><span>维护模式和节点元数据修改必须经过管理员接口，并写入审计日志。</span></footer>
        </section>

        <section class="import-panel surface-panel">
          <header><div><h2>导入 EVE 事件</h2><p>用于离线回放、实验探针和验收数据</p></div><DatabaseZap :size="16" /></header>
          <label><span>目标探针 ID</span><input v-model="importSensorId" class="mono" maxlength="80"></label>
          <label class="file-control"><span>EVE JSON / NDJSON</span><input type="file" accept=".json,.ndjson,application/json" @change="onFile"><em><FileUp :size="14" />{{ importFile?.name || '选择本地文件' }}</em></label>
          <button :disabled="importing || !importFile" @click="importEve"><RefreshCw v-if="importing" :size="13" class="spin" /><FileUp v-else :size="13" />{{ importing ? '正在校验并导入…' : '校验并导入' }}</button>
          <p v-if="importMessage" :class="['import-result', importTone]" role="status"><ShieldCheck v-if="importTone === 'success'" :size="13" /><XCircle v-else :size="13" />{{ importMessage }}</p>
          <small>单次上限 10 MiB；服务端逐行拒绝错误记录并对重复 Flow/告警去重。</small>
        </section>
      </aside>
    </section>

    <section v-if="selected" class="telemetry-grid" aria-label="探针数据质量与批次台账">
      <div class="quality-panel surface-panel">
        <header>
          <div><h2>数据质量 · {{ selected.id }}</h2><p>{{ windowLabels[healthWindowSeconds] }} · 统计来自后端摄取台账，未测量项显示「未测量」</p></div>
          <div class="quality-actions">
            <label class="window-select"><span>窗口</span>
              <select v-model="healthWindowSeconds" aria-label="质量统计窗口">
                <option v-for="(label, seconds) in windowLabels" :key="seconds" :value="Number(seconds)">{{ label }}</option>
              </select>
            </label>
            <button class="page-button" :disabled="qualityStatus === 'pending'" @click="() => refreshQuality()"><RefreshCw :size="13" :class="{ spin: qualityStatus === 'pending' }" />刷新</button>
          </div>
        </header>

        <LoadingState v-if="qualityStatus === 'pending' && !qualityItem" :rows="4" label="正在读取数据质量台账" />
        <ErrorState v-else-if="qualityError" title="无法加载数据质量" description="真实后端模式下请确认 FastAPI 服务与窗口参数正常。" @retry="refreshQuality" />
        <div v-else-if="qualityItem" class="quality-body">
          <div class="quality-headline">
            <span :class="['state', qualityItem.state]"><i />{{ stateLabels[qualityItem.state] }}</span>
            <p>{{ qualityItem.healthReason }}</p>
          </div>
          <dl class="quality-facts">
            <div><dt>窗口内批次</dt><dd class="mono">{{ formatNumber(qualityItem.batches) }}</dd></div>
            <div><dt>接收事件</dt><dd class="mono">{{ formatNumber(qualityItem.eventsAccepted) }}</dd></div>
            <div><dt>重复事件</dt><dd class="mono">{{ formatNumber(qualityItem.eventsDuplicate) }}</dd></div>
            <div><dt>拒绝事件</dt><dd class="mono" :class="{ danger: qualityItem.eventsRejected }">{{ formatNumber(qualityItem.eventsRejected) }}</dd></div>
            <div><dt>积压深度</dt><dd class="mono" :class="{ warning: qualityItem.spoolDepth }">{{ formatNumber(qualityItem.spoolDepth) }}</dd></div>
            <div><dt>丢弃事件</dt><dd class="mono" :class="{ warning: qualityItem.droppedEvents }">{{ formatNumber(qualityItem.droppedEvents) }}</dd></div>
            <div><dt>期望上报间隔</dt><dd class="mono">{{ qualityItem.expectedIntervalSeconds }} s</dd></div>
            <div><dt>最近批次</dt><dd class="mono">{{ formatTs(qualityItem.lastBatchAt) }}</dd></div>
            <div><dt>最近事件</dt><dd class="mono">{{ formatTs(qualityItem.lastEventAt) }}</dd></div>
            <div><dt>最近心跳</dt><dd class="mono">{{ formatTs(qualityItem.lastHeartbeatAt) }}</dd></div>
          </dl>
          <div class="metric-grid">
            <div v-for="cell in metricViews" :key="cell.label" class="metric-cell">
              <span>{{ cell.label }}</span>
              <template v-if="cell.view.measured"><b class="mono">{{ cell.view.text }}</b><i>{{ cell.view.unit }}</i></template>
              <em v-else class="unmeasured">未测量</em>
              <small v-if="cell.view.note" :title="cell.view.note">{{ cell.view.note }}</small>
            </div>
          </div>
          <p class="quality-legend"><span class="legend-item"><span class="swatch measured" aria-hidden="true" />已实测（measured=true）</span><span class="legend-item"><span class="swatch unmeasured" aria-hidden="true" />未测量（measured=false，不代表数值 0）</span></p>
        </div>
        <div v-else class="quality-empty">
          <p><ShieldCheck :size="16" />{{ isMock ? '演示模式：数据质量台账仅真实后端提供。' : '该窗口内暂无质量统计（未测量）。' }}</p>
        </div>
      </div>

      <div class="ledger surface-panel">
        <header>
          <div><h2>摄取批次台账</h2><p>逐批接收、去重与拒绝结果 · 探针 {{ selected.id }}</p></div>
          <div class="quality-actions">
            <label class="window-select"><span>每页</span>
              <select v-model="batchPageSize" aria-label="批次每页条数" @change="batchPage = 1">
                <option :value="10">10</option><option :value="25">25</option><option :value="50">50</option>
              </select>
            </label>
            <button class="page-button" :disabled="batchesStatus === 'pending'" @click="() => refreshBatches()"><RefreshCw :size="13" :class="{ spin: batchesStatus === 'pending' }" />刷新</button>
          </div>
        </header>

        <LoadingState v-if="batchesStatus === 'pending' && !batchRows.length" :rows="5" label="正在读取批次台账" />
        <ErrorState v-else-if="batchesError" title="无法加载批次台账" description="真实后端模式下请确认探针存在且批次接口正常。" @retry="refreshBatches" />
        <EmptyState v-else-if="!batchRows.length" :title="isMock ? '演示模式：无批次数据' : '该探针暂无批次记录'" :description="isMock ? '批次台账由真实后端在接收 EVE 批次时逐条记录。' : '选择其他时间窗口或探针后再试。'" />
        <template v-else>
          <div class="table-wrap"><table class="ledger-table">
            <thead><tr><th>批次 / 摘要</th><th>接收时间</th><th>状态</th><th>载荷</th><th>事件总数</th><th>接收 / 重复 / 拒绝</th><th>产出 Flow / 告警</th><th>首末事件</th><th>时钟偏差</th></tr></thead>
            <tbody>
              <tr v-for="row in batchRows" :key="row.id">
                <td><b class="mono">{{ row.batchId }}</b><small class="mono">{{ row.contentSha256.slice(0, 12) }}… · {{ row.encoding }}</small></td>
                <td class="mono">{{ formatTime(row.receivedAt) }}</td>
                <td><span :class="['batch-status', row.status]">{{ batchStatusLabels[row.status] }}</span></td>
                <td class="mono">{{ formatBytes(row.payloadBytes) }}</td>
                <td class="mono">{{ formatNumber(row.eventCount) }}</td>
                <td class="mono"><b class="good">{{ formatNumber(row.acceptedCount) }}</b> / <b>{{ formatNumber(row.duplicateCount) }}</b> / <b :class="{ danger: row.rejectedCount }">{{ formatNumber(row.rejectedCount) }}</b></td>
                <td class="mono">{{ formatNumber(row.createdFlows) }} / {{ formatNumber(row.createdAlerts) }}</td>
                <td class="mono">{{ formatTs(row.firstEventAt) }}<small v-if="row.lastEventAt && row.firstEventAt && row.lastEventAt !== row.firstEventAt">→ {{ formatTs(row.lastEventAt) }}</small><small v-else-if="!row.firstEventAt">无事件时间</small></td>
                <td class="mono">{{ row.clockSkewSeconds === null ? '—' : `${row.clockSkewSeconds} s` }}</td>
              </tr>
            </tbody>
          </table></div>
          <footer class="pager">
            <span class="mono">第 {{ batchPage }} 页 · 共 {{ formatNumber(batchTotal) }} 条</span>
            <div>
              <button :disabled="!canPrevious" aria-label="上一页" @click="batchPage -= 1"><RefreshCw :size="12" class="flip" />上一页</button>
              <button :disabled="!canNext" aria-label="下一页" @click="batchPage += 1">下一页<RefreshCw :size="12" /></button>
            </div>
          </footer>
        </template>
      </div>
    </section>
  </div>
</template>

<style scoped>
.sensors-page{padding:20px 22px 28px}.page-button{display:flex;align-items:center;gap:5px;height:34px;padding:0 9px;border:1px solid var(--border-default);border-radius:8px;background:var(--surface-1);color:var(--text-secondary);font-size:13px;cursor:pointer}.page-button:disabled{opacity:.55}.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.icon-button{display:grid;place-items:center;width:28px;height:28px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-1);color:var(--text-tertiary);cursor:pointer}.icon-button:hover{color:var(--text-secondary)}
/* 在线检测状态横幅 */
.detection-banner{display:flex;gap:12px;align-items:flex-start;margin-bottom:12px;padding:10px 13px;border-left:3px solid var(--border-strong)}.detection-banner.mode-enabled{border-left-color:var(--status-success)}.detection-banner.mode-shadow{border-left-color:var(--status-warning)}.detection-banner.mode-disabled{border-left-color:var(--text-disabled)}.detection-banner.error{border-left-color:var(--status-error)}.detection-banner.pending{border-left-color:var(--border-default)}.detection-banner>svg{flex:0 0 auto;margin-top:1px;color:var(--accent-strong)}.detection-banner.mode-disabled>svg{color:var(--text-tertiary)}.banner-copy{min-width:0;flex:1}.banner-copy>b{display:flex;gap:6px;align-items:center;color:var(--text-tertiary);font-size:12px;letter-spacing:.06em;text-transform:uppercase}.banner-copy>b .demo-tag{padding:0 5px;border-radius:999px;background:var(--accent-muted);color:var(--accent-strong);font-size:11px;letter-spacing:0}.banner-copy>strong{display:block;margin-top:2px;color:var(--text-primary);font-size:14px}.detection-banner.mode-enabled .banner-copy>strong{color:var(--status-success)}.detection-banner.mode-shadow .banner-copy>strong{color:var(--status-warning)}.detection-banner.mode-disabled .banner-copy>strong{color:var(--text-tertiary)}.banner-copy>p{margin:3px 0 0;color:var(--text-tertiary);font-size:13px;line-height:1.5}.banner-notes{display:flex;flex-wrap:wrap;gap:4px 10px;margin:6px 0 0;padding:0;list-style:none}.banner-notes li{color:var(--text-secondary);font-size:12px}.banner-notes li::before{content:'· ';color:var(--text-tertiary)}.banner-side{display:flex;gap:8px;align-items:center}.channel-pills{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end}.channel-pills>span{display:inline-flex;gap:5px;align-items:center;padding:3px 7px;border:1px solid var(--border-subtle);border-radius:999px;color:var(--text-secondary);font-size:12px}.channel-pills>span i{width:6px;height:6px;border-radius:50%;background:var(--text-disabled)}.channel-pills>span.up i{background:var(--status-success)}.channel-pills>span.down i{background:var(--status-error)}.channel-pills>span em{color:var(--text-tertiary);font-style:normal}.channel-pills>span.up em{color:var(--text-secondary)}
/* 遥测区布局 */
.telemetry-grid{display:grid;grid-template-columns:minmax(340px,430px) minmax(0,1fr);gap:12px;margin-top:12px;align-items:start}.quality-panel,.ledger{overflow:hidden}.quality-panel>header,.ledger>header{display:flex;justify-content:space-between;gap:10px;align-items:center;min-height:50px;padding:8px 11px;border-bottom:1px solid var(--border-subtle)}.quality-panel>header h2,.ledger>header h2{margin:0;font-size:14px}.quality-panel>header p,.ledger>header p{margin:2px 0 0;color:var(--text-tertiary);font-size:12px}.quality-actions{display:flex;gap:6px;align-items:center}.window-select{display:flex;gap:5px;align-items:center;color:var(--text-tertiary);font-size:12px}.window-select select{height:28px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;padding:0 4px}
.quality-body{padding:10px 11px}.quality-headline{display:flex;gap:8px;align-items:center;padding:7px 9px;border-radius:8px;background:var(--surface-2);margin-bottom:8px}.quality-headline p{margin:0;color:var(--text-secondary);font-size:12px}.quality-facts{margin:0;display:grid;grid-template-columns:1fr 1fr;gap:0 10px}.quality-facts>div{display:flex;justify-content:space-between;gap:8px;min-height:26px;padding:4px 2px;border-bottom:1px dashed var(--border-subtle);font-size:12px}.quality-facts dt{color:var(--text-tertiary)}.quality-facts dd{margin:0;color:var(--text-secondary);text-align:right}.metric-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:7px;margin-top:10px}.metric-cell{position:relative;display:grid;grid-template-columns:1fr auto;gap:0 5px;padding:7px 9px;border:1px solid var(--border-subtle);border-radius:8px;background:var(--surface-2)}.metric-cell>span{grid-column:1/-1;color:var(--text-tertiary);font-size:12px}.metric-cell>b{margin-top:2px;color:var(--text-primary);font-size:16px;font-weight:650;overflow:hidden;text-overflow:ellipsis}.metric-cell>i{color:var(--text-tertiary);font-size:12px;font-style:normal;align-self:end;padding-bottom:3px;white-space:nowrap}.metric-cell>em.unmeasured{grid-column:1/-1;margin-top:3px;color:var(--text-tertiary);font-size:13px;font-style:normal}.metric-cell>small{grid-column:1/-1;margin-top:3px;overflow:hidden;color:var(--text-disabled);font-size:11px;line-height:1.4;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;white-space:normal}.quality-legend{display:flex;flex-wrap:wrap;gap:6px 12px;margin:10px 0 0;color:var(--text-tertiary);font-size:11px}.quality-legend .legend-item{display:inline-flex;align-items:center}.quality-legend .swatch{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:3px}.quality-legend .swatch.measured{background:var(--status-success)}.quality-legend .swatch.unmeasured{background:var(--text-disabled)}.quality-empty{display:grid;min-height:150px;place-items:center;color:var(--text-tertiary);font-size:13px;text-align:center}.quality-empty p{display:flex;gap:6px;align-items:center;margin:0}
/* 批次台账 */
.ledger-table{width:100%;min-width:1080px;border-collapse:collapse}.ledger th{height:30px;padding:0 8px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px;text-align:left}.ledger td{height:45px;padding:5px 8px;border-top:1px solid var(--border-subtle);color:var(--text-secondary);font-size:12px;white-space:nowrap}.ledger td b,.ledger td small{display:block}.ledger td small{margin-top:2px;color:var(--text-tertiary);font-size:11px}.batch-status{display:inline-block;padding:1px 6px;border-radius:4px;background:var(--surface-3);color:var(--text-secondary);font-size:12px}.batch-status.accepted{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.batch-status.partial{background:color-mix(in srgb,var(--status-warning) 12%,transparent);color:var(--status-warning)}.batch-status.rejected{background:color-mix(in srgb,var(--status-error) 12%,transparent);color:var(--status-error)}.pager{display:flex;justify-content:space-between;align-items:center;min-height:40px;padding:6px 10px;border-top:1px solid var(--border-subtle);color:var(--text-tertiary);font-size:12px}.pager>div{display:flex;gap:6px}.pager button{display:flex;gap:4px;align-items:center;height:26px;padding:0 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer}.pager button:disabled{opacity:.4;cursor:not-allowed}.pager .flip{transform:rotate(180deg)}
.good{color:var(--status-success)!important}.warning{color:var(--status-warning)!important}.danger{color:var(--status-error)!important}
.state{display:inline-flex;align-items:center;gap:5px;color:var(--text-secondary);font-size:12px}.state i{width:6px;height:6px;border-radius:50%;background:var(--text-tertiary)}.state.online{color:var(--status-success)}.state.online i{background:var(--status-success)}.state.degraded,.state.maintenance{color:var(--status-warning)}.state.degraded i,.state.maintenance i{background:var(--status-warning)}.state.offline{color:var(--status-error)}.state.offline i{background:var(--status-error)}
.metric-strip{display:grid;grid-template-columns:repeat(5,1fr);margin-bottom:12px;border-block:1px solid var(--border-default);background:var(--surface-1)}.metric-strip>div{min-width:0;padding:9px 12px;border-right:1px solid var(--border-subtle)}.metric-strip>div:last-child{border-right:0}.metric-strip span,.metric-strip b,.metric-strip small{display:block}.metric-strip span{color:var(--text-tertiary);font-size:12px}.metric-strip b{margin-top:2px;font-size:16px}.metric-strip small{margin-top:1px;overflow:hidden;color:var(--text-tertiary);font-size:12px;text-overflow:ellipsis;white-space:nowrap}
.toolbar{display:grid;grid-template-columns:minmax(240px,1fr) 130px auto;gap:8px;align-items:center;margin-bottom:10px;padding:8px}.toolbar label{position:relative}.toolbar label svg{position:absolute;top:8px;left:9px;color:var(--text-tertiary)}.toolbar input,.toolbar select{width:100%;height:31px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);font-size:12px}.toolbar input{padding:0 9px 0 29px}.toolbar select{padding:0 7px}.toolbar>span{color:var(--text-tertiary);font-size:12px;text-align:right}
.sensor-layout{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:12px}.registry{min-width:0;overflow:hidden}.registry>header,.detail>header,.import-panel>header{display:flex;justify-content:space-between;align-items:center;min-height:46px;padding:8px 11px;border-bottom:1px solid var(--border-subtle)}header h2,header p{margin:0}header h2{font-size:14px}header p{margin-top:2px;color:var(--text-tertiary);font-size:12px}.registry>header>svg,.import-panel>header>svg{color:var(--accent-strong)}.table-wrap{overflow-x:auto}.registry table{width:100%;min-width:870px;border-collapse:collapse}.registry th{height:30px;padding:0 8px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px;text-align:left}.registry td{height:47px;padding:5px 8px;border-top:1px solid var(--border-subtle);color:var(--text-secondary);font-size:12px;white-space:nowrap}.registry tbody tr{cursor:pointer}.registry tbody tr:hover,.registry tbody tr.selected{background:var(--surface-2)}.registry tbody tr.selected{box-shadow:inset 2px 0 var(--accent)}.registry td b,.registry td small{display:block}.registry td b{color:var(--text-primary);font-size:12px}.registry td small{margin-top:2px;color:var(--text-tertiary);font-size:12px}.subtle{color:var(--text-tertiary)!important}
.sensor-side{display:grid;align-content:start;gap:10px}.detail,.import-panel{overflow:hidden}.health-alert{display:flex;gap:7px;margin:10px;padding:8px;border-left:2px solid var(--status-warning);background:color-mix(in srgb,var(--status-warning) 8%,transparent);color:var(--status-warning)}.health-alert b,.health-alert span{display:block}.health-alert span{color:var(--text-secondary);font-size:12px}.health-alert b{margin-bottom:2px;color:var(--text-primary)}.detail dl{margin:0}.detail dl>div{display:grid;grid-template-columns:90px 1fr;gap:8px;min-height:34px;padding:7px 10px;border-bottom:1px solid var(--border-subtle)}.detail dt,.detail dd{font-size:12px}.detail dt{color:var(--text-tertiary)}.detail dd{display:flex;align-items:center;gap:4px;margin:0;color:var(--text-secondary);text-align:right;justify-content:flex-end}.detail footer{display:flex;gap:7px;padding:9px 10px;color:var(--status-success);background:var(--surface-2)}.detail footer span{color:var(--text-tertiary);font-size:12px}
.import-panel>label{display:block;margin:9px 10px}.import-panel label>span{display:block;margin-bottom:4px;color:var(--text-tertiary);font-size:12px}.import-panel label>input:not([type=file]){width:100%;height:31px;padding:0 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-primary);font-size:12px}.file-control input{position:absolute;width:1px;height:1px;opacity:0}.file-control em{display:flex;align-items:center;gap:5px;min-height:34px;padding:0 8px;border:1px dashed var(--border-strong);border-radius:6px;color:var(--text-secondary);font-size:12px;font-style:normal;cursor:pointer}.import-panel>button{display:flex;align-items:center;justify-content:center;gap:5px;width:calc(100% - 20px);height:31px;margin:0 10px;border:1px solid color-mix(in srgb,var(--accent) 50%,var(--border-default));border-radius:6px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px;cursor:pointer}.import-panel>button:disabled{opacity:.5}.import-panel>small{display:block;padding:9px 10px;color:var(--text-tertiary);font-size:12px}.import-result{display:flex;gap:5px;margin:8px 10px 0;padding:7px;border-radius:5px;background:color-mix(in srgb,var(--status-success) 8%,transparent);color:var(--status-success);font-size:12px}.import-result.error{background:color-mix(in srgb,var(--status-error) 8%,transparent);color:var(--status-error)}
@media(max-width:1280px){.telemetry-grid{grid-template-columns:1fr}.quality-panel{max-width:560px}}
@media(max-width:1100px){.metric-strip{grid-template-columns:repeat(3,1fr)}.sensor-layout{grid-template-columns:1fr}.sensor-side{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.sensors-page{padding:16px 12px 24px}.metric-strip{grid-template-columns:1fr 1fr}.toolbar{grid-template-columns:1fr 120px}.toolbar>span{grid-column:1/-1;text-align:left}.sensor-side{grid-template-columns:1fr}.detection-banner{flex-direction:column}.banner-side{justify-content:flex-start}.quality-panel>header,.ledger>header{flex-direction:column;align-items:flex-start}.quality-facts{grid-template-columns:1fr}}
</style>
