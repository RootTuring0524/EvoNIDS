<script setup lang="ts">
import { AlertTriangle, DatabaseZap, FileUp, MapPin, RefreshCw, Search, ServerCog, ShieldCheck, XCircle } from '~/utils/icons'
import { eveIngestionResponseSchema, sensorsResponseSchema } from '~~/shared/schemas/security'
import type { SensorRecord, SensorState } from '~~/shared/types/security'

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
</script>

<template>
  <div class="sensors-page">
    <PageHeader eyebrow="Collection Plane" title="探针与数据源" description="管理 Suricata 采集节点、上报健康度与 EVE 数据质量">
      <button class="page-button" :disabled="status === 'pending'" @click="() => refresh()"><RefreshCw :size="14" :class="{ spin: status === 'pending' }" />刷新状态</button>
    </PageHeader>

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
  </div>
</template>

<style scoped>
.sensors-page{padding:20px 22px 28px}.page-button{display:flex;align-items:center;gap:5px;height:34px;padding:0 9px;border:1px solid var(--border-default);border-radius:8px;background:var(--surface-1);color:var(--text-secondary);font-size:13px;cursor:pointer}.page-button:disabled{opacity:.55}.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.metric-strip{display:grid;grid-template-columns:repeat(5,1fr);margin-bottom:12px;border-block:1px solid var(--border-default);background:var(--surface-1)}.metric-strip>div{min-width:0;padding:9px 12px;border-right:1px solid var(--border-subtle)}.metric-strip>div:last-child{border-right:0}.metric-strip span,.metric-strip b,.metric-strip small{display:block}.metric-strip span{color:var(--text-tertiary);font-size:12px}.metric-strip b{margin-top:2px;font-size:16px}.metric-strip small{margin-top:1px;overflow:hidden;color:var(--text-tertiary);font-size:12px;text-overflow:ellipsis;white-space:nowrap}.good{color:var(--status-success)!important}.warning{color:var(--status-warning)!important}.danger{color:var(--status-error)!important}
.toolbar{display:grid;grid-template-columns:minmax(240px,1fr) 130px auto;gap:8px;align-items:center;margin-bottom:10px;padding:8px}.toolbar label{position:relative}.toolbar label svg{position:absolute;top:8px;left:9px;color:var(--text-tertiary)}.toolbar input,.toolbar select{width:100%;height:31px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);font-size:12px}.toolbar input{padding:0 9px 0 29px}.toolbar select{padding:0 7px}.toolbar>span{color:var(--text-tertiary);font-size:12px;text-align:right}
.sensor-layout{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:12px}.registry{min-width:0;overflow:hidden}.registry>header,.detail>header,.import-panel>header{display:flex;justify-content:space-between;align-items:center;min-height:46px;padding:8px 11px;border-bottom:1px solid var(--border-subtle)}header h2,header p{margin:0}header h2{font-size:14px}header p{margin-top:2px;color:var(--text-tertiary);font-size:12px}.registry>header>svg,.import-panel>header>svg{color:var(--accent-strong)}.table-wrap{overflow-x:auto}.registry table{width:100%;min-width:870px;border-collapse:collapse}.registry th{height:30px;padding:0 8px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px;text-align:left}.registry td{height:47px;padding:5px 8px;border-top:1px solid var(--border-subtle);color:var(--text-secondary);font-size:12px;white-space:nowrap}.registry tbody tr{cursor:pointer}.registry tbody tr:hover,.registry tbody tr.selected{background:var(--surface-2)}.registry tbody tr.selected{box-shadow:inset 2px 0 var(--accent)}.registry td b,.registry td small{display:block}.registry td b{color:var(--text-primary);font-size:12px}.registry td small{margin-top:2px;color:var(--text-tertiary);font-size:12px}.subtle{color:var(--text-tertiary)!important}
.state{display:inline-flex;align-items:center;gap:5px;color:var(--text-secondary);font-size:12px}.state i{width:6px;height:6px;border-radius:50%;background:var(--text-tertiary)}.state.online{color:var(--status-success)}.state.online i{background:var(--status-success)}.state.degraded,.state.maintenance{color:var(--status-warning)}.state.degraded i,.state.maintenance i{background:var(--status-warning)}.state.offline{color:var(--status-error)}.state.offline i{background:var(--status-error)}
.sensor-side{display:grid;align-content:start;gap:10px}.detail,.import-panel{overflow:hidden}.health-alert{display:flex;gap:7px;margin:10px;padding:8px;border-left:2px solid var(--status-warning);background:color-mix(in srgb,var(--status-warning) 8%,transparent);color:var(--status-warning)}.health-alert b,.health-alert span{display:block}.health-alert span{color:var(--text-secondary);font-size:12px}.health-alert b{margin-bottom:2px;color:var(--text-primary)}.detail dl{margin:0}.detail dl>div{display:grid;grid-template-columns:90px 1fr;gap:8px;min-height:34px;padding:7px 10px;border-bottom:1px solid var(--border-subtle)}.detail dt,.detail dd{font-size:12px}.detail dt{color:var(--text-tertiary)}.detail dd{display:flex;align-items:center;gap:4px;margin:0;color:var(--text-secondary);text-align:right;justify-content:flex-end}.detail footer{display:flex;gap:7px;padding:9px 10px;color:var(--status-success);background:var(--surface-2)}.detail footer span{color:var(--text-tertiary);font-size:12px}
.import-panel>label{display:block;margin:9px 10px}.import-panel label>span{display:block;margin-bottom:4px;color:var(--text-tertiary);font-size:12px}.import-panel label>input:not([type=file]){width:100%;height:31px;padding:0 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-primary);font-size:12px}.file-control input{position:absolute;width:1px;height:1px;opacity:0}.file-control em{display:flex;align-items:center;gap:5px;min-height:34px;padding:0 8px;border:1px dashed var(--border-strong);border-radius:6px;color:var(--text-secondary);font-size:12px;font-style:normal;cursor:pointer}.import-panel>button{display:flex;align-items:center;justify-content:center;gap:5px;width:calc(100% - 20px);height:31px;margin:0 10px;border:1px solid color-mix(in srgb,var(--accent) 50%,var(--border-default));border-radius:6px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px;cursor:pointer}.import-panel>button:disabled{opacity:.5}.import-panel>small{display:block;padding:9px 10px;color:var(--text-tertiary);font-size:12px}.import-result{display:flex;gap:5px;margin:8px 10px 0;padding:7px;border-radius:5px;background:color-mix(in srgb,var(--status-success) 8%,transparent);color:var(--status-success);font-size:12px}.import-result.error{background:color-mix(in srgb,var(--status-error) 8%,transparent);color:var(--status-error)}
@media(max-width:1100px){.metric-strip{grid-template-columns:repeat(3,1fr)}.sensor-layout{grid-template-columns:1fr}.sensor-side{grid-template-columns:1fr 1fr}}@media(max-width:700px){.sensors-page{padding:16px 12px 24px}.metric-strip{grid-template-columns:1fr 1fr}.toolbar{grid-template-columns:1fr 120px}.toolbar>span{grid-column:1/-1;text-align:left}.sensor-side{grid-template-columns:1fr}}
</style>
