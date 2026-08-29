<script setup lang="ts">
import { keepPreviousData, useQuery } from '@tanstack/vue-query'
import { createColumnHelper, getCoreRowModel, useVueTable, type SortingState, type VisibilityState } from '@tanstack/vue-table'
import { Download, Play, Search, SlidersHorizontal } from '~/utils/icons'
import { agentAnalysisSchema, alertDetailSchema, alertsResponseSchema } from '~~/shared/schemas/security'
import { DETECTION_CATEGORIES, type Alert } from '~~/shared/types/security'
import { downloadCsv } from '~/utils/export'

const filters = reactive({ severity: 'all', status: 'all', category: 'all' })
const search = ref('')
const debouncedSearch = refDebounced(search, 260)
const page = ref(1)
const pageSize = ref(25)
const sorting = ref<SortingState>([{ id: 'riskScore', desc: true }])
const columnVisibility = ref<VisibilityState>({})
const columnDrawerOpen = ref(false)
const toastOpen = ref(false)
const batchRunning = ref(false)
const batchProgress = ref({ completed: 0, total: 0, failed: 0 })
const router = useRouter()
const toast = reactive({ title: '', description: '', tone: 'success' as 'success' | 'error' | 'info' })

const columnHelper = createColumnHelper<Alert>()
const columns = [
  columnHelper.display({ id: 'expand', header: '', enableSorting: false, enableHiding: false }),
  columnHelper.accessor('severity', { header: '等级', enableHiding: false }),
  columnHelper.accessor('timestamp', { header: '时间' }),
  columnHelper.accessor('title', { header: '告警与检测器', enableHiding: false }),
  columnHelper.accessor('sourceIp', { header: '源地址' }),
  columnHelper.accessor('destinationIp', { header: '目的地址' }),
  columnHelper.accessor('category', { header: '攻击类型' }),
  columnHelper.accessor('agentDecision', { header: 'Agent 结论' }),
  columnHelper.accessor('riskScore', { header: '风险' }),
  columnHelper.accessor('status', { header: '状态' }),
  columnHelper.accessor('owner', { header: '负责人' }),
]

const activeSort = computed(() => sorting.value[0] || { id: 'riskScore', desc: true })
const alertsQuery = useQuery({
  queryKey: computed(() => [
    'alerts',
    filters.severity,
    filters.status,
    filters.category,
    debouncedSearch.value,
    page.value,
    pageSize.value,
    activeSort.value.id,
    activeSort.value.desc,
  ]),
  queryFn: () => validatedFetch('/alerts', alertsResponseSchema, {
    query: {
      severity: filters.severity,
      status: filters.status,
      category: filters.category,
      search: debouncedSearch.value,
      page: page.value,
      pageSize: pageSize.value,
      sortBy: activeSort.value.id,
      sortDir: activeSort.value.desc ? 'desc' : 'asc',
    },
  }),
  placeholderData: keepPreviousData,
})

const rows = computed(() => alertsQuery.data.value?.items ?? [])
const total = computed(() => alertsQuery.data.value?.total ?? 0)
const agentCompleted = computed(() => alertsQuery.data.value?.agentCompleted ?? 0)
const agentPending = computed(() => alertsQuery.data.value?.agentPending ?? 0)
const agentDecisions = computed(() => alertsQuery.data.value?.agentDecisions ?? {})
const table = useVueTable({
  get data() { return rows.value },
  columns,
  getRowId: (row) => row.id,
  state: {
    get sorting() { return sorting.value },
    get columnVisibility() { return columnVisibility.value },
  },
  onSortingChange: (updater) => {
    sorting.value = typeof updater === 'function' ? updater(sorting.value) : updater
    page.value = 1
  },
  onColumnVisibilityChange: (updater) => {
    columnVisibility.value = typeof updater === 'function' ? updater(columnVisibility.value) : updater
  },
  manualSorting: true,
  getCoreRowModel: getCoreRowModel(),
})

const statusLabels: Record<string, string> = { new: '待研判', investigating: '调查中', contained: '已遏制', closed: '已关闭' }
const agentDecisionLabels: Record<string, string> = { known_match: '已知攻击', new_pattern: '新模式', rule_variant: '规则变体', benign: '正常排除' }
const categoryOptions = DETECTION_CATEGORIES
const dirty = computed(() => filters.severity !== 'all' || filters.status !== 'all' || filters.category !== 'all' || Boolean(search.value))
const columnWidths = {
  expand: '42px', severity: '70px', timestamp: '88px', title: 'minmax(260px, 1.7fr)', sourceIp: '140px',
  destinationIp: '160px', category: '132px', agentDecision: '108px', riskScore: '68px', status: '104px', owner: '88px',
}

watch([() => filters.severity, () => filters.status, () => filters.category, debouncedSearch], () => { page.value = 1 })

function resetFilters() {
  filters.severity = 'all'
  filters.status = 'all'
  filters.category = 'all'
  search.value = ''
  page.value = 1
}

function setPageSize(value: number) {
  pageSize.value = value
  page.value = 1
}

function openAlert(row: Alert) {
  return router.push(`/alerts/${row.id}`)
}

function showToast(title: string, description: string, tone: 'success' | 'error' | 'info' = 'success') {
  toast.title = title
  toast.description = description
  toast.tone = tone
  toastOpen.value = true
}

function exportCsv() {
  if (!rows.value.length) {
    showToast('没有可导出的告警', '请先调整筛选条件。', 'info')
    return
  }

  const visible = new Set(table.getVisibleLeafColumns().map((column) => column.id))
  const fields = [
    { id: 'severity', label: '等级', value: (row: Alert) => row.severity },
    { id: 'timestamp', label: '时间', value: (row: Alert) => row.timestamp },
    { id: 'title', label: '告警', value: (row: Alert) => row.title },
    { id: 'sourceIp', label: '源地址', value: (row: Alert) => row.sourceIp },
    { id: 'destinationIp', label: '目的地址', value: (row: Alert) => `${row.destinationIp}:${row.destinationPort}` },
    { id: 'category', label: '攻击类型', value: (row: Alert) => row.category },
    { id: 'agentDecision', label: 'Agent 结论', value: (row: Alert) => row.agentDecision ? agentDecisionLabels[row.agentDecision] : '未研判' },
    { id: 'riskScore', label: '风险', value: (row: Alert) => row.riskScore },
    { id: 'status', label: '状态', value: (row: Alert) => statusLabels[row.status] },
    { id: 'owner', label: '负责人', value: (row: Alert) => row.owner || '未分派' },
  ].filter((field) => visible.has(field.id))
  downloadCsv(
    `evonids-alerts-page-${page.value}.csv`,
    fields.map((field) => field.label),
    rows.value.map((row) => fields.map((field) => field.value(row))),
  )
  showToast('告警视图已导出', `已导出当前页 ${rows.value.length} 条记录，并遵循当前列显隐设置。`)
}

async function runPendingAgents() {
  if (batchRunning.value) return
  batchRunning.value = true
  batchProgress.value = { completed: 0, total: 0, failed: 0 }
  try {
    const queue: Alert[] = []
    let queuePage = 1
    let queueTotal = 0
    do {
      const payload = await validatedFetch('/alerts', alertsResponseSchema, {
        query: { page: queuePage, pageSize: 100, sortBy: 'riskScore', sortDir: 'desc' },
      })
      queue.push(...payload.items)
      queueTotal = payload.total
      queuePage += 1
    } while (queue.length < queueTotal)

    const pending = queue.filter((item) => item.agentState !== 'completed')
    batchProgress.value.total = pending.length
    if (!pending.length) {
      showToast('Agent 研判已完整', '当前队列没有尚未研判的告警。', 'info')
      return
    }

    for (const alert of pending) {
      try {
        const detail = await validatedFetch(`/alerts/${alert.id}`, alertDetailSchema)
        await validatedFetch('/agent/analyze', agentAnalysisSchema, {
          method: 'POST',
          body: { alertId: alert.id, profile: detail.profile },
        })
      } catch {
        batchProgress.value.failed += 1
      } finally {
        batchProgress.value.completed += 1
      }
    }
    await alertsQuery.refetch()
    showToast(
      'Agent 批量研判完成',
      `处理 ${batchProgress.value.completed} 条，失败 ${batchProgress.value.failed} 条；成功结果已持久化并进入审计日志。`,
      batchProgress.value.failed ? 'error' : 'success',
    )
  } finally {
    batchRunning.value = false
  }
}
</script>

<template>
  <div class="alerts-page">
    <Breadcrumb :items="[{ label: '安全运营', to: '/overview' }, { label: '告警研判' }]" />
    <PageHeader eyebrow="Detection Queue" title="告警研判" description="按风险、模型证据一致性与处置时效管理检测结果">
      <UiButton :disabled="batchRunning || agentPending === 0" @click="runPendingAgents"><Play :size="14" aria-hidden="true" />{{ batchRunning ? `研判中 ${batchProgress.completed}/${batchProgress.total}` : agentPending ? `研判全部未完成（${agentPending}）` : 'Agent 已全部完成' }}</UiButton>
      <UiButton @click="exportCsv"><Download :size="14" aria-hidden="true" />导出当前视图</UiButton>
    </PageHeader>

    <section class="queue-summary" aria-label="告警队列摘要">
      <div><span>当前队列</span><b class="mono">{{ total }}</b></div>
      <div><span>Agent 已完成</span><b class="mono success">{{ agentCompleted }} / {{ total }}</b></div>
      <div><span>新模式</span><b class="mono info">{{ agentDecisions.new_pattern || 0 }}</b></div>
      <div><span>正常排除</span><b class="mono">{{ agentDecisions.benign || 0 }}</b></div>
      <p><span v-if="alertsQuery.isFetching.value" class="query-state">正在刷新 · </span>模型先检出 · Agent 再研判 · 待处理 <span class="mono">{{ agentPending }}</span></p>
    </section>

    <FilterBar label="告警筛选" :dirty="dirty" @reset="resetFilters">
      <label class="field search-field"><span>搜索</span><span class="input-wrap"><Search :size="14" aria-hidden="true" /><input v-model="search" type="search" placeholder="告警 ID、IP、标题…" aria-label="搜索告警"></span></label>
      <label class="field"><span>危险等级</span><select v-model="filters.severity"><option value="all">全部等级</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="info">信息</option></select></label>
      <label class="field"><span>处置状态</span><select v-model="filters.status"><option value="all">全部状态</option><option value="new">待研判</option><option value="investigating">调查中</option><option value="contained">已遏制</option><option value="closed">已关闭</option></select></label>
      <label class="field"><span>检测类别</span><select v-model="filters.category"><option value="all">全部重点类别</option><option v-for="category in categoryOptions" :key="category" :value="category">{{ category }}</option></select></label>
      <template #actions><UiButton size="compact" @click="columnDrawerOpen = true"><SlidersHorizontal :size="13" aria-hidden="true" />列设置</UiButton></template>
    </FilterBar>

    <DataTable
      :table="table"
      label="告警研判数据表"
      :loading="alertsQuery.isPending.value"
      :error="alertsQuery.isError.value"
      :total="total"
      :page="page"
      :page-size="pageSize"
      :height="458"
      :min-width="1288"
      :column-widths="columnWidths"
      :fixed-columns="[{ id: 'expand', left: 0 }, { id: 'severity', left: 42 }, { id: 'title', left: 112 }]"
      :row-label="(row: Alert) => `打开告警 ${row.id}：${row.title}`"
      :evidence="(row: Alert) => row.evidence"
      empty-description="当前筛选条件没有匹配的安全告警。"
      @retry="alertsQuery.refetch()"
      @row-activate="openAlert"
      @update:page="page = $event"
      @update:page-size="setPageSize"
    >
      <template #cell-severity="{ row }"><SeverityBadge :level="row.severity" /></template>
      <template #cell-timestamp="{ row }"><span class="mono subtle">{{ formatTimestamp(row.timestamp) }}</span></template>
      <template #cell-title="{ row }"><span class="alert-title"><b>{{ row.title }}</b><small><code>{{ row.id }}</code> · {{ row.detector }}</small></span></template>
      <template #cell-sourceIp="{ row }"><span class="mono">{{ row.sourceIp }}</span></template>
      <template #cell-destinationIp="{ row }"><span class="mono">{{ row.destinationIp }}<small>:{{ row.destinationPort }}</small></span></template>
      <template #cell-category="{ row }"><span class="category">{{ row.category }}</span></template>
      <template #cell-agentDecision="{ row }"><span :class="['agent-decision', row.agentDecision || 'not_run']">{{ row.agentDecision ? agentDecisionLabels[row.agentDecision] : '未研判' }}</span></template>
      <template #cell-riskScore="{ row }"><RiskScore :value="row.riskScore" :severity="row.severity" compact /></template>
      <template #cell-status="{ row }"><StatusIndicator :status="row.status" :label="statusLabels[row.status]" /></template>
      <template #cell-owner="{ row }">{{ row.owner || '未分派' }}</template>
    </DataTable>

    <DetailDrawer v-model:open="columnDrawerOpen" title="告警表格列设置" description="选择当前工作台需要显示的字段；关键研判列保持固定。">
      <section class="drawer-section"><h2>固定列</h2><p>等级与告警名称固定在左侧，横向浏览时保持上下文。</p><div class="pinned-list"><span>等级</span><span>告警与检测器</span></div></section>
      <section class="drawer-section"><h2>可见列</h2><label v-for="column in table.getAllLeafColumns().filter((item) => item.getCanHide())" :key="column.id" class="column-option"><input type="checkbox" :checked="column.getIsVisible()" @change="column.toggleVisibility(($event.target as HTMLInputElement).checked)"><span>{{ String(column.columnDef.header || column.id) }}</span></label></section>
    </DetailDrawer>
    <Toast v-model:open="toastOpen" :title="toast.title" :description="toast.description" :tone="toast.tone" />
  </div>
</template>

<style scoped>
.alerts-page { padding: 14px 22px 28px; }
.queue-summary { display: grid; grid-template-columns: repeat(4, minmax(120px, auto)) 1fr; align-items: center; min-height: 57px; margin-bottom: 12px; border-block: 1px solid var(--border-default); background: var(--surface-1); }.queue-summary > div { padding: 7px 14px; border-right: 1px solid var(--border-subtle); }.queue-summary span, .queue-summary b { display: block; }.queue-summary span { color: var(--text-tertiary); font-size:13px; }.queue-summary b { margin-top: 1px; font-size: 17px; }.queue-summary b.success { color: var(--status-success); }.queue-summary b.info { color: var(--accent-strong); }.queue-summary p { justify-self: end; margin: 0; padding: 0 14px; color: var(--text-tertiary); font-size:13px; }.queue-summary p span { display: inline; }.query-state { color: var(--accent-strong) !important; }
.field { min-width: 0; }.field > span:first-child { display: block; margin: 0 0 3px 2px; color: var(--text-tertiary); font-size:13px; }.field select, .field input { width: 100%; height: 32px; border: 1px solid var(--border-default); border-radius: 6px; background: var(--surface-2); color: var(--text-secondary); font-size:13px; }.field select { padding: 0 7px; }.input-wrap { position: relative; display: block; }.input-wrap svg { position: absolute; top: 9px; left: 9px; color: var(--text-tertiary); }.input-wrap input { padding: 0 9px 0 31px; }
.alert-title { display: block; min-width: 0; overflow: hidden; }.alert-title b, .alert-title small { display: block; overflow: hidden; text-overflow: ellipsis; }.alert-title b { color: var(--text-primary); font-size:14px; font-weight: 600; }.alert-title small { margin-top: 2px; color: var(--text-tertiary); font-size:13px; }.subtle { color: var(--text-tertiary); }.category { overflow: hidden; padding: 2px 5px; border: 1px solid var(--border-subtle); border-radius: 4px; background: var(--surface-2); text-overflow: ellipsis; }
.agent-decision{display:inline-flex;align-items:center;padding:2px 6px;border-radius:4px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px}.agent-decision.known_match{background:color-mix(in srgb,var(--status-success) 9%,transparent);color:var(--status-success)}.agent-decision.new_pattern,.agent-decision.rule_variant{background:color-mix(in srgb,var(--status-warning) 9%,transparent);color:var(--status-warning)}.agent-decision.benign{color:var(--accent-strong)}
.drawer-section { padding: 4px 0 15px; border-bottom: 1px solid var(--border-subtle); }.drawer-section + .drawer-section { padding-top: 14px; }.drawer-section h2 { margin: 0; font-size: 12px; }.drawer-section p { margin: 3px 0 10px; color: var(--text-tertiary); font-size:13px; }.pinned-list { display: flex; gap: 6px; }.pinned-list span { padding: 4px 7px; border: 1px solid color-mix(in srgb, var(--accent) 32%, var(--border-default)); border-radius: 5px; background: var(--accent-muted); color: var(--accent-strong); font-size:13px; }.column-option { display: flex; align-items: center; gap: 8px; min-height: 38px; border-bottom: 1px solid var(--border-subtle); color: var(--text-secondary); font-size:14px; cursor: pointer; }.column-option input { accent-color: var(--accent); }
@media (max-width: 1000px) { .queue-summary { grid-template-columns: repeat(4, 1fr); }.queue-summary p { display: none; } }
@media (max-width: 650px) { .alerts-page { padding: 12px 12px 24px; }.queue-summary { grid-template-columns: 1fr 1fr; }.queue-summary > div { min-width: 0; } }
</style>
