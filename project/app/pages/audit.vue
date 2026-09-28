<script setup lang="ts">
import { Download, FolderKanban, Search, ShieldCheck, X } from '~/utils/icons'
import {
  auditEventsResponseSchema,
  caseIdSchema,
  type AuditEventsApiResponse,
} from '~~/shared/schemas/security'
import { downloadCsv } from '~/utils/export'

const route = useRoute()
const router = useRouter()
const search = ref('')
const objectType = ref('all')
const outcome = ref('all')
const page = ref(1)
const pageSize = ref(100)
const exportMessage = ref('')
// The committed case filter is reflected in the URL (?caseId=CASE-…); the draft
// holds whatever the analyst is typing in the toolbar.
const caseId = ref('')
const caseDraft = ref('')
const caseError = ref('')

function normalizeCaseId(value: unknown): string {
  return typeof value === 'string' ? value.trim().toUpperCase() : ''
}

function isCaseId(value: string): boolean {
  return caseIdSchema.safeParse(value).success
}

function syncCaseFromUrl(value: unknown) {
  const previous = caseId.value
  const raw = normalizeCaseId(value)
  if (!raw) {
    caseId.value = ''
    caseDraft.value = ''
    caseError.value = ''
    if (previous) page.value = 1
    return
  }
  if (isCaseId(raw)) {
    caseId.value = raw
    caseDraft.value = raw
    caseError.value = ''
    if (raw !== previous) page.value = 1
  } else {
    // Malformed deep link: keep the filter off and explain the expected format.
    caseId.value = ''
    caseDraft.value = raw
    caseError.value = '案件编号格式应为 CASE- 后跟 12 位大写十六进制字符'
    if (previous) page.value = 1
  }
}

syncCaseFromUrl(route.query.caseId)
watch(() => route.query.caseId, syncCaseFromUrl)

function applyCaseFilter() {
  const raw = normalizeCaseId(caseDraft.value)
  if (!raw) {
    clearCaseFilter()
    return
  }
  if (!isCaseId(raw)) {
    caseError.value = '案件编号格式应为 CASE- 后跟 12 位大写十六进制字符'
    return
  }
  caseError.value = ''
  if (raw === caseId.value) {
    caseDraft.value = raw
    return
  }
  page.value = 1
  void router.replace({ query: { ...route.query, caseId: raw } })
}

function clearCaseFilter() {
  if (!rawDraft() && !caseId.value) {
    caseDraft.value = ''
    caseError.value = ''
    return
  }
  page.value = 1
  caseDraft.value = ''
  caseError.value = ''
  const nextQuery = { ...route.query }
  delete nextQuery.caseId
  void router.replace({ query: nextQuery })
}

function rawDraft(): string {
  return caseDraft.value.trim()
}

const query = computed(() => ({
  search: search.value.trim(),
  objectType: objectType.value,
  outcome: outcome.value,
  ...(caseId.value ? { caseId: caseId.value } : {}),
  page: page.value,
  pageSize: pageSize.value,
}))
const { data, status, error, refresh } = await useAsyncData(
  'audit-events',
  () => validatedFetch<AuditEventsApiResponse>('/audit', auditEventsResponseSchema, { query: query.value }),
  { watch: [query] },
)

watch([search, objectType, outcome, pageSize], () => { page.value = 1 })

// Guard against a stale page number after the result set shrinks below it.
watch([() => data.value?.total, pageSize], () => {
  const total = data.value?.total ?? 0
  if (total <= 0) return
  const lastPage = Math.max(1, Math.ceil(total / pageSize.value))
  if (page.value > lastPage) page.value = lastPage
})

function errorStatusCode(err: unknown): number {
  if (!err || typeof err !== 'object') return 0
  const candidate = err as { statusCode?: unknown; data?: { statusCode?: unknown } }
  const raw = candidate.statusCode ?? candidate.data?.statusCode
  return typeof raw === 'number' ? raw : 0
}
const caseNotFound = computed(() => errorStatusCode(error.value) === 404 && Boolean(caseId.value))
const isMockMode = computed(() => Boolean(useRuntimeConfig().public.useMockApi))
const emptyTitle = computed(() => (caseId.value ? '该案件暂无审计事件' : '没有匹配的审计记录'))
const emptyDescription = computed(() => {
  if (caseId.value) {
    return isMockMode.value
      ? '演示模式不提供案件审计事件，连接真实后端后可查看。'
      : `未找到编号 ${caseId.value} 匹配的审计事件，可调整其他筛选条件或更换案件编号。`
  }
  return '调整操作人、对象或结果筛选条件后重试。'
})
const errorTitle = computed(() => (caseNotFound.value ? '案件不存在' : '审计日志加载失败'))
const errorDescription = computed(() =>
  caseNotFound.value
    ? `未找到编号 ${caseId.value} 的案件。请检查案件编号，或在工具栏清除案件筛选后重试。`
    : undefined,
)
const canGoNext = computed(() => (data.value?.total ?? 0) > page.value * pageSize.value)

const actionLabels: Record<string, string> = {
  'alert.created': '创建告警',
  'alert.update': '更新告警处置',
  'rule.candidate': '创建候选规则',
  'rule.validating': '启动规则回放',
  'rule.validated': '规则验证通过',
  'rule.rejected': '规则验证失败',
  'rule.repaired': '创建修复版本',
  'rule.confirmed': '人工确认规则',
  'rule.deployed': '批准规则部署',
  'rule.deprecated': '废弃规则',
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(value))
}

function resultLabel(value: string) {
  return value === 'completed' ? '成功' : value === 'failed' ? '失败' : value
}

function exportAudit() {
  const items = data.value?.items ?? []
  downloadCsv(
    `evonids-audit-${new Date().toISOString().slice(0, 10)}.csv`,
    ['时间', '操作人', '操作', '对象类型', '对象 ID', '结果', 'Request ID', '备注'],
    items.map((item) => [
      item.createdAt,
      item.actor,
      actionLabels[item.action] || item.action,
      item.objectType,
      item.objectId,
      resultLabel(item.outcome),
      item.requestId || '',
      item.note || '',
    ]),
  )
  exportMessage.value = `已导出 ${items.length} 条审计记录`
  window.setTimeout(() => { exportMessage.value = '' }, 2400)
}
</script>

<template>
  <div class="audit-page">
    <PageHeader
      eyebrow="Audit Trail"
      title="审计日志"
      description="追踪告警处置、规则验证与人工审批；每次变更均关联对象、操作人和 Request ID。"
    >
      <button class="page-button" :disabled="status === 'pending' || !data?.items.length" @click="exportAudit">
        <Download :size="13" />导出当前结果
      </button>
    </PageHeader>

    <div v-if="exportMessage" class="export-message" role="status">
      <ShieldCheck :size="14" />{{ exportMessage }}
    </div>

    <section class="audit-summary">
      <div>
        <ShieldCheck :size="16" />
        <span>
          <b>操作链路可追踪</b>
          <small>当前查询返回 {{ data?.total ?? 0 }} 条记录{{ caseId ? ` · 案件 ${caseId}` : '' }} · 时区 Asia/Shanghai</small>
        </span>
      </div>
      <p>审计事件由 FastAPI 事务同步写入；生产环境仍需接入不可变日志存储和保留策略。</p>
    </section>

    <section class="audit-toolbar surface-panel" aria-label="审计筛选">
      <label>
        <Search :size="14" />
        <input v-model="search" placeholder="操作人、对象 ID、Request ID…">
      </label>
      <select v-model="objectType" aria-label="对象类型">
        <option value="all">全部对象</option>
        <option value="rule">规则</option>
        <option value="alert">告警</option>
        <option value="case">案件</option>
      </select>
      <select v-model="outcome" aria-label="执行结果">
        <option value="all">全部结果</option>
        <option value="completed">成功</option>
        <option value="failed">失败</option>
      </select>
      <div class="case-filter" role="group" aria-label="按案件筛选">
        <FolderKanban :size="14" />
        <input
          v-model="caseDraft"
          placeholder="案件编号 CASE-…"
          aria-label="案件编号"
          @keydown.enter="applyCaseFilter"
        >
        <button type="button" title="应用案件筛选" @click="applyCaseFilter">筛选</button>
        <button
          v-if="caseId"
          type="button"
          class="case-clear"
          title="清除案件筛选"
          aria-label="清除案件筛选"
          @click="clearCaseFilter"
        >
          <X :size="13" />
        </button>
      </div>
    </section>
    <p v-if="caseError" class="case-error" role="alert">{{ caseError }}</p>

    <section class="audit-table surface-panel">
      <LoadingState v-if="status === 'pending'" :rows="6" label="正在读取审计记录" />
      <ErrorState v-else-if="error" :title="errorTitle" :description="errorDescription" @retry="refresh" />
      <EmptyState v-else-if="!data?.items.length" :title="emptyTitle" :description="emptyDescription" />
      <template v-else>
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>时间</th><th>操作人</th><th>操作</th><th>对象</th>
                <th>结果</th><th>Request ID</th><th>备注</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in data.items" :key="item.id">
                <td class="mono subtle">{{ formatTime(item.createdAt) }}</td>
                <td>{{ item.actor }}</td>
                <td>{{ actionLabels[item.action] || item.action }}</td>
                <td><small>{{ item.objectType }}</small><b class="mono">{{ item.objectId }}</b></td>
                <td>
                  <StatusIndicator
                    :status="item.outcome === 'completed' ? 'healthy' : 'error'"
                    :label="resultLabel(item.outcome)"
                  />
                </td>
                <td class="mono subtle">{{ item.requestId || '—' }}</td>
                <td class="note-cell" :title="item.note || ''">{{ item.note || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <footer>
          <span class="pager">
            <button class="pager-btn" :disabled="page <= 1" @click="page -= 1">上一页</button>
            <span>第 {{ page }} 页 · 显示 {{ data.items.length }} / {{ data.total }} 条</span>
            <button class="pager-btn" :disabled="!canGoNext" @click="page += 1">下一页</button>
          </span>
          <span class="pager-meta">
            <select v-model="pageSize" aria-label="每页条数">
              <option :value="50">50 条/页</option>
              <option :value="100">100 条/页</option>
              <option :value="200">200 条/页</option>
            </select>
            <span>数据库事务审计 · API 分页上限 200</span>
          </span>
        </footer>
      </template>
    </section>
  </div>
</template>

<style scoped>
.audit-page{padding:20px 22px 28px}.page-button{display:flex;align-items:center;gap:5px;height:34px;padding:0 9px;border:1px solid var(--border-default);border-radius:8px;background:var(--surface-1);color:var(--text-secondary);font-size:13px;cursor:pointer}.page-button:disabled{cursor:not-allowed;opacity:.55}.export-message{display:flex;align-items:center;gap:6px;margin-bottom:10px;padding:8px 10px;border:1px solid color-mix(in srgb,var(--status-success) 35%,var(--border-default));border-radius:7px;color:var(--status-success);font-size:13px}
.audit-summary{display:flex;justify-content:space-between;align-items:center;min-height:56px;margin-bottom:12px;padding:8px 12px;border-block:1px solid var(--border-default);background:var(--surface-1)}.audit-summary>div{display:flex;align-items:center;gap:8px}.audit-summary svg{color:var(--status-success)}.audit-summary span b,.audit-summary span small{display:block}.audit-summary span b{font-size:13px}.audit-summary span small,.audit-summary p{color:var(--text-tertiary);font-size:12px}.audit-summary p{max-width:520px;margin:0;text-align:right}
.audit-toolbar{display:grid;grid-template-columns:minmax(0,1fr) 150px 110px minmax(250px,.9fr);gap:8px;margin-bottom:12px;padding:9px}.audit-toolbar label{position:relative}.audit-toolbar label svg{position:absolute;top:8px;left:9px;color:var(--text-tertiary)}.audit-toolbar input,.audit-toolbar select{width:100%;height:32px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);font-size:12px}.audit-toolbar input{padding:0 8px 0 29px}.audit-toolbar select{padding:0 7px}
.case-filter{position:relative;display:flex;align-items:center;gap:5px}.case-filter>svg{position:absolute;top:8px;left:9px;color:var(--text-tertiary);pointer-events:none}.case-filter input{min-width:0;flex:1}.case-filter button{flex:none;height:24px;padding:0 7px;border:1px solid var(--border-default);border-radius:5px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer;white-space:nowrap}.case-filter button:hover{border-color:var(--border-strong);color:var(--text-primary)}.case-error{margin:-6px 0 10px;color:var(--status-error);font-size:12px}
.audit-table{overflow:hidden}.table-scroll{overflow-x:auto}.audit-table table{width:100%;min-width:1050px;border-collapse:collapse}.audit-table th{height:34px;padding:0 9px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px;text-align:left}.audit-table td{height:48px;padding:6px 9px;border-top:1px solid var(--border-subtle);color:var(--text-secondary);font-size:13px}.audit-table td b,.audit-table td small{display:block}.audit-table td small{color:var(--text-tertiary);font-size:11px}.subtle{color:var(--text-tertiary)!important}.note-cell{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.audit-table footer{display:flex;justify-content:space-between;min-height:38px;align-items:center;padding:0 9px;border-top:1px solid var(--border-subtle);background:var(--surface-2);color:var(--text-tertiary);font-size:12px}.pager{display:flex;align-items:center;gap:8px}.pager-btn{padding:3px 8px;border:1px solid var(--border-default);border-radius:5px;background:var(--surface-1);color:var(--text-secondary);font-size:12px;cursor:pointer}.pager-btn:disabled{cursor:not-allowed;opacity:.5}.pager-meta{display:flex;align-items:center;gap:8px}.pager-meta select{height:26px;border:1px solid var(--border-default);border-radius:5px;background:var(--surface-1);color:var(--text-secondary);font-size:12px}
@media(max-width:1150px){.audit-toolbar{grid-template-columns:minmax(0,1fr) 150px 110px}.case-filter{grid-column:1/-1}}
@media(max-width:750px){.audit-page{padding:16px 12px 24px}.audit-summary{align-items:flex-start}.audit-summary p{display:none}.audit-toolbar{grid-template-columns:1fr}.audit-table footer{flex-direction:column;align-items:flex-start;padding:8px 9px;gap:6px}.audit-table footer span:last-child{display:none}}
</style>
