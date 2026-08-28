<script setup lang="ts">
import { Download, Search, ShieldCheck } from '~/utils/icons'
import { auditEventsResponseSchema } from '~~/shared/schemas/security'
import { downloadCsv } from '~/utils/export'

const search = ref('')
const objectType = ref('all')
const outcome = ref('all')
const exportMessage = ref('')
const query = computed(() => ({
  search: search.value.trim(),
  objectType: objectType.value,
  outcome: outcome.value,
  page: 1,
  pageSize: 100,
}))
const { data, status, error, refresh } = await useAsyncData(
  'audit-events',
  () => validatedFetch('/audit', auditEventsResponseSchema, { query: query.value }),
  { watch: [query] },
)

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
          <small>当前查询返回 {{ data?.total ?? 0 }} 条记录 · 时区 Asia/Shanghai</small>
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
      </select>
      <select v-model="outcome" aria-label="执行结果">
        <option value="all">全部结果</option>
        <option value="completed">成功</option>
        <option value="failed">失败</option>
      </select>
    </section>

    <section class="audit-table surface-panel">
      <LoadingState v-if="status === 'pending'" :rows="6" label="正在读取审计记录" />
      <ErrorState v-else-if="error" title="审计日志加载失败" @retry="refresh" />
      <EmptyState
        v-else-if="!data?.items.length"
        title="没有匹配的审计记录"
        description="调整操作人、对象或结果筛选条件后重试。"
      />
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
          显示 {{ data.items.length }} / {{ data.total }} 条记录
          <span>数据库事务审计 · API 分页上限 200</span>
        </footer>
      </template>
    </section>
  </div>
</template>

<style scoped>
.audit-page{padding:20px 22px 28px}.page-button{display:flex;align-items:center;gap:5px;height:34px;padding:0 9px;border:1px solid var(--border-default);border-radius:8px;background:var(--surface-1);color:var(--text-secondary);font-size:13px;cursor:pointer}.page-button:disabled{cursor:not-allowed;opacity:.55}.export-message{display:flex;align-items:center;gap:6px;margin-bottom:10px;padding:8px 10px;border:1px solid color-mix(in srgb,var(--status-success) 35%,var(--border-default));border-radius:7px;color:var(--status-success);font-size:13px}
.audit-summary{display:flex;justify-content:space-between;align-items:center;min-height:56px;margin-bottom:12px;padding:8px 12px;border-block:1px solid var(--border-default);background:var(--surface-1)}.audit-summary>div{display:flex;align-items:center;gap:8px}.audit-summary svg{color:var(--status-success)}.audit-summary span b,.audit-summary span small{display:block}.audit-summary span b{font-size:13px}.audit-summary span small,.audit-summary p{color:var(--text-tertiary);font-size:12px}.audit-summary p{max-width:520px;margin:0;text-align:right}
.audit-toolbar{display:grid;grid-template-columns:1fr 160px 130px;gap:8px;margin-bottom:12px;padding:9px}.audit-toolbar label{position:relative}.audit-toolbar label svg{position:absolute;top:8px;left:9px;color:var(--text-tertiary)}.audit-toolbar input,.audit-toolbar select{width:100%;height:32px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);font-size:12px}.audit-toolbar input{padding:0 8px 0 29px}.audit-toolbar select{padding:0 7px}
.audit-table{overflow:hidden}.table-scroll{overflow-x:auto}.audit-table table{width:100%;min-width:1050px;border-collapse:collapse}.audit-table th{height:34px;padding:0 9px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px;text-align:left}.audit-table td{height:48px;padding:6px 9px;border-top:1px solid var(--border-subtle);color:var(--text-secondary);font-size:13px}.audit-table td b,.audit-table td small{display:block}.audit-table td small{color:var(--text-tertiary);font-size:11px}.subtle{color:var(--text-tertiary)!important}.note-cell{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.audit-table footer{display:flex;justify-content:space-between;min-height:38px;align-items:center;padding:0 9px;border-top:1px solid var(--border-subtle);background:var(--surface-2);color:var(--text-tertiary);font-size:12px}
@media(max-width:750px){.audit-page{padding:16px 12px 24px}.audit-summary{align-items:flex-start}.audit-summary p{display:none}.audit-toolbar{grid-template-columns:1fr}.audit-table footer span{display:none}}
</style>
