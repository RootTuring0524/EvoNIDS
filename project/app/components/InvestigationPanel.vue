<script setup lang="ts">
import { Bot, CheckCircle2, CircleAlert, Copy, Play, RefreshCw, ShieldAlert, ShieldCheck, Sparkles, TriangleAlert, XCircle } from '~/utils/icons'
import {
  feedbackCreateRequestSchema,
  investigationCreateRequestSchema,
  investigationDetailResponseSchema,
  investigationRunSchema,
  investigationsListResponseSchema,
  type InvestigationDetailApiResponse,
  type InvestigationRunApiResponse,
} from '~~/shared/schemas/security'
import type { FeedbackVerdict, InvestigationRunState, ToolExecutionRead } from '~~/shared/types/security'
import { evidenceLinkTargets } from '~/utils/evidenceLinks'

const props = defineProps<{ alertId: string }>()
const isMock = useRuntimeConfig().public.useMockApi

// ---- local state (all displayed values come from the backend API) ----------
const runs = ref<InvestigationRunApiResponse[]>([])
const listState = ref<'idle' | 'loading' | 'error'>('idle')
const listError = ref('')
const selectedId = ref<string | null>(null)
const detail = ref<InvestigationDetailApiResponse | null>(null)
const detailLoading = ref(false)
const detailError = ref('')
const starting = ref(false)
const notice = ref('')

// Feedback form state
const verdict = ref<FeedbackVerdict | null>(null)
const label = ref('')
const comment = ref('')
const submitting = ref(false)
const feedbackError = ref('')
const feedbackSuccess = ref('')

let pollTimer: number | null = null

const runStateLabels: Record<InvestigationRunState, string> = {
  queued: '排队中',
  running: '运行中',
  succeeded: '已完成',
  insufficient_evidence: '证据不足',
  degraded: 'AI 不可用',
  failed: '失败',
  cancelled: '已取消',
}
const claimTypeLabels: Record<string, string> = {
  observation: '观察',
  inference: '推断',
  recommendation: '建议',
  rejected: '已驳回',
}
const verdictOptions: FeedbackVerdict[] = ['agree', 'disagree', 'unsure']
const verdictMeta: Record<FeedbackVerdict, { label: string; tone: string }> = {
  agree: { label: '同意', tone: 'agree' },
  disagree: { label: '不同意', tone: 'disagree' },
  unsure: { label: '不确定', tone: 'unsure' },
}
const toolStateLabels: Record<ToolExecutionRead['state'], string> = {
  completed: '已完成',
  rejected: '已拒绝',
  failed: '失败',
}

function readError(error: unknown) {
  const shape = (typeof error === 'object' && error !== null ? error : {}) as {
    data?: { statusMessage?: string; message?: string; detail?: string | null }
    statusMessage?: string
    message?: string
  }
  return shape.data?.detail || shape.data?.statusMessage || shape.data?.message
    || shape.statusMessage || shape.message || '操作失败，请稍后重试。'
}
function showNotice(text: string) {
  notice.value = text
  window.setTimeout(() => { if (notice.value === text) notice.value = '' }, 4000)
}
function clearPoll() {
  if (pollTimer) { window.clearTimeout(pollTimer); pollTimer = null }
}

// ---- run list ---------------------------------------------------------------
async function loadRuns() {
  if (isMock) { runs.value = []; listState.value = 'idle'; return }
  listState.value = 'loading'
  listError.value = ''
  try {
    const response = await validatedFetch('/investigations', investigationsListResponseSchema, {
      query: { alertId: props.alertId, page: 1, pageSize: 25 },
    })
    runs.value = response.items
    // Keep the previous selection when it is still part of the refreshed list.
    if (selectedId.value && !runs.value.some((run) => run.id === selectedId.value)) {
      selectedId.value = null
      detail.value = null
    }
    // Auto-open the newest listed run when nothing is selected yet.
    const firstRun = runs.value[0]
    if (!selectedId.value && firstRun && !detailLoading.value) {
      selectedId.value = firstRun.id
      void fetchDetail(firstRun.id)
    }
    listState.value = 'idle'
  } catch (error) {
    listError.value = readError(error)
    listState.value = 'error'
  }
}

// ---- run detail + polling ---------------------------------------------------
async function openRun(runId: string) {
  selectedId.value = runId
  clearPoll()
  await fetchDetail(runId)
}

async function fetchDetail(runId: string, reschedule = true) {
  detailLoading.value = true
  detailError.value = ''
  const previousState = selectedId.value === runId ? detail.value?.run.state : undefined
  try {
    const result = await validatedFetch(`/investigations/${encodeURIComponent(runId)}`, investigationDetailResponseSchema)
    if (selectedId.value !== runId) return
    detail.value = result
    const state = result.run.state
    const active = state === 'queued' || state === 'running'
    if (active && reschedule) {
      schedulePoll(runId)
    } else if (!active && (previousState === 'queued' || previousState === 'running')) {
      // A run we were polling reached a terminal state: refresh the nav chips
      // so their state labels match the run we just rendered.
      void loadRuns()
    }
  } catch (error) {
    if (selectedId.value !== runId) return
    detail.value = null
    detailError.value = readError(error)
  } finally {
    detailLoading.value = false
  }
}

function schedulePoll(runId: string) {
  clearPoll()
  pollTimer = window.setTimeout(() => {
    pollTimer = null
    if (selectedId.value === runId) void fetchDetail(runId)
  }, 3000)
}

async function startInvestigation() {
  if (!props.alertId || starting.value || isMock) return
  starting.value = true
  detailError.value = ''
  try {
    // Backend applies its own defaults for maxToolCalls / budgetUsd when absent.
    const parsed = investigationCreateRequestSchema.safeParse({ alertId: props.alertId })
    if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? '调查参数无效')
    // The backend answers 202 with the queued InvestigationRunRead record.
    const createdRun = await validatedFetch('/investigations', investigationRunSchema, {
      method: 'POST',
      body: parsed.data,
    })
    runs.value = [createdRun, ...runs.value.filter((run) => run.id !== createdRun.id)]
    selectedId.value = createdRun.id
    detail.value = null
    clearPoll()
    await fetchDetail(createdRun.id)
    showNotice('AI 调查已启动，正在排队执行…')
  } catch (error) {
    detailError.value = readError(error)
  } finally {
    starting.value = false
  }
}

// ---- feedback ----------------------------------------------------------------
function resetFeedbackForm() {
  verdict.value = null
  label.value = ''
  comment.value = ''
  feedbackError.value = ''
}

async function submitFeedback() {
  const runId = selectedId.value
  const current = detail.value?.run
  if (!runId || !current || submitting.value) return
  const parsed = feedbackCreateRequestSchema.safeParse({
    objectType: 'investigation_run',
    objectId: runId,
    verdict: verdict.value ?? undefined,
    label: label.value || undefined,
    comment: comment.value || undefined,
  })
  if (!parsed.success || !parsed.data.verdict) {
    feedbackError.value = '请先选择对调查结论的判定（同意 / 不同意 / 不确定）。'
    return
  }
  submitting.value = true
  feedbackError.value = ''
  feedbackSuccess.value = ''
  try {
    await validatedFetch(`/investigations/${encodeURIComponent(runId)}/feedback`, feedbackCreateRequestSchema, {
      method: 'POST',
      body: parsed.data,
    })
    feedbackSuccess.value = '反馈已提交，审计记录已写入。'
    resetFeedbackForm()
    await fetchDetail(runId, false)
  } catch (error) {
    feedbackError.value = readError(error)
  } finally {
    submitting.value = false
  }
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    showNotice('已复制')
  } catch {
    showNotice('浏览器未授予剪贴板权限')
  }
}

function timestamp(text: string | null): string {
  if (!text) return '—'
  const date = new Date(text)
  return Number.isNaN(date.getTime()) ? text : date.toLocaleString('zh-CN')
}

function usd(value: number | null): string {
  return value === null ? '—' : `$${value.toFixed(4)}`
}
function seconds(value: number | null): string {
  return value === null ? '—' : `${(value / 1000).toFixed(1)} s`
}

// Retrieval snapshot: render only what the backend actually reported. Nested
// objects/arrays are summarised by their shape, never invented.
interface RetrievalEntry { key: string; display: string }
function retrievalEntries(retrieval: Record<string, unknown> | undefined): RetrievalEntry[] {
  if (!retrieval) return []
  return Object.entries(retrieval).map(([key, value]) => {
    if (value === null || value === undefined) return { key, display: '无' }
    if (Array.isArray(value)) return { key, display: `数组 · ${value.length} 项` }
    if (typeof value === 'object') {
      const count = Object.keys(value as Record<string, unknown>).length
      return { key, display: `对象 · ${count} 个字段` }
    }
    return { key, display: String(value) }
  })
}

function rejectedClaims() {
  return (detail.value?.claims ?? []).filter((claim) => claim.claimType === 'rejected')
}

watch(() => props.alertId, () => {
  runs.value = []
  detail.value = null
  selectedId.value = null
  detailError.value = ''
  clearPoll()
  resetFeedbackForm()
  if (!isMock) void loadRuns()
})
onMounted(() => {
  if (!isMock) void loadRuns()
  else listState.value = 'idle'
})
onBeforeUnmount(clearPoll)

const runningNow = computed(() => {
  const run = detail.value?.run
  return run !== undefined && (run.state === 'queued' || run.state === 'running')
})
const selectedRun = computed(() => detail.value?.run ?? null)
const canReview = computed(() => {
  const state = selectedRun.value?.state
  return state === 'succeeded' || state === 'insufficient_evidence' || state === 'degraded'
})
</script>

<template>
  <section class="investigation surface-panel" aria-label="AI 调查">
    <header class="inv-head">
      <div>
        <h2>AI 调查</h2>
        <p><code>{{ alertId }}</code> · 基于检索证据的逐条引用结论<template v-if="runs.length"> · 共 {{ runs.length }} 次运行</template></p>
      </div>
      <div class="inv-actions">
        <button :disabled="isMock || listState === 'loading'" @click="loadRuns"><RefreshCw :size="13" :class="{ spin: listState === 'loading' }" />刷新</button>
        <button class="primary" :disabled="isMock || starting || listState === 'loading'" :aria-busy="starting" @click="startInvestigation"><Play :size="13" />{{ starting ? '正在启动…' : '启动 AI 调查' }}</button>
      </div>
    </header>

    <div v-if="isMock" class="mock-notice" role="note">
      <TriangleAlert :size="14" /><div><b>演示模式</b><p>AI 调查运行只由真实后端产生；此处不伪造运行、结论或证据。连接真实后端后即可启动调查。</p></div>
    </div>

    <div v-if="notice" class="inv-toast" role="status"><CheckCircle2 :size="14" />{{ notice }}</div>

    <template v-if="!isMock">
      <div v-if="listState === 'loading' && runs.length === 0" class="panel-hint"><LoadingState :rows="3" label="正在加载调查运行" /></div>
      <ErrorState v-else-if="listState === 'error' && runs.length === 0" title="调查运行加载失败" :description="listError" @retry="loadRuns" />

      <div v-else-if="runs.length === 0" class="empty-runs">
        <Bot :size="22" /><div><b>该告警还没有 AI 调查运行</b><p>点击「启动 AI 调查」后，后端将排队执行带逐条证据引用的调查；结果会在这里展示。</p></div>
      </div>

      <template v-else>
        <div v-if="detailError" class="inv-error" role="alert"><XCircle :size="14" />{{ detailError }}</div>
        <div v-if="starting" class="start-note" role="status"><span /><b>调查排队中</b><em>运行与结论由后端生成</em></div>

        <nav v-if="runs.length > 1" class="run-list" aria-label="调查运行列表">
          <button v-for="run in runs" :key="run.id" :class="{ active: run.id === selectedId }" @click="openRun(run.id)">
            <span :class="['state-dot', run.state]" /><b class="mono">{{ run.id }}</b>
            <em :class="run.state">{{ runStateLabels[run.state] }}</em>
          </button>
        </nav>

        <div v-if="detailLoading && !detail" class="panel-hint"><LoadingState :rows="6" label="正在加载调查详情" /></div>
        <ErrorState v-else-if="detailError && !detail" title="调查详情加载失败" :description="detailError" @retry="() => selectedId && openRun(selectedId)" />
        <template v-else-if="detail && detail.run">
          <div v-if="detail.run.state === 'insufficient_evidence'" class="state-banner insufficient" role="status">
            <Sparkles :size="18" /><div><b>证据不足</b><p>本次调查未能收集到足以形成可靠结论的证据，未给出确定性研判。</p><p v-if="detail.run.summary" class="mono-state">{{ detail.run.summary }}</p></div>
          </div>
          <div v-else-if="detail.run.state === 'degraded'" class="state-banner degraded" role="status">
            <ShieldAlert :size="18" /><div><b>AI 不可用</b><p>模型服务或调查链路降级，本次调查未完整执行。基础检测、案件与证据功能不受影响，仍可继续使用。</p><p v-if="detail.run.summary" class="mono-state">{{ detail.run.summary }}</p></div>
          </div>
          <div v-else-if="detail.run.state === 'failed'" class="state-banner failed" role="status">
            <CircleAlert :size="18" /><div><b>调查失败</b><p>{{ detail.run.errorMessage || '后端返回失败状态，请查看错误信息后重试。' }}</p></div>
          </div>
          <div v-else-if="detail.run.state === 'cancelled'" class="state-banner failed" role="status">
            <CircleAlert :size="18" /><div><b>调查已取消</b><p>{{ detail.run.errorMessage || '该次运行已取消，未产生新结论。' }}</p></div>
          </div>
          <div v-else-if="runningNow" class="state-banner running" role="status">
            <span class="pulse" /><div><b>调查运行中</b><p>后端正在执行工具链与证据检索；页面会轮询直到进入终态。</p></div>
          </div>
          <div v-else class="state-banner done" role="status">
            <ShieldCheck :size="18" /><div><b>调查完成</b><p>以下结论均带可追溯的证据引用。</p></div>
          </div>

          <section class="run-meta surface-2-block" aria-label="运行元数据">
            <div class="meta-title"><b>运行信息</b><span class="mono">{{ detail.run.id }}</span></div>
            <dl>
              <div><dt>发起人</dt><dd>{{ detail.run.requestedBy || '—' }}</dd></div>
              <div><dt>供应商 / 模型</dt><dd class="mono">{{ detail.run.provider || '—' }} / {{ detail.run.modelId || '—' }}</dd></div>
              <div><dt>Prompt 模板</dt><dd class="mono">{{ detail.run.promptTemplateVersion || '—' }}</dd></div>
              <div><dt>工具注册表</dt><dd class="mono">{{ detail.run.toolRegistryVersion || '—' }}</dd></div>
              <div><dt>知识版本</dt><dd class="mono">{{ detail.run.knowledgeVersion || '—' }}</dd></div>
              <div><dt>最大工具调用</dt><dd>{{ detail.run.maxToolCalls }}</dd></div>
              <div><dt>Token 用量</dt><dd class="mono">{{ detail.run.promptTokens }} / {{ detail.run.completionTokens }}</dd></div>
              <div><dt>成本估算</dt><dd class="mono">{{ usd(detail.run.costEstimateUsd) }}</dd></div>
              <div><dt>不确定性</dt><dd class="mono">{{ detail.run.uncertainty === null ? '—' : detail.run.uncertainty.toFixed(3) }}</dd></div>
              <div><dt>延迟</dt><dd class="mono">{{ seconds(detail.run.latencyMs) }}</dd></div>
              <div><dt>尝试次数</dt><dd>{{ detail.run.attempts }}</dd></div>
              <div><dt>创建 / 完成</dt><dd class="mono">{{ timestamp(detail.run.createdAt) }}<template v-if="detail.run.completedAt"> → {{ timestamp(detail.run.completedAt) }}</template></dd></div>
            </dl>
          </section>

          <section v-if="retrievalEntries(detail.run.retrieval).length" class="retrieval surface-2-block" aria-label="检索快照摘要">
            <div class="meta-title"><b>检索快照</b><span>本次运行实际使用的检索结果</span></div>
            <div class="retrieval-grid">
              <div v-for="entry in retrievalEntries(detail.run.retrieval)" :key="entry.key"><dt class="mono">{{ entry.key }}</dt><dd>{{ entry.display }}</dd></div>
            </div>
          </section>

          <ul v-if="detail.run.degradedReasons.length" class="degraded-list" aria-label="降级原因">
            <li v-for="reason in detail.run.degradedReasons" :key="reason"><ShieldAlert :size="12" />{{ reason }}</li>
          </ul>

          <p v-if="detail.run.summary" class="run-summary">{{ detail.run.summary }}</p>

          <section class="claims-block" aria-label="调查结论">
            <div class="block-head"><div><h3>调查结论（{{ detail.claims.length }}）</h3><p>每条结论引用后端检索到的证据，可点击查看原文</p></div></div>
            <div v-if="detail.claims.length === 0" class="sub-empty">本次运行没有产生结论条目。</div>
            <article v-for="claim in detail.claims" :key="claim.id" class="claim-card" :class="{ rejected: claim.claimType === 'rejected' }">
              <header>
                <div class="claim-title">
                  <span :class="['claim-type', claim.claimType]">{{ claimTypeLabels[claim.claimType] }}</span>
                  <b>#{{ claim.claimIndex + 1 }}</b>
                  <template v-if="claim.claimType === 'rejected'"><em class="rejected-mark">已驳回</em></template>
                </div>
                <div class="claim-flags">
                  <span class="score"><i />置信 {{ (claim.confidence * 100).toFixed(0) }}%</span>
                  <span class="score"><i />不确定 {{ (claim.uncertainty * 100).toFixed(0) }}%</span>
                  <span v-if="claim.verified" class="chip-ok">已验证</span>
                  <span v-else class="chip-raw">未验证</span>
                </div>
              </header>
              <p class="claim-statement">{{ claim.statement }}</p>
              <div v-if="claim.claimType === 'rejected' && claim.rejectionReason" class="rejection-reason"><XCircle :size="13" /><span><b>驳回原因</b>{{ claim.rejectionReason }}</span></div>
              <div v-if="claim.mitreTechniques.length" class="techniques"><span v-for="tech in claim.mitreTechniques" :key="tech" class="mono">{{ tech }}</span></div>
              <div v-if="claim.evidenceIds.length" class="evidence-links">
                <span class="evidence-caption">证据引用（{{ claim.evidenceIds.length }}）</span>
                <NuxtLink
                  v-for="target in evidenceLinkTargets(claim.evidenceIds)"
                  :key="target.id"
                  :to="target.to"
                  class="mono"
                >{{ target.id }}</NuxtLink>
                <button v-if="claim.evidenceIds.length > 5" class="copy-all" @click="copyText(claim.evidenceIds.join('\n'))"><Copy :size="12" />复制全部 ID</button>
              </div>
            </article>
            <p v-if="rejectedClaims().length" class="rejected-note">已驳回条目不参与调查结论，驳回原因如上所示。</p>
          </section>

          <section class="tools-block surface-2-block" aria-label="工具执行记录">
            <div class="block-head"><div><h3>工具执行（{{ detail.tools.length }}）</h3><p>仅记录工具名称、状态、耗时与错误</p></div></div>
            <div v-if="detail.tools.length === 0" class="sub-empty">本次运行没有工具执行记录。</div>
            <div v-for="tool in detail.tools" :key="tool.id" class="tool-row" :class="tool.state">
              <span :class="['tool-chip', tool.state]">{{ toolStateLabels[tool.state] }}</span>
              <b class="mono">{{ tool.toolName }}</b>
              <em class="mono">v{{ tool.toolVersion }}</em>
              <span class="duration">耗时 {{ tool.durationMs }} ms</span>
              <p v-if="tool.error" class="tool-error" role="alert">{{ tool.error }}</p>
              <p v-else-if="tool.resultSummary" class="tool-summary">{{ tool.resultSummary }}</p>
            </div>
          </section>

          <section class="feedback-block surface-2-block" aria-label="分析师反馈">
            <div class="block-head"><div><h3>分析师反馈</h3><p>判定仅对本次运行的结论整体生效，写入审计</p></div></div>
            <div v-if="detail.feedback.length" class="feedback-list">
              <div v-for="item in detail.feedback" :key="item.id" class="feedback-row">
                <span :class="['verdict-chip', verdictMeta[item.verdict].tone]">{{ verdictMeta[item.verdict].label }}</span>
                <b>{{ item.actor }}</b>
                <em v-if="item.label" class="mono">{{ item.label }}</em>
                <p v-if="item.comment">{{ item.comment }}</p>
                <small class="mono">{{ timestamp(item.createdAt) }}</small>
              </div>
            </div>
            <div v-if="canReview" class="feedback-form">
              <p v-if="feedbackSuccess" class="form-success" role="status"><CheckCircle2 :size="13" />{{ feedbackSuccess }}</p>
              <fieldset>
                <legend>本次调查结论是否可信？</legend>
                <label v-for="option in verdictOptions" :key="option"><input v-model="verdict" type="radio" name="verdict" :value="option">{{ verdictMeta[option].label }}</label>
              </fieldset>
              <label class="field"><span>标签（可选）</span><input v-model="label" type="text" maxlength="200" placeholder="如：高置信结论"></label>
              <label class="field"><span>评注（可选）</span><textarea v-model="comment" rows="3" maxlength="2000" placeholder="补充说明将写入审计记录…" /></label>
              <p v-if="feedbackError" class="form-error" role="alert"><XCircle :size="13" />{{ feedbackError }}</p>
              <button class="primary" :disabled="submitting" @click="submitFeedback">{{ submitting ? '提交中…' : '提交反馈' }}</button>
            </div>
            <p v-else-if="detail.run.state !== 'succeeded' && detail.run.state !== 'insufficient_evidence' && detail.run.state !== 'degraded'" class="sub-empty">仅对已完成的调查提供反馈。</p>
          </section>
        </template>
      </template>
    </template>
  </section>
</template>

<style scoped>
.investigation{overflow:hidden}
.inv-head{display:flex;justify-content:space-between;align-items:center;gap:10px;min-height:52px;padding:8px 12px;border-bottom:1px solid var(--border-subtle)}
.inv-head h2{margin:0;font-size:14px}.inv-head p{margin:2px 0 0;color:var(--text-tertiary);font-size:12px}.inv-head p code{color:var(--text-secondary)}
.inv-actions{display:flex;gap:7px}.inv-actions button{display:flex;gap:5px;align-items:center;height:30px;padding:0 10px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer}.inv-actions button.primary{border-color:color-mix(in srgb,var(--accent) 50%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.inv-actions button:disabled{opacity:.55;cursor:not-allowed}
.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.mock-notice{display:flex;gap:9px;margin:12px;padding:10px 11px;border:1px dashed color-mix(in srgb,var(--status-warning) 45%,var(--border-default));border-radius:8px;background:color-mix(in srgb,var(--status-warning) 7%,transparent);color:var(--status-warning);font-size:12px}.mock-notice>div{flex:1}.mock-notice b{display:block}.mock-notice p{margin:3px 0 0;color:var(--text-tertiary);line-height:1.55}
.inv-toast{display:flex;gap:6px;align-items:center;margin:10px 12px 0;padding:8px 10px;border:1px solid color-mix(in srgb,var(--status-success) 35%,var(--border-default));border-radius:7px;background:color-mix(in srgb,var(--status-success) 7%,transparent);color:var(--status-success);font-size:12px}
.panel-hint{padding:6px}
.empty-runs{display:flex;gap:10px;align-items:flex-start;min-height:104px;padding:18px;color:var(--text-tertiary)}.empty-runs>div{flex:1}.empty-runs b{display:block;color:var(--text-primary);font-size:13px}.empty-runs p{margin:3px 0 0;font-size:13px;line-height:1.55}
.inv-error{display:flex;gap:6px;align-items:center;margin:10px 12px 0;padding:8px 10px;border-left:2px solid var(--status-error);background:color-mix(in srgb,var(--status-error) 8%,transparent);color:var(--status-error);font-size:12px}
.start-note{display:flex;gap:6px;align-items:center;min-height:33px;padding:0 12px;border-bottom:1px solid var(--border-subtle);background:color-mix(in srgb,var(--status-warning) 6%,var(--surface-2));color:var(--status-warning);font-size:12px}.start-note span{width:6px;height:6px;border-radius:50%;background:currentColor}.start-note em{margin-left:auto;color:var(--text-tertiary);font-style:normal}
.run-list{display:flex;gap:6px;overflow-x:auto;padding:10px 12px;border-bottom:1px solid var(--border-subtle)}.run-list button{display:flex;align-items:center;gap:6px;min-width:max-content;height:29px;padding:0 9px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer}.run-list button.active{border-color:color-mix(in srgb,var(--accent) 55%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.run-list b{font-weight:550}.run-list em{font-style:normal;color:var(--text-tertiary)}.run-list em.succeeded{color:var(--status-success)}.run-list em.running,.run-list em.queued{color:var(--status-warning)}.run-list em.failed,.run-list em.cancelled{color:var(--status-error)}.state-dot{width:7px;height:7px;border-radius:50%;background:var(--text-tertiary)}.state-dot.succeeded{background:var(--status-success)}.state-dot.running,.state-dot.queued{background:var(--status-warning)}.state-dot.failed,.state-dot.cancelled,.state-dot.insufficient_evidence,.state-dot.degraded{background:var(--status-error)}
.state-banner{display:flex;gap:10px;align-items:flex-start;margin:12px 12px 0;padding:10px 12px;border-radius:8px;background:var(--surface-2)}.state-banner>div{flex:1}.state-banner b{display:block;font-size:13px}.state-banner p{margin:3px 0 0;font-size:12px;line-height:1.55}.state-banner .mono-state{color:var(--text-secondary);font-family:var(--mono,ui-monospace,monospace);font-size:12px}
.state-banner.insufficient{border-left:3px solid var(--status-warning);background:color-mix(in srgb,var(--status-warning) 8%,transparent)}.state-banner.insufficient b,.state-banner.insufficient svg{color:var(--status-warning)}
.state-banner.degraded,.state-banner.failed{border-left:3px solid var(--status-error);background:color-mix(in srgb,var(--status-error) 7%,transparent)}.state-banner.degraded b,.state-banner.degraded svg,.state-banner.failed b,.state-banner.failed svg{color:var(--status-error)}
.state-banner.running{border-left:3px solid var(--status-warning)}.state-banner.running b,.state-banner.running svg{color:var(--status-warning)}.state-banner.done{border-left:3px solid var(--status-success)}.state-banner.done b,.state-banner.done svg{color:var(--status-success)}
.pulse{width:8px;height:8px;margin-top:3px;border-radius:50%;background:var(--status-warning);animation:pulse 1.2s ease-in-out infinite}@keyframes pulse{50%{opacity:.25}}
.surface-2-block{margin:12px;border:1px solid var(--border-subtle);border-radius:9px;background:var(--surface-1)}
.meta-title{display:flex;justify-content:space-between;align-items:center;gap:8px;min-height:40px;padding:0 11px;border-bottom:1px solid var(--border-subtle)}.meta-title b{font-size:13px}.meta-title span{color:var(--text-tertiary);font-size:12px}.meta-title .mono{color:var(--text-secondary);font-size:11px}
.run-meta dl{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));margin:0}.run-meta dl>div{min-width:0;padding:8px 10px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.run-meta dt{color:var(--text-tertiary);font-size:12px}.run-meta dd{margin:2px 0 0;overflow:hidden;color:var(--text-secondary);font-size:12px;text-overflow:ellipsis;white-space:nowrap}.run-meta dd.mono{font-family:var(--mono,ui-monospace,monospace);font-size:11px}
.retrieval-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}.retrieval-grid>div{min-width:0;padding:7px 10px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.retrieval-grid dt{overflow:hidden;color:var(--text-tertiary);font-size:11px;text-overflow:ellipsis;white-space:nowrap}.retrieval-grid dd{margin:2px 0 0;overflow:hidden;color:var(--text-secondary);font-size:12px;text-overflow:ellipsis;white-space:nowrap}
.degraded-list{margin:0 12px;padding:8px 0 0;list-style:none;display:grid;gap:4px}.degraded-list li{display:flex;gap:6px;align-items:center;color:var(--status-warning);font-size:12px}
.run-summary{margin:12px;padding:10px 12px;border-left:2px solid var(--accent);background:var(--surface-2);color:var(--text-secondary);font-size:13px;line-height:1.6}
.claims-block{margin:12px;border:1px solid var(--border-subtle);border-radius:9px;background:var(--surface-1);overflow:hidden}
.block-head{display:flex;justify-content:space-between;align-items:center;min-height:46px;padding:0 12px;border-bottom:1px solid var(--border-subtle)}.block-head h3{margin:0;font-size:13px}.block-head p{margin:3px 0 0;color:var(--text-tertiary);font-size:12px}
.claim-card{padding:11px 12px;border-bottom:1px solid var(--border-subtle)}.claim-card:last-child{border-bottom:0}.claim-card.rejected{background:color-mix(in srgb,var(--status-error) 4%,var(--surface-2))}
.claim-card>header{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}.claim-title{display:flex;gap:6px;align-items:center}.claim-type{padding:1px 7px;border-radius:4px;font-size:12px;background:var(--accent-muted);color:var(--accent-strong)}.claim-type.recommendation{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.claim-type.rejected{background:color-mix(in srgb,var(--status-error) 12%,transparent);color:var(--status-error)}.claim-title>em{font-style:normal;font-weight:600}.claim-title b{color:var(--text-tertiary);font-size:12px;font-weight:600}.rejected-mark{color:var(--status-error)!important;font-size:12px}
.claim-flags{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.score{display:inline-flex;align-items:center;gap:4px;color:var(--text-tertiary);font-size:12px}.score i{width:6px;height:6px;border-radius:50%;background:var(--severity-info)}.chip-ok{padding:1px 6px;border-radius:4px;font-size:12px;background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.chip-raw{padding:1px 6px;border-radius:4px;font-size:12px;background:var(--surface-3);color:var(--text-tertiary)}
.claim-statement{margin:8px 0;color:var(--text-primary);font-size:13px;line-height:1.65}
.rejection-reason{display:flex;gap:7px;align-items:flex-start;margin:6px 0;padding:7px 9px;border-left:2px solid var(--status-error);background:color-mix(in srgb,var(--status-error) 7%,transparent);color:var(--status-error);font-size:12px}.rejection-reason span{flex:1}.rejection-reason b{display:block;font-weight:650}.rejection-reason svg{flex:0 0 auto;margin-top:1px}
.techniques{display:flex;gap:5px;flex-wrap:wrap;margin:7px 0}.techniques span{padding:1px 6px;border-radius:4px;background:var(--surface-3);color:var(--accent-strong);font-size:11px}
.evidence-links{display:flex;gap:5px;align-items:center;flex-wrap:wrap;margin-top:7px}.evidence-caption{color:var(--text-tertiary);font-size:12px}.evidence-links a{display:inline-flex;padding:2px 7px;border:1px solid color-mix(in srgb,var(--accent) 35%,var(--border-default));border-radius:5px;background:var(--accent-muted);color:var(--accent-strong);font-size:11px;text-decoration:none}.evidence-links a:hover{text-decoration:underline}.copy-all{display:inline-flex;gap:4px;align-items:center;padding:2px 6px;border:0;background:transparent;color:var(--text-tertiary);font-size:11px;cursor:pointer}.rejected-note{margin:0;padding:8px 12px;color:var(--text-tertiary);font-size:12px}
.sub-empty{padding:12px;color:var(--text-tertiary);font-size:13px}
.tools-block .tool-row{display:grid;grid-template-columns:auto auto 1fr auto;gap:8px;align-items:center;padding:8px 12px;border-top:1px solid var(--border-subtle)}.tool-row:first-of-type{border-top:0}.tool-chip{padding:1px 6px;border-radius:4px;font-size:12px;background:var(--surface-3);color:var(--text-tertiary)}.tool-chip.completed{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.tool-chip.rejected{background:color-mix(in srgb,var(--status-warning) 14%,transparent);color:var(--status-warning)}.tool-chip.failed{background:color-mix(in srgb,var(--status-error) 12%,transparent);color:var(--status-error)}.tool-row b{font-size:12px}.tool-row em{color:var(--text-tertiary);font-size:11px;font-style:normal}.tool-row .duration{color:var(--text-tertiary);font-size:12px;text-align:right}.tool-row p{grid-column:2/-1;margin:0;font-size:12px;line-height:1.5}.tool-error{color:var(--status-error)}.tool-summary{color:var(--text-secondary)}
.feedback-list{display:grid}.feedback-row{display:grid;grid-template-columns:auto auto 1fr;gap:5px 10px;align-items:center;padding:8px 12px;border-top:1px solid var(--border-subtle)}.feedback-row p{grid-column:1/-1;margin:0;color:var(--text-secondary);font-size:12px}.feedback-row small{color:var(--text-tertiary);font-size:11px;text-align:right}.verdict-chip{padding:1px 7px;border-radius:4px;font-size:12px}.verdict-chip.agree{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.verdict-chip.disagree{background:color-mix(in srgb,var(--status-error) 12%,transparent);color:var(--status-error)}.verdict-chip.unsure{background:color-mix(in srgb,var(--text-tertiary) 16%,transparent);color:var(--text-tertiary)}
.feedback-form{padding:11px 12px;border-top:1px solid var(--border-subtle)}.feedback-form fieldset{border:0;margin:0 0 10px;padding:0;display:flex;gap:14px}.feedback-form legend{display:block;width:100%;margin-bottom:6px;color:var(--text-tertiary);font-size:12px}.feedback-form fieldset label{display:inline-flex;gap:5px;align-items:center;color:var(--text-secondary);font-size:13px;cursor:pointer}.field{display:block;margin:0 0 9px}.field>span{display:block;margin-bottom:4px;color:var(--text-tertiary);font-size:12px}.field input,.field textarea{width:100%;padding:7px 9px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-primary);font-size:13px;resize:vertical}.form-error,.form-success{display:flex;gap:5px;align-items:center;margin:0 0 8px;font-size:12px}.form-error{color:var(--status-error)}.form-success{color:var(--status-success)}.feedback-form>button{height:31px;padding:0 11px;border:1px solid color-mix(in srgb,var(--accent) 55%,var(--border-default));border-radius:7px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px;cursor:pointer}.feedback-form>button:disabled{opacity:.55}
@media(max-width:900px){.run-meta dl{grid-template-columns:repeat(2,1fr)}.retrieval-grid{grid-template-columns:1fr 1fr}}@media(max-width:600px){.run-meta dl,.retrieval-grid{grid-template-columns:1fr}.tool-row{grid-template-columns:1fr auto}.tool-row p{grid-column:1/-1}}
</style>
