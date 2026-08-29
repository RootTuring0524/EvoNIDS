<script setup lang="ts">
import { ArrowLeft, CheckCircle2, FileClock, Network, Play, ShieldBan, UserPlus, X } from '~/utils/icons'
import { agentAnalysisResponseSchema, alertDetailSchema, ruleDetailSchema } from '~~/shared/schemas/security'
import type { AgentRuleProposal } from '~~/shared/schemas/security'
import type { AgentAnalysis } from '~~/shared/types/security'

const route = useRoute()
const id = computed(() => String(route.params.id))
const isMock = useRuntimeConfig().public.useMockApi
const activeTab = ref<'detection' | 'profile' | 'agent' | 'evidence'>('detection')
const successMessage = ref('')
const alertAction = ref<'assign' | 'contain' | null>(null)
const actionError = ref('')
const agentAnalysis = ref<AgentAnalysis | null>(null)
const proposedRule = ref<AgentRuleProposal | null>(null)
const ruleSaving = ref(false)
const agentStatus = ref<'idle' | 'pending' | 'success' | 'error'>('idle')
const agentError = ref('')
const { data: detail, status, error, refresh } = await useAsyncData(() => `alert-${id.value}`, () => validatedFetch(`/alerts/${id.value}`, alertDetailSchema), { watch: [id] })
const hasCompletedAgent = computed(() =>
  detail.value?.agent.state === 'completed' && !detail.value.agent.runId.startsWith('AGENT-NOT-RUN-'),
)
const trustedEvidenceCount = computed(() =>
  agentAnalysis.value?.evidenceIds.length
  ?? detail.value?.rag.filter((item) => item.usedByAgent).length
  ?? 0,
)
const statusLabels: Record<string, string> = { new: '待研判', investigating: '调查中', contained: '已遏制', closed: '已关闭' }
const tabs = [
  { id: 'detection', label: '检测证据' }, { id: 'profile', label: '异常画像' }, { id: 'agent', label: 'Agent 研判' }, { id: 'evidence', label: 'RAG 证据' },
] as const
function act(message: string) { successMessage.value = message; setTimeout(() => successMessage.value = '', 2600) }
const agentDuration = computed(() => agentAnalysis.value?.steps.reduce((total, step) => total + step.durationMs, 0) ?? 0)

async function updateAlert(
  nextAction: 'assign' | 'contain',
  body: Record<string, string>,
  message: string,
) {
  if (alertAction.value || !detail.value) return
  alertAction.value = nextAction
  actionError.value = ''
  try {
    detail.value = await validatedFetch(`/alerts/${id.value}`, alertDetailSchema, {
      method: 'PATCH',
      body,
    })
    act(message)
  } catch (error) {
    const value = error as { data?: { statusMessage?: string; message?: string }; message?: string }
    actionError.value =
      value.data?.statusMessage || value.data?.message || value.message || '告警操作失败，请稍后重试。'
  } finally {
    alertAction.value = null
  }
}

async function runAgent() {
  if (!detail.value || agentStatus.value === 'pending') return
  const seed = agentAnalysis.value ?? detail.value.agent
  agentAnalysis.value = {
    ...seed,
    state: 'running',
    hypothesis: agentAnalysis.value?.hypothesis ?? '正在结合双通道结果与可信证据构建攻击假设。',
    summary: agentAnalysis.value?.summary ?? `Agent 正在读取结构化画像，并仅使用标记为实际采用的 ${trustedEvidenceCount.value} 条证据。`,
    recommendation: agentAnalysis.value?.recommendation ?? '等待模式比较、规则策略和验证建议完成。',
    steps: seed.steps.map((step, index) => ({
      ...step,
      state: index === 0 ? 'active' : 'pending',
      durationMs: 0,
      result: index === 0 ? '正在校验画像字段…' : '等待前序工具完成',
    })),
  }
  agentStatus.value = 'pending'
  agentError.value = ''
  try {
    const result = await validatedFetch('/agent/analyze', agentAnalysisResponseSchema, {
      method: 'POST', body: { alertId: id.value, profile: detail.value.profile },
    })
    const { proposedRule: proposal, ...analysis } = result
    agentAnalysis.value = analysis
    proposedRule.value = proposal ?? null
    if (result.state === 'completed') {
      agentStatus.value = 'success'
      act('DeepSeek V4 Pro 研判完成，证据与步骤已更新')
    } else {
      agentStatus.value = 'error'
      agentError.value = result.state === 'failed' ? 'Agent 已返回失败状态，请检查失败节点后重试。' : 'Agent 返回非终态结果，请重新运行。'
    }
  } catch {
    agentStatus.value = 'error'
    agentError.value = 'Agent 服务未返回通过契约校验的结果；画像与证据仍保持只读。'
    if (agentAnalysis.value) {
      agentAnalysis.value = {
        ...agentAnalysis.value,
        state: 'failed',
        steps: agentAnalysis.value.steps.map((step) => step.state === 'active'
          ? { ...step, state: 'failed', result: '服务响应失败或未通过输出契约校验' }
          : step),
      }
    }
  }
}

async function saveProposedRule() {
  if (!proposedRule.value || ruleSaving.value) return
  if (isMock) {
    actionError.value = '演示模式仅预览 Agent 提案；启动真实后端后可将候选规则写入数据库。'
    return
  }
  ruleSaving.value = true
  actionError.value = ''
  try {
    const created = await validatedFetch('/rules', ruleDetailSchema, {
      method: 'POST',
      body: {
        structured: proposedRule.value.structured,
        sourceAlertId: proposedRule.value.sourceAlertId,
        rationale: proposedRule.value.rationale,
        author: 'DeepSeek V4 Pro',
        source: 'agent',
      },
    })
    act(`候选规则 ${created.record.id} 已创建，请在规则页完成回放验证与人工确认`)
    proposedRule.value = null
    refresh()
  } catch (error) {
    const value = error as { data?: { statusMessage?: string; message?: string }; message?: string }
    actionError.value =
      value.data?.statusMessage || value.data?.message || value.message || '候选规则保存失败，请稍后重试。'
  } finally {
    ruleSaving.value = false
  }
}

async function selectTab(tab: typeof activeTab.value) {
  activeTab.value = tab
  if (tab === 'agent' && agentStatus.value === 'idle') {
    if (hasCompletedAgent.value && detail.value) {
      agentAnalysis.value = detail.value.agent
      agentStatus.value = 'success'
    } else {
      await runAgent()
    }
  }
}

watch(id, () => {
  activeTab.value = 'detection'
  agentAnalysis.value = null
  proposedRule.value = null
  ruleSaving.value = false
  agentStatus.value = 'idle'
  agentError.value = ''
})
</script>

<template>
  <div class="detail-page">
    <NuxtLink to="/alerts" class="back-link"><ArrowLeft :size="14" />返回告警队列</NuxtLink>
    <LoadingState v-if="status === 'pending'" :rows="8" />
    <ErrorState v-else-if="error || !detail" title="无法加载告警详情" @retry="refresh" />
    <template v-else>
      <div v-if="successMessage" class="success-toast" role="status"><CheckCircle2 :size="15" />{{ successMessage }}<button aria-label="关闭提示" @click="successMessage = ''"><X :size="13" /></button></div>
      <div v-if="actionError" class="success-toast error-toast" role="alert">{{ actionError }}<button aria-label="关闭错误提示" @click="actionError = ''"><X :size="13" /></button></div>
      <header class="detail-header">
        <div class="title-row"><SeverityBadge :level="detail.alert.severity" /><h1>{{ detail.alert.title }}</h1><StatusIndicator :status="detail.alert.status" :label="statusLabels[detail.alert.status]" /></div>
        <p><code>{{ detail.alert.id }}</code><span>·</span>{{ detail.alert.category }}<span>·</span>{{ detail.alert.sensor }}<span>·</span><code>{{ detail.alert.timestamp }}</code></p>
        <div class="detail-actions"><button :disabled="alertAction !== null" @click="updateAlert('assign', { owner: '当前分析师', actor: '当前分析师', note: '从告警详情页认领' }, '告警已分派给当前分析师')"><UserPlus :size="13" />{{ alertAction === 'assign' ? '分派中…' : '分派给我' }}</button><button :disabled="alertAction !== null || detail.alert.status === 'contained' || detail.alert.status === 'closed'" @click="updateAlert('contain', { status: 'contained', actor: '当前分析师', note: '已创建 30 分钟临时遏制策略，等待复核永久策略。' }, '告警已遏制，审计记录已写入')"><ShieldBan :size="13" />{{ alertAction === 'contain' ? '执行中…' : '临时遏制' }}</button><button class="primary" @click="selectTab('agent')"><Play :size="13" />{{ hasCompletedAgent ? '查看 Agent 研判' : '运行 Agent 研判' }}</button></div>
      </header>

      <section class="entity-strip">
        <div><span>源实体</span><b class="mono">{{ detail.profile.src_ip }}:{{ detail.profile.src_port }}</b></div><i>→</i><div><span>目的实体</span><b class="mono">{{ detail.profile.dst_ip }}:{{ detail.profile.dst_port }}</b></div><div><span>协议 / 服务</span><b>{{ detail.profile.protocol }} · {{ detail.profile.service }}</b></div><div><span>Flow</span><b class="mono">{{ detail.profile.flow_id }}</b></div><div><span>负责人</span><b>{{ detail.alert.owner || '未分派' }}</b></div>
      </section>

      <nav class="detail-tabs" aria-label="告警详情视图">
        <button v-for="tab in tabs" :key="tab.id" :class="{ active: activeTab === tab.id }" @click="selectTab(tab.id)">{{ tab.label }}<span v-if="tab.id === 'evidence'">{{ detail.rag.filter((item) => item.usedByAgent).length }}</span></button>
      </nav>

      <div v-if="activeTab === 'detection'" class="tab-content">
        <DualChannelEvidence :transformer="detail.transformer" :auto-encoder="detail.autoEncoder" :fusion="detail.fusion" />
        <div class="detection-lower">
          <section class="feature-evidence surface-panel"><div class="panel-title"><h2>关键异常特征</h2><span>对融合风险的贡献排序</span></div><div class="feature-rows"><div v-for="item in detail.transformer.abnormalFeatures" :key="item.field"><code>{{ item.field }}</code><b class="mono">{{ item.value }}</b><i><span :style="{ width: `${item.contribution * 250}%` }" /></i><em class="mono">{{ Math.round(item.contribution * 100) }}%</em></div></div></section>
          <section class="evidence-summary surface-panel"><div class="panel-title"><h2>原始检测证据</h2><span>由传感器写入，不经 Agent 改写</span></div><ul><li v-for="item in detail.alert.evidence" :key="item"><CheckCircle2 :size="13" />{{ item }}</li></ul><button @click="activeTab = 'profile'"><Network :size="13" />查看完整 Flow 画像</button></section>
        </div>
      </div>
      <div v-else-if="activeTab === 'profile'" class="tab-content"><AnomalyProfileView :profile="detail.profile" /></div>
      <div v-else-if="activeTab === 'agent'" class="tab-content agent-layout">
        <section class="agent-work surface-panel">
          <LoadingState v-if="agentStatus === 'pending' && !agentAnalysis" :rows="6" label="DeepSeek V4 Pro 正在读取画像并检索证据" />
          <div v-if="agentStatus === 'pending'" class="agent-run-notice" role="status"><span /><b>Agent 工作流运行中</b><em>节点会按工具执行结果更新，不展示隐藏思维链</em></div>
          <AgentPanel v-if="agentAnalysis" :analysis="agentAnalysis" :proposed-rule="proposedRule" :saving="ruleSaving" :can-persist="!isMock" @save-rule="saveProposedRule" />
          <ErrorState v-if="agentStatus === 'error'" title="Agent 研判失败" :description="agentError" @retry="runAgent" />
        </section>
        <aside class="agent-side surface-panel"><h2>关联对象</h2>
          <NuxtLink v-if="detail.relatedRule?.recordId" :to="`/rules/${detail.relatedRule.recordId}`"><span>{{ detail.relatedRule.label }}</span><b class="mono">{{ detail.relatedRule.ruleId }}</b></NuxtLink>
          <div v-else-if="detail.relatedRule" class="related-static"><span>{{ detail.relatedRule.label }}</span><b class="mono">{{ detail.relatedRule.ruleId }}</b></div>
          <button @click="selectTab('evidence')"><span>实际采用的 RAG 证据</span><b>{{ trustedEvidenceCount }} 条</b></button>
          <button :disabled="agentStatus === 'pending'" @click="runAgent"><span>重新运行 Agent</span><b>{{ agentStatus === 'pending' ? '运行中…' : '执行' }}</b></button>
          <div><FileClock :size="14" /><span>本次运行总耗时</span><b class="mono">{{ (agentDuration / 1000).toFixed(2) }} s</b></div>
          <p>DeepSeek V4 Pro 只读取结构化画像与实际授权的 {{ trustedEvidenceCount }} 条证据，不直接处理原始流量。</p>
        </aside>
      </div>
      <div v-else class="tab-content"><RagEvidenceList :items="detail.rag" :query="detail.ragQuery" :top-k="detail.rag.filter((item) => item.allowed).length" /></div>
    </template>
  </div>
</template>

<style scoped>
.detail-page { padding: 16px 22px 30px; }.back-link { display: inline-flex; align-items: center; gap: 5px; margin-bottom: 12px; color: var(--text-tertiary); font-size:13px; text-decoration: none; }.back-link:hover { color: var(--text-primary); }.success-toast { position: fixed; z-index: 50; top: 64px; right: 18px; display: flex; align-items: center; gap: 7px; padding: 9px 11px; border: 1px solid color-mix(in srgb, var(--status-success) 38%, var(--border-default)); border-radius: 8px; background: var(--surface-2); color: var(--status-success); font-size:13px; box-shadow: 0 10px 26px rgba(0,0,0,.2); }.success-toast button { display: grid; place-items: center; border: 0; background: transparent; color: var(--text-tertiary); cursor: pointer; }
.error-toast { border-color: color-mix(in srgb, var(--status-error) 38%, var(--border-default)); color: var(--status-error); }
.detail-header { position: relative; margin-bottom: 12px; }.title-row { display: flex; align-items: center; gap: 9px; }.title-row h1 { margin: 0; font-size: 21px; font-weight: 650; }.detail-header > p { display: flex; gap: 7px; margin: 5px 0 0; color: var(--text-tertiary); font-size:13px; }.detail-header code { color: var(--text-secondary); font-size:13px; }.detail-actions { position: absolute; top: 0; right: 0; display: flex; gap: 6px; }.detail-actions button { display: flex; align-items: center; gap: 5px; height: 32px; padding: 0 8px; border: 1px solid var(--border-default); border-radius: 7px; background: var(--surface-1); color: var(--text-secondary); font-size:13px; cursor: pointer; }.detail-actions button.primary { border-color: color-mix(in srgb, var(--accent) 48%, var(--border-default)); background: var(--accent-muted); color: var(--accent-strong); }
.detail-actions button:disabled { cursor: not-allowed; opacity: .55; }
.entity-strip { display: grid; grid-template-columns: 1fr 20px 1fr .7fr 1.15fr .6fr; align-items: center; margin-bottom: 12px; border-block: 1px solid var(--border-default); background: var(--surface-1); }.entity-strip > div { min-width: 0; padding: 9px 12px; border-right: 1px solid var(--border-subtle); }.entity-strip > div:last-child { border-right: 0; }.entity-strip > i { color: var(--accent-strong); font-style: normal; text-align: center; }.entity-strip span,.entity-strip b { display: block; }.entity-strip span { color: var(--text-tertiary); font-size:12px; }.entity-strip b { margin-top: 2px; overflow: hidden; color: var(--text-secondary); font-size:13px; font-weight: 550; text-overflow: ellipsis; white-space: nowrap; }
.detail-tabs { display: flex; gap: 2px; margin-bottom: 12px; border-bottom: 1px solid var(--border-default); }.detail-tabs button { position: relative; min-height: 35px; padding: 0 11px; border: 0; background: transparent; color: var(--text-tertiary); font-size:13px; cursor: pointer; }.detail-tabs button.active { color: var(--text-primary); }.detail-tabs button.active::after { position: absolute; right: 8px; bottom: -1px; left: 8px; height: 2px; background: var(--accent); content: ''; }.detail-tabs button span { margin-left: 4px; padding: 1px 4px; border-radius: 999px; background: var(--surface-3); font-size:12px; }.tab-content { animation: tab-in 160ms ease; } @keyframes tab-in { from { opacity: 0; transform: translateY(2px); } }
.detection-lower { display: grid; grid-template-columns: 1.35fr 1fr; gap: 12px; margin-top: 12px; }.panel-title { display: flex; justify-content: space-between; align-items: center; min-height: 41px; padding: 0 12px; border-bottom: 1px solid var(--border-subtle); }.panel-title h2 { margin: 0; font-size:14px; }.panel-title span { color: var(--text-tertiary); font-size:12px; }.feature-rows { padding: 7px 12px 10px; }.feature-rows > div { display: grid; grid-template-columns: minmax(150px,1fr) 75px 1fr 30px; gap: 8px; align-items: center; min-height: 28px; }.feature-rows code,.feature-rows b,.feature-rows em { font-size:13px; }.feature-rows b { color: var(--text-secondary); font-weight: 500; }.feature-rows em { color: var(--text-tertiary); font-style: normal; text-align: right; }.feature-rows i { height: 4px; background: var(--surface-3); }.feature-rows i span { display: block; height: 100%; background: var(--severity-info); }.evidence-summary ul { display: grid; gap: 7px; margin: 0; padding: 10px 12px; list-style: none; }.evidence-summary li { display: flex; gap: 6px; color: var(--text-secondary); font-size:13px; }.evidence-summary li svg { flex: 0 0 auto; color: var(--status-success); }.evidence-summary button { display: flex; align-items: center; justify-content: center; gap: 5px; width: 100%; min-height: 34px; border: 0; border-top: 1px solid var(--border-subtle); background: var(--surface-2); color: var(--accent-strong); font-size:13px; cursor: pointer; }
.agent-layout { display: grid; grid-template-columns: minmax(0,1fr) 245px; gap: 12px; }.agent-work { min-width: 0; overflow: hidden; }.agent-work :deep(.agent-panel) { border: 0; }.agent-run-notice { display: flex; align-items: center; gap: 6px; min-height: 33px; padding: 0 12px; border-bottom: 1px solid var(--border-subtle); background: color-mix(in srgb,var(--status-warning) 6%,var(--surface-2)); color: var(--status-warning); font-size:12px; }.agent-run-notice span { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }.agent-run-notice em { margin-left: auto; color: var(--text-tertiary); font-style: normal; }.agent-side { overflow: hidden; }.agent-side h2 { margin: 0; padding: 10px 12px; border-bottom: 1px solid var(--border-subtle); font-size:14px; }.agent-side > a,.agent-side > button,.agent-side > div { display: flex; justify-content: space-between; align-items: center; width: 100%; min-height: 49px; padding: 7px 12px; border: 0; border-bottom: 1px solid var(--border-subtle); background: transparent; color: var(--text-secondary); text-decoration: none; font-size:13px; cursor: pointer; text-align: left; }.agent-side > button:disabled { opacity: .55; cursor: wait; }.agent-side > div { justify-content: flex-start; gap: 7px; }.agent-side > div b { margin-left: auto; }.agent-side span,.agent-side b { display: block; }.agent-side b { color: var(--text-primary); font-size:13px; }.agent-side > p { margin: 0; padding: 11px 12px; color: var(--text-tertiary); font-size:12px; line-height: 1.55; }
@media (max-width: 1000px) { .detail-actions { position: static; margin-top: 10px; }.entity-strip { grid-template-columns: repeat(3,minmax(0,1fr)); align-items: stretch; }.entity-strip > i { display: none; }.entity-strip > div { border-bottom: 1px solid var(--border-subtle); }.agent-layout,.detection-lower { grid-template-columns: 1fr; } }
@media (max-width: 650px) { .detail-page { padding: 14px 12px 24px; }.title-row { align-items: flex-start; flex-wrap: wrap; }.title-row h1 { width: 100%; font-size: 18px; }.detail-actions { flex-wrap: wrap; }.detail-actions button { flex: 1 1 auto; justify-content: center; }.detail-header > p { flex-wrap: wrap; }.entity-strip { grid-template-columns: 1fr 1fr; }.entity-strip > div:last-child { grid-column: 1/-1; }.detail-tabs { overflow-x: auto; } }
</style>
