<script setup lang="ts">
import { ArrowLeft, Check, CheckCircle2, Copy, FileJson2, GitCompare, History, Play, Rocket, RotateCcw, ShieldCheck, ShieldX, XCircle } from '~/utils/icons'
import { z } from 'zod'
import { ruleDetailSchema } from '~~/shared/schemas/security'
import type { RuleStage } from '~~/shared/types/security'

const route = useRoute()
const id = computed(() => String(route.params.id))
const activeTab = ref<'rule' | 'validation' | 'diff' | 'evidence'>('rule')
const deployOpen = ref(false)
const dialogAction = ref<'repair' | 'reject' | 'deprecate' | null>(null)
const copied = ref(false)
const action = ref<string | null>(null)
const actionError = ref('')
const successMessage = ref('')

const timelineSchema = z.object({
  currentStage: z.enum(['candidate', 'validating', 'validated', 'rejected', 'repaired', 'confirmed', 'deployed', 'deprecated']),
  items: z.array(z.object({
    id: z.string(),
    stage: z.enum(['candidate', 'validating', 'validated', 'rejected', 'repaired', 'confirmed', 'deployed', 'deprecated']),
    timestamp: z.string(),
    actor: z.string(),
    summary: z.string(),
    note: z.string().optional(),
    outcome: z.enum(['completed', 'failed']),
  })),
})

const { data: detail, status, error, refresh } = await useAsyncData(
  () => `rule-${id.value}`,
  () => validatedFetch(`/rules/${id.value}`, ruleDetailSchema),
  { watch: [id] },
)
const { data: timeline, error: timelineError, refresh: refreshTimeline } = await useAsyncData(
  () => `rule-timeline-${id.value}`,
  () => validatedFetch(`/rules/${id.value}/timeline`, timelineSchema),
  { watch: [id] },
)

const stageLabels: Record<RuleStage, string> = {
  candidate: 'Candidate', validating: 'Validating', validated: 'Validated', rejected: 'Rejected',
  repaired: 'Repaired', confirmed: 'Confirmed', deployed: 'Deployed', deprecated: 'Deprecated',
}
const normalStages: RuleStage[] = ['candidate', 'validating', 'validated', 'confirmed', 'deployed']
const repairableStages: RuleStage[] = ['rejected', 'validated', 'confirmed', 'deployed', 'deprecated']

const stageIndex = computed(() => detail.value ? normalStages.indexOf(detail.value.record.stage) : -1)
const isBusy = computed(() => action.value !== null)

function readError(error: unknown) {
  const value = error as { data?: { statusMessage?: string; message?: string }; statusMessage?: string; message?: string }
  return value?.data?.statusMessage || value?.data?.message || value?.statusMessage || value?.message || '操作失败，请重试。'
}

function showSuccess(message: string) {
  successMessage.value = message
  window.setTimeout(() => { successMessage.value = '' }, 4200)
}

async function runAction(endpoint: string, body: Record<string, string>, success: string) {
  action.value = endpoint
  actionError.value = ''
  try {
    const next = await validatedFetch(`/rules/${id.value}/${endpoint}`, ruleDetailSchema, { method: 'POST', body })
    detail.value = next
    await refreshTimeline()
    showSuccess(success)
    return true
  } catch (caught) {
    actionError.value = readError(caught)
    return false
  } finally {
    action.value = null
  }
}

async function copyRule() {
  if (!detail.value) return
  try {
    await navigator.clipboard.writeText(JSON.stringify(detail.value.structured, null, 2))
    copied.value = true
    window.setTimeout(() => { copied.value = false }, 1500)
  } catch {
    actionError.value = '浏览器未授予剪贴板权限，请从 JSON 面板手动复制。'
  }
}

async function advanceValidation() {
  if (!detail.value) return
  const completing = detail.value.record.stage === 'validating'
  await runAction('validate', { actor: 'Root' }, completing ? '回放验证完成，规则已进入 Validated。' : '规则已进入 Validating，等待回放结果。')
}

async function confirmValidated() {
  await runAction('confirm', { actor: 'Root', note: '已复核验证指标、证据与误报风险。' }, '人工确认完成。规则当前为 Confirmed，可进入部署审批。')
}

async function deploy(note: string) {
  const ok = await runAction('deploy', { actor: 'Root', note }, '部署审批已记录；检测平面下发需由独立执行器完成。')
  if (ok) deployOpen.value = false
}

function openLifecycleDialog(next: 'repair' | 'reject' | 'deprecate') {
  actionError.value = ''
  dialogAction.value = next
}

async function confirmLifecycle(reason: string) {
  if (!dialogAction.value) return
  const endpoint = dialogAction.value
  const messages = {
    repair: '修复版本已创建，必须重新完成回放验证。',
    reject: '规则已进入 Rejected，等待修复。',
    deprecate: '规则已从检测平面撤下并标记为 Deprecated。',
  }
  const ok = await runAction(endpoint, { actor: 'Root', reason }, messages[endpoint])
  if (ok) dialogAction.value = null
}
</script>

<template>
  <div class="rule-detail-page">
    <NuxtLink to="/rules" class="back-link"><ArrowLeft :size="15" />返回规则进化中心</NuxtLink>
    <LoadingState v-if="status === 'pending'" :rows="8" />
    <ErrorState v-else-if="error || !detail" title="无法加载规则详情" description="该规则不存在，或当前原型尚未提供一致的详情数据。" @retry="refresh" />
    <template v-else>
      <div v-if="successMessage" class="success-banner" role="status"><CheckCircle2 :size="15" />{{ successMessage }}</div>
      <div v-if="actionError && !deployOpen && !dialogAction" class="error-banner" role="alert"><XCircle :size="15" />{{ actionError }}</div>

      <header class="rule-header">
        <div><p><span :class="['stage-pill', `stage-${detail.record.stage}`]"><i />{{ stageLabels[detail.record.stage] }}</span><code>{{ detail.structured.rule_id }}</code> · version {{ detail.structured.version }} / revision {{ detail.record.revision }}</p><h1>{{ detail.structured.rule_name }}</h1><span>{{ detail.structured.description }}</span></div>
        <div class="header-actions">
          <button :disabled="isBusy" @click="copyRule"><component :is="copied ? Check : Copy" :size="14" />{{ copied ? '已复制' : '复制规则' }}</button>
          <button v-if="['candidate','repaired','validating'].includes(detail.record.stage)" class="primary" :disabled="isBusy" @click="advanceValidation"><Play :size="14" />{{ action === 'validate' ? '正在提交…' : detail.record.stage === 'validating' ? '完成回放验证' : '提交回放验证' }}</button>
          <button v-if="detail.record.stage === 'validating'" class="danger" :disabled="isBusy" @click="openLifecycleDialog('reject')"><XCircle :size="14" />驳回验证</button>
          <button v-if="detail.record.stage === 'validated'" class="primary" :disabled="isBusy" @click="confirmValidated"><ShieldCheck :size="14" />{{ action === 'confirm' ? '正在确认…' : '人工确认验证结果' }}</button>
          <button v-if="detail.record.stage === 'confirmed'" class="primary" :disabled="isBusy" @click="actionError='';deployOpen=true"><Rocket :size="14" />部署到检测平面</button>
          <button v-if="repairableStages.includes(detail.record.stage)" :disabled="isBusy" @click="openLifecycleDialog('repair')"><RotateCcw :size="14" />创建修复版本</button>
          <button v-if="detail.record.stage === 'deployed'" class="danger" :disabled="isBusy" @click="openLifecycleDialog('deprecate')"><ShieldX :size="14" />废弃规则</button>
        </div>
      </header>

      <section class="stage-gate" aria-label="正常部署门禁">
        <template v-for="(stage,index) in normalStages" :key="stage"><div :class="{ active: detail.record.stage === stage, complete: stageIndex > index || ['deployed','deprecated'].includes(detail.record.stage) }"><span>{{ index + 1 }}</span><b>{{ stageLabels[stage] }}</b></div><i v-if="index < normalStages.length - 1" /></template>
      </section>

      <section class="rule-meta"><div><span>攻击类型</span><b>{{ detail.structured.attack_type }}</b></div><div><span>ATT&CK</span><b class="mono">{{ detail.structured.mitre_technique_ids.join(', ') }}</b></div><div><span>来源告警</span><NuxtLink :to="`/alerts/${detail.sourceAlertId}`" class="mono">{{ detail.sourceAlertId }}</NuxtLink></div><div><span>生成来源</span><b>{{ detail.structured.generated_by }}</b></div><div><span>质量分</span><b class="mono good">{{ detail.validation.qualityScore }} / 100</b></div><div><span>父版本</span><b class="mono">{{ detail.structured.parent_rule_id || '根版本' }}</b></div></section>

      <nav class="rule-tabs" aria-label="规则详情视图"><button :class="{active:activeTab==='rule'}" :aria-pressed="activeTab==='rule'" @click="activeTab='rule'"><FileJson2 :size="14" />结构化规则</button><button :class="{active:activeTab==='validation'}" :aria-pressed="activeTab==='validation'" @click="activeTab='validation'"><ShieldCheck :size="14" />回放验证</button><button :class="{active:activeTab==='diff'}" :aria-pressed="activeTab==='diff'" @click="activeTab='diff'"><GitCompare :size="14" />Rule Diff</button><button :class="{active:activeTab==='evidence'}" :aria-pressed="activeTab==='evidence'" @click="activeTab='evidence'"><History :size="14" />证据与 Lineage</button></nav>

      <div v-if="activeTab === 'rule'" class="rule-content">
        <section class="conditions-panel surface-panel"><div class="panel-head"><div><h2>条件可视化</h2><p>所有条件必须同时满足（AND）</p></div><span>{{ detail.structured.conditions.length }} 个条件</span></div><div class="condition-flow"><template v-for="(condition,index) in detail.structured.conditions" :key="condition.field"><div class="condition-card"><span class="mono">{{ condition.field }}</span><b>{{ condition.operator }}</b><em class="mono">{{ condition.value }}</em></div><i v-if="index < detail.structured.conditions.length - 1">AND</i></template></div><dl><div><dt>攻击阶段</dt><dd>{{ detail.structured.attack_stage }}</dd></div><div><dt>危险等级</dt><dd><SeverityBadge :level="detail.structured.severity" /></dd></div><div><dt>父规则 / 版本</dt><dd class="mono">{{ detail.structured.parent_rule_id || '—' }}</dd></div><div><dt>关联证据</dt><dd>{{ detail.structured.evidence_ids.length }} 条</dd></div></dl></section>
        <section class="json-panel surface-panel"><div class="panel-head"><div><h2>规则 JSON</h2><p>Schema: <code>evonids.rule/v1</code></p></div><button @click="copyRule"><component :is="copied ? Check : Copy" :size="13" />{{ copied ? '已复制' : '复制' }}</button></div><pre><code>{{ JSON.stringify(detail.structured, null, 2) }}</code></pre></section>
      </div>

      <div v-else-if="activeTab === 'validation'" class="validation-content">
        <RuleValidationScore :validation="detail.validation" />
        <section class="checks-panel surface-panel"><div class="panel-head"><div><h2>验证检查项</h2><p>结构、语义、回放与证据一致性</p></div><span :class="['check-summary',{failed:detail.validation.schemaChecks.some((check)=>!check.passed)}]"><CheckCircle2 v-if="detail.validation.schemaChecks.every((check)=>check.passed)" :size="13" /><XCircle v-else :size="13" />{{ detail.validation.schemaChecks.every((check)=>check.passed) ? '全部通过' : '存在失败项' }}</span></div><div class="check-rows"><div v-for="check in detail.validation.schemaChecks" :key="check.label" :class="{failed:!check.passed}"><CheckCircle2 v-if="check.passed" :size="14" /><XCircle v-else :size="14" /><span><b>{{ check.label }}</b><small>{{ check.note }}</small></span></div></div><div class="robustness"><span>阈值扰动范围</span><code>destination_port_count_60s: 45–58</code><b>稳健性 {{ detail.validation.perturbationRobustness }}%</b></div></section>
      </div>

      <RuleDiff v-else-if="activeTab === 'diff' && detail.previousVersion" :before="detail.previousVersion" :after="detail.structured" :reason="detail.diffReason" :coverage-change="detail.expectedCoverageChange" :false-positive-risk="detail.falsePositiveRisk" />
      <EmptyState v-else-if="activeTab === 'diff'" title="当前版本没有父版本" description="产生修复版本后，这里会显示新增、删除和阈值变化。" />

      <div v-else class="evidence-content">
        <section class="surface-panel link-panel"><div class="panel-head"><div><h2>关联证据</h2><p>生成与验证均可追踪到来源</p></div></div><NuxtLink v-for="eid in detail.structured.evidence_ids" :key="eid" to="/knowledge"><span><CheckCircle2 :size="14" /><b class="mono">{{ eid }}</b></span><em>已授权 · 参与规则生成</em></NuxtLink><div class="lineage-summary"><span>当前版本</span><b class="mono">v{{ detail.structured.version }}</b><span>父版本</span><b class="mono">{{ detail.structured.parent_rule_id || '根版本' }}</b></div></section>
        <RuleTimeline v-if="timeline" :items="timeline.items" :current-stage="timeline.currentStage" />
        <ErrorState v-else-if="timelineError" title="生命周期记录加载失败" @retry="refreshTimeline" />
        <LoadingState v-else :rows="4" />
      </div>

      <DeployConfirmationDialog v-model:open="deployOpen" :detail="detail" :loading="action === 'deploy'" :error="deployOpen ? actionError : ''" @confirm="deploy" />
      <LifecycleConfirmationDialog v-if="dialogAction" :open="true" :action="dialogAction" :loading="action === dialogAction" :error="actionError" @update:open="(open) => { if (!open && !isBusy) dialogAction = null }" @confirm="confirmLifecycle" />
    </template>
  </div>
</template>

<style scoped>
.rule-detail-page{padding:16px 22px 30px}.back-link{display:inline-flex;align-items:center;gap:5px;margin-bottom:12px;color:var(--text-tertiary);font-size:12px;text-decoration:none}.success-banner,.error-banner{display:flex;align-items:center;gap:7px;margin-bottom:10px;padding:9px 11px;border:1px solid color-mix(in srgb,var(--status-success) 35%,var(--border-default));border-radius:7px;background:color-mix(in srgb,var(--status-success) 7%,transparent);color:var(--status-success);font-size:12px}.error-banner{border-color:color-mix(in srgb,var(--status-error) 35%,var(--border-default));background:color-mix(in srgb,var(--status-error) 7%,transparent);color:var(--status-error)}
.rule-header{display:flex;justify-content:space-between;gap:20px;margin-bottom:12px}.rule-header p,.rule-header h1,.rule-header>div>span{margin:0}.rule-header p{display:flex;align-items:center;gap:8px;color:var(--text-tertiary);font-size:14px}.rule-header h1{margin-top:6px;font-size:22px}.rule-header>div>span{display:block;margin-top:4px;color:var(--text-secondary);font-size:13px}.stage-pill{display:inline-flex!important;align-items:center;gap:5px;padding:3px 7px;border-radius:5px;background:var(--accent-muted);color:var(--accent-strong);font-size:14px}.stage-pill i{width:6px;height:6px;border-radius:50%;background:currentColor}.stage-pill.stage-deployed{color:var(--status-success);background:color-mix(in srgb,var(--status-success) 9%,transparent)}.stage-pill.stage-rejected,.stage-pill.stage-deprecated{color:var(--status-error);background:color-mix(in srgb,var(--status-error) 9%,transparent)}.stage-pill.stage-validating{color:var(--status-warning);background:color-mix(in srgb,var(--status-warning) 9%,transparent)}.header-actions{display:flex;gap:7px;align-items:flex-start;justify-content:flex-end;flex-wrap:wrap;max-width:520px}.header-actions button{display:flex;align-items:center;gap:5px;height:34px;padding:0 10px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-1);color:var(--text-secondary);font-size:12px;cursor:pointer}.header-actions button.primary{border-color:color-mix(in srgb,var(--accent) 52%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.header-actions button.danger{color:var(--status-error)}.header-actions button:disabled{cursor:wait;opacity:.55}
.stage-gate{display:grid;grid-template-columns:auto 1fr auto 1fr auto 1fr auto 1fr auto;align-items:center;margin-bottom:12px;padding:10px 14px;border-block:1px solid var(--border-default);background:var(--surface-1)}.stage-gate>div{display:flex;align-items:center;gap:6px;color:var(--text-tertiary)}.stage-gate>div span{display:grid;width:23px;height:23px;place-items:center;border:1px solid var(--border-default);border-radius:50%;font-size:14px}.stage-gate>div b{font-size:14px;font-weight:600}.stage-gate>div.active{color:var(--accent-strong)}.stage-gate>div.active span{border-color:var(--accent);background:var(--accent-muted)}.stage-gate>div.complete{color:var(--status-success)}.stage-gate>div.complete span{border-color:var(--status-success)}.stage-gate>i{height:1px;margin:0 9px;background:var(--border-default)}
.rule-meta{display:grid;grid-template-columns:.75fr .75fr .85fr 1fr .65fr 1fr;margin-bottom:12px;border-block:1px solid var(--border-default);background:var(--surface-1)}.rule-meta>div{min-width:0;padding:9px 11px;border-right:1px solid var(--border-subtle)}.rule-meta>div:last-child{border-right:0}.rule-meta span,.rule-meta b,.rule-meta a{display:block}.rule-meta span{color:var(--text-tertiary);font-size:14px}.rule-meta b,.rule-meta a{margin-top:3px;overflow:hidden;color:var(--text-secondary);font-size:12px;font-weight:550;text-overflow:ellipsis;white-space:nowrap}.rule-meta a{color:var(--accent-strong);text-decoration:none}.rule-meta b.good{color:var(--status-success)}
.rule-tabs{display:flex;gap:3px;margin-bottom:12px;border-bottom:1px solid var(--border-default)}.rule-tabs button{position:relative;display:flex;align-items:center;gap:5px;min-height:39px;padding:0 12px;border:0;background:transparent;color:var(--text-tertiary);font-size:12px;cursor:pointer}.rule-tabs button.active{color:var(--text-primary)}.rule-tabs button.active::after{position:absolute;right:9px;bottom:-1px;left:9px;height:2px;background:var(--accent);content:''}
.rule-content{display:grid;grid-template-columns:1.1fr .9fr;gap:12px}.conditions-panel,.json-panel,.checks-panel,.link-panel{overflow:hidden}.panel-head{display:flex;justify-content:space-between;align-items:center;min-height:54px;padding:9px 13px;border-bottom:1px solid var(--border-subtle)}.panel-head h2,.panel-head p{margin:0}.panel-head h2{font-size:14px}.panel-head p{margin-top:3px;color:var(--text-tertiary);font-size:14px}.panel-head>span{color:var(--text-tertiary);font-size:14px}.panel-head button{display:flex;align-items:center;gap:4px;padding:5px 7px;border:1px solid var(--border-default);border-radius:5px;background:var(--surface-2);color:var(--text-secondary);font-size:14px;cursor:pointer}.condition-flow{display:flex;align-items:stretch;gap:6px;overflow-x:auto;padding:14px}.condition-card{flex:1;min-width:145px;padding:9px;border-left:2px solid var(--accent);background:var(--surface-2)}.condition-card span,.condition-card b,.condition-card em{display:block}.condition-card span{overflow:hidden;color:var(--text-secondary);font-size:14px;text-overflow:ellipsis}.condition-card b{margin-top:5px;color:var(--accent-strong);font-size:13px}.condition-card em{color:var(--text-primary);font-size:13px;font-style:normal}.condition-flow>i{align-self:center;color:var(--text-tertiary);font-size:13px;font-style:normal}.conditions-panel dl{display:grid;grid-template-columns:1fr 1fr;margin:0;border-top:1px solid var(--border-subtle)}.conditions-panel dl div{display:flex;justify-content:space-between;align-items:center;min-height:39px;padding:6px 11px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.conditions-panel dt,.conditions-panel dd{font-size:14px}.conditions-panel dt{color:var(--text-tertiary)}.conditions-panel dd{margin:0;color:var(--text-secondary)}.json-panel pre{height:320px;margin:0;padding:13px;overflow:auto;background:#0a1017;color:#b8c6d8;font-size:12px;line-height:1.6;white-space:pre-wrap}.validation-content{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(300px,.65fr);gap:12px}.check-summary{display:flex;align-items:center;gap:4px;color:var(--status-success)!important}.check-summary.failed{color:var(--status-error)!important}.check-rows>div{display:flex;gap:8px;align-items:center;min-height:50px;padding:7px 12px;border-bottom:1px solid var(--border-subtle);color:var(--status-success)}.check-rows>div.failed{color:var(--status-error)}.check-rows b,.check-rows small{display:block}.check-rows b{color:var(--text-primary);font-size:12px}.check-rows small{margin-top:2px;color:var(--text-tertiary);font-size:14px}.robustness{display:grid;gap:3px;padding:10px 12px;background:var(--surface-2)}.robustness span,.robustness code,.robustness b{font-size:14px}.robustness span{color:var(--text-tertiary)}.robustness b{color:var(--status-success)}
.evidence-content{display:grid;grid-template-columns:minmax(280px,.7fr) minmax(0,1.3fr);gap:12px}.link-panel>a{display:flex;justify-content:space-between;align-items:center;min-height:48px;padding:8px 12px;border-bottom:1px solid var(--border-subtle);color:var(--text-secondary);text-decoration:none}.link-panel>a span{display:flex;align-items:center;gap:6px}.link-panel>a svg{color:var(--status-success)}.link-panel>a b,.link-panel>a em{font-size:14px}.link-panel>a em{color:var(--text-tertiary);font-style:normal}.lineage-summary{display:grid;grid-template-columns:auto 1fr;gap:5px 10px;padding:12px}.lineage-summary span{color:var(--text-tertiary);font-size:14px}.lineage-summary b{font-size:14px}
@media(max-width:1000px){.rule-header{flex-direction:column}.header-actions{justify-content:flex-start;max-width:none}.rule-meta{grid-template-columns:repeat(3,1fr)}.rule-content,.validation-content,.evidence-content{grid-template-columns:1fr}}@media(max-width:700px){.rule-detail-page{padding:14px 12px 24px}.stage-gate{display:flex;overflow-x:auto;gap:8px}.stage-gate>i{flex:0 0 28px}.stage-gate>div{flex:0 0 auto}.rule-meta{grid-template-columns:1fr 1fr}.rule-tabs{overflow-x:auto}.rule-tabs button{white-space:nowrap}.rule-header h1{font-size:20px}}
</style>
