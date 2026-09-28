<script setup lang="ts">
import { z } from 'zod'
import { CheckCircle2, Copy, Play, RefreshCw, Rocket, RotateCcw, ShieldAlert, ShieldCheck, TriangleAlert, X, XCircle } from '~/utils/icons'
import {
  ruleDeploymentCreateRequestSchema,
  ruleDeploymentPromoteRequestSchema,
  ruleDeploymentRollbackRequestSchema,
  ruleDeploymentSchema,
  ruleIRVersionSchema,
  ruleSandboxRunSchema,
  ruleDeploymentsResponseSchema,
  sandboxCapabilitySchema,
  sensorGroupSchema,
  type ruleSandboxMetricsSchema,
  type RuleDeploymentApiResponse,
  type RuleIRVersionApiResponse,
  type RuleSandboxRunApiResponse,
  type SandboxCapabilityApiResponse,
  type SensorGroupApiResponse,
} from '~~/shared/schemas/security'
import { formatSandboxMetric } from '~/utils/formatSandboxMetric'

const zVersionListSchema = z.array(ruleIRVersionSchema)
const zSandboxRunListSchema = z.array(ruleSandboxRunSchema)
const zSensorGroupListSchema = z.array(sensorGroupSchema)

const props = defineProps<{ ruleId: string }>()
const isMock = useRuntimeConfig().public.useMockApi

// ---- data state -------------------------------------------------------------
const capability = ref<SandboxCapabilityApiResponse | null>(null)
const capabilityState = ref<'idle' | 'loading' | 'error'>('idle')
const capabilityError = ref('')

const versions = ref<RuleIRVersionApiResponse[]>([])
const versionsState = ref<'idle' | 'loading' | 'error'>('idle')
const versionsError = ref('')

const runs = ref<RuleSandboxRunApiResponse[]>([])
const runsState = ref<'idle' | 'loading' | 'error'>('idle')
const runsError = ref('')

const deployments = ref<RuleDeploymentApiResponse[]>([])
const deploymentsState = ref<'idle' | 'loading' | 'error'>('idle')
const deploymentsError = ref('')

const groups = ref<SensorGroupApiResponse[]>([])
const groupsState = ref<'idle' | 'loading' | 'error'>('idle')
const groupsError = ref('')

const irJson = ref('')
const irSid = ref<'' | number>('')
const compiling = ref(false)
const runningSandbox = ref('')
const notice = ref('')
const actionError = ref('')
const copied = ref('')

// dialog state ----------------------------------------------------------------
type DialogKind = 'deploy' | 'promote' | 'rollback'
const dialogOpen = ref(false)
const dialogKind = ref<DialogKind | null>(null)
const dialogContextId = ref('') // versionId for deploy, deploymentId for promote/rollback
const dialogState = ref<'canary' | 'deployed'>('canary')
const dialogGroupId = ref('')
const dialogNote = ref('')
const dialogReason = ref('')
const dialogError = ref('')
const dialogSubmitting = ref(false)

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
  window.setTimeout(() => { if (notice.value === text) notice.value = '' }, 4200)
}

async function loadCapability() {
  capabilityState.value = 'loading'
  capabilityError.value = ''
  try {
    capability.value = await validatedFetch('/rule-governance/sandbox-capability', sandboxCapabilitySchema)
    capabilityState.value = 'idle'
  } catch (error) {
    capabilityError.value = readError(error)
    capabilityState.value = 'error'
  }
}

async function loadVersions() {
  versionsState.value = 'loading'
  versionsError.value = ''
  try {
    versions.value = await validatedFetch(`/rule-governance/rules/${encodeURIComponent(props.ruleId)}/versions`, zVersionListSchema)
    versionsState.value = 'idle'
  } catch (error) {
    versionsError.value = readError(error)
    versionsState.value = 'error'
  }
}

async function loadRuns() {
  runsState.value = 'loading'
  runsError.value = ''
  try {
    const list = await validatedFetch(`/rule-governance/rules/${encodeURIComponent(props.ruleId)}/sandbox-runs`, zSandboxRunListSchema, { query: { limit: '10' } })
    runs.value = list
    runsState.value = 'idle'
  } catch (error) {
    runsError.value = readError(error)
    runsState.value = 'error'
  }
}

async function loadDeployments() {
  deploymentsState.value = 'loading'
  deploymentsError.value = ''
  try {
    const response = await validatedFetch(`/rule-governance/rules/${encodeURIComponent(props.ruleId)}/deployments`, ruleDeploymentsResponseSchema)
    deployments.value = response.items
    deploymentsState.value = 'idle'
  } catch (error) {
    deploymentsError.value = readError(error)
    deploymentsState.value = 'error'
  }
}

async function loadGroups() {
  groupsState.value = 'loading'
  groupsError.value = ''
  try {
    groups.value = await validatedFetch('/rule-governance/sensor-groups', zSensorGroupListSchema)
    groupsState.value = 'idle'
  } catch (error) {
    groupsError.value = readError(error)
    groupsState.value = 'error'
  }
}

function loadAll() {
  void loadCapability()
  void loadVersions()
  void loadRuns()
  void loadDeployments()
  void loadGroups()
}
onMounted(() => { if (!isMock) loadAll() })

// ---- compile IR --------------------------------------------------------------
async function compileIr() {
  if (compiling.value || isMock) return
  compiling.value = true
  actionError.value = ''
  try {
    let ir: unknown
    try {
      ir = JSON.parse(irJson.value)
    } catch {
      throw new Error('IR 不是合法的 JSON，请检查后重试。')
    }
    if (ir === null || typeof ir !== 'object' || Array.isArray(ir)) {
      throw new Error('IR 必须是 JSON 对象（如 { version, rules, … }）。')
    }
    const sid = irSid.value === '' ? undefined : irSid.value
    if (sid !== undefined && (!Number.isInteger(sid) || sid < 1)) {
      throw new Error('SID 必须是正整数。')
    }
    await validatedFetch(`/rule-governance/rules/${encodeURIComponent(props.ruleId)}/versions`, ruleIRVersionSchema, {
      method: 'POST',
      body: { ir, sid },
    })
    irJson.value = ''
    irSid.value = ''
    showNotice('IR 编译成功，规则版本已创建。')
    await loadVersions()
    await loadRuns()
  } catch (error) {
    actionError.value = readError(error)
  } finally {
    compiling.value = false
  }
}

// ---- sandbox run -------------------------------------------------------------
async function runSandbox(versionId: string) {
  if (runningSandbox.value || isMock) return
  runningSandbox.value = versionId
  actionError.value = ''
  try {
    const created = await validatedFetch(
      `/rule-governance/rules/${encodeURIComponent(props.ruleId)}/versions/${encodeURIComponent(versionId)}/sandbox`,
      ruleSandboxRunSchema,
      { method: 'POST', body: {} },
    )
    showNotice(`沙箱验证完成：${sandboxStatusLabels[created.status] ?? created.status}`)
    await loadRuns()
  } catch (error) {
    actionError.value = readError(error)
  } finally {
    runningSandbox.value = ''
  }
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = text.slice(0, 24)
    window.setTimeout(() => { copied.value = '' }, 1500)
  } catch {
    actionError.value = '浏览器未授予剪贴板权限。'
  }
}

// ---- dialogs ------------------------------------------------------------------
function openDeployDialog(versionId: string) {
  actionError.value = ''
  dialogKind.value = 'deploy'
  dialogContextId.value = versionId
  dialogState.value = 'canary'
  dialogGroupId.value = ''
  dialogNote.value = ''
  dialogReason.value = ''
  dialogError.value = ''
  dialogOpen.value = true
}
function openPromoteDialog(deployment: RuleDeploymentApiResponse) {
  actionError.value = ''
  dialogKind.value = 'promote'
  dialogContextId.value = deployment.id
  dialogGroupId.value = ''
  dialogNote.value = ''
  dialogReason.value = ''
  dialogError.value = ''
  dialogOpen.value = true
}
function openRollbackDialog(deployment: RuleDeploymentApiResponse) {
  actionError.value = ''
  dialogKind.value = 'rollback'
  dialogContextId.value = deployment.id
  dialogReason.value = ''
  dialogNote.value = ''
  dialogGroupId.value = ''
  dialogError.value = ''
  dialogOpen.value = true
}
function closeDialog() {
  if (dialogSubmitting.value) return
  dialogOpen.value = false
  dialogKind.value = null
}

async function submitDialog() {
  if (!dialogKind.value || dialogSubmitting.value) return
  dialogSubmitting.value = true
  dialogError.value = ''
  try {
    if (dialogKind.value === 'deploy') {
      const parsed = ruleDeploymentCreateRequestSchema.safeParse({
        ruleVersionId: dialogContextId.value,
        sensorGroupId: dialogGroupId.value,
        state: dialogState.value,
        note: dialogNote.value || undefined,
      })
      if (!parsed.success || !dialogGroupId.value) {
        throw new Error('请选择传感器组后再部署。')
      }
      await validatedFetch(`/rule-governance/rules/${encodeURIComponent(props.ruleId)}/deployments`, ruleDeploymentSchema, {
        method: 'POST',
        body: parsed.data,
      })
      showNotice(dialogState.value === 'canary' ? '金丝雀部署已创建。' : '规则已部署到生产组。')
    } else if (dialogKind.value === 'promote') {
      const parsed = ruleDeploymentPromoteRequestSchema.safeParse({
        note: dialogNote.value || undefined,
        targetGroupId: dialogGroupId.value || undefined,
      })
      if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? '提升参数无效')
      await validatedFetch(`/rule-governance/deployments/${encodeURIComponent(dialogContextId.value)}/promote`, ruleDeploymentSchema, {
        method: 'POST',
        body: parsed.data,
      })
      showNotice('金丝雀部署已提升为生产部署。')
    } else {
      const reason = dialogReason.value.trim()
      if (reason.length < 10) throw new Error('回滚原因至少需要 10 个字符。')
      const parsed = ruleDeploymentRollbackRequestSchema.safeParse({ reason })
      if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? '回滚原因无效')
      await validatedFetch(`/rule-governance/deployments/${encodeURIComponent(dialogContextId.value)}/rollback`, ruleDeploymentSchema, {
        method: 'POST',
        body: parsed.data,
      })
      showNotice('部署已回滚，原因已写入记录。')
    }
    dialogOpen.value = false
    dialogKind.value = null
    await loadDeployments()
  } catch (error) {
    dialogError.value = readError(error)
  } finally {
    dialogSubmitting.value = false
  }
}

// ---- display helpers -----------------------------------------------------------
const sandboxStatusLabels: Record<RuleSandboxRunApiResponse['status'], string> = {
  blocked: '未执行（被阻止）',
  partial: '部分通过',
  validated: '验证通过',
  validation_failed: '验证失败',
  failed: '执行失败',
}
const deploymentStateLabels: Record<RuleDeploymentApiResponse['state'], string> = {
  canary: '金丝雀',
  deployed: '已部署',
  rolled_back: '已回滚',
}
const stageLabels = { canary: '金丝雀', production: '生产' }

const metricLabels: Record<string, string> = {
  normalFlows: '正常流数',
  maliciousFlows: '恶意流数',
  truePositives: '真正例',
  falsePositives: '误报',
  falseNegatives: '漏报',
  recall: '召回率',
  precision: '精确率',
  f1: 'F1',
  falsePositiveRate: '误报率',
  falsePositivesPerMillion: '每百万误报',
  replaySeconds: '重放耗时(s)',
  peakRssKb: '峰值内存(KB)',
}

const metricKeys = [
  'normalFlows', 'maliciousFlows', 'truePositives', 'falsePositives', 'falseNegatives',
  'recall', 'precision', 'f1', 'falsePositiveRate', 'falsePositivesPerMillion',
  'replaySeconds', 'peakRssKb',
] as const

function metricRows(metrics: z.infer<typeof ruleSandboxMetricsSchema>) {
  return metricKeys.map((key) => {
    const value = metrics[key]
    const view = formatSandboxMetric(value, metrics.measured[key])
    return { key, label: metricLabels[key], view }
  })
}
function groupName(groupId: string): string {
  return groups.value.find((group) => group.id === groupId)?.name ?? groupId
}
function deploymentVersionLabel(versionId: string): string {
  const found = versions.value.find((version) => version.id === versionId)
  return found ? `v${found.version}` : versionId
}
</script>

<template>
  <section class="governance" aria-label="规则治理">
    <div v-if="isMock" class="demo-banner" role="note">
      <TriangleAlert :size="15" /><div><b>演示模式：规则治理为只读占位</b><p>IR 编译、Suricata 沙箱验证与部署均需要真实后端；此处不伪造版本、验证指标或部署状态。</p></div>
    </div>

    <div v-if="notice" class="gov-toast" role="status"><CheckCircle2 :size="14" />{{ notice }}</div>
    <div v-if="actionError" class="gov-error" role="alert"><XCircle :size="14" />{{ actionError }}</div>

    <template v-if="!isMock">
      <section class="capability surface-panel" aria-label="沙箱能力">
        <LoadingState v-if="capabilityState === 'loading'" :rows="1" />
        <ErrorState v-else-if="capabilityState === 'error'" title="沙箱能力检测失败" :description="capabilityError" @retry="loadCapability" />
        <template v-else-if="capability">
          <div v-if="!capability.suricataAvailable" class="cap-banner off" role="status"><ShieldAlert :size="17" /><div><b>本机未安装 Suricata：未执行真实验证</b><p>沙箱验证需要后端主机上的 Suricata；缺少时将返回 blocked 运行，不会产生虚假指标。</p></div></div>
          <div v-else class="cap-banner on" role="status"><ShieldCheck :size="17" /><div><b>Suricata 沙箱可用</b><p>后端将执行真实的语法检查与流量重放验证。</p></div></div>
          <dl class="cap-details">
            <div><dt>可执行文件</dt><dd class="mono">{{ capability.binary || '—' }}</dd></div>
            <div><dt>执行器版本</dt><dd class="mono">{{ capability.executorVersion || '—' }}</dd></div>
            <div><dt>说明</dt><dd>{{ capability.note || '—' }}</dd></div>
          </dl>
        </template>
      </section>

      <section class="compile surface-panel" aria-label="编译 IR">
        <div class="panel-head"><div><h2>编译规则 IR</h2><p>粘贴结构规则 IR（JSON 对象），后端编译为可验证的 Suricata 文本</p></div><span>schema: evonids.rule/v1</span></div>
        <div class="compile-body">
          <textarea v-model="irJson" rows="9" spellcheck="false" class="mono" placeholder='{\n  "rule_id": "EVO-…",\n  "description": "…",\n  "conditions": [ … ]\n}' aria-label="IR JSON" />
          <label class="sid-field"><span>SID（可选）</span><input v-model.number="irSid" type="number" min="1" max="2147483647" placeholder="如 1000001"><small>缺省时由后端分配</small></label>
          <button class="primary" :disabled="compiling" @click="compileIr"><Rocket :size="13" />{{ compiling ? '编译中…' : '编译 IR' }}</button>
        </div>
      </section>

      <section class="versions surface-panel" aria-label="已编译版本">
        <div class="panel-head"><div><h2>编译版本（{{ versions.length }}）</h2><p>SID / rev / IR 摘要与生成的 Suricata 文本</p></div><button :disabled="versionsState === 'loading'" @click="loadVersions"><RefreshCw :size="13" :class="{ spin: versionsState === 'loading' }" />刷新</button></div>
        <LoadingState v-if="versionsState === 'loading' && versions.length === 0" :rows="3" />
        <ErrorState v-else-if="versionsState === 'error' && versions.length === 0" :description="versionsError" @retry="loadVersions" />
        <div v-else-if="versions.length === 0" class="empty-block">尚无编译版本。使用上方 IR 编辑器创建第一个版本。</div>
        <article v-for="version in versions" :key="version.id" class="version-card">
          <header>
            <div class="version-title"><span class="v-chip mono">v{{ version.version }}</span><b>SID {{ version.sid ?? '待分配' }}</b><em class="mono">rev {{ version.rev ?? '—' }}</em></div>
            <div class="version-actions">
              <span class="state-tag mono">{{ version.state }}</span>
              <button :disabled="runningSandbox !== '' || dialogOpen" @click="runSandbox(version.id)"><Play :size="12" />{{ runningSandbox === version.id ? '运行中…' : '运行沙箱验证' }}</button>
              <button class="deploy-version" :disabled="dialogOpen" @click="openDeployDialog(version.id)"><Rocket :size="12" />创建部署</button>
            </div>
          </header>
          <dl class="version-meta">
            <div><dt>IR 摘要</dt><dd class="mono digest"><button class="copy-mini" title="复制完整摘要" @click="copyText(version.irDigest)"><Copy :size="11" /></button>{{ copied === version.irDigest.slice(0, 24) ? version.irDigest : version.irDigest.slice(0, 20) + '…' }}</dd></div>
            <div><dt>创建人</dt><dd>{{ version.createdBy }}</dd></div>
            <div><dt>创建时间</dt><dd class="mono">{{ new Date(version.createdAt).toLocaleString('zh-CN') }}</dd></div>
          </dl>
          <details class="suricata-text">
            <summary>查看 Suricata 文本（{{ version.suricataText ? version.suricataText.length : 0 }} 字符）</summary>
            <div class="suricata-body"><button @click="version.suricataText && copyText(version.suricataText)"><Copy :size="12" />复制</button><pre class="mono">{{ version.suricataText || '（后端未生成 Suricata 文本）' }}</pre></div>
          </details>
        </article>
      </section>

      <section class="sandbox surface-panel" aria-label="沙箱验证记录">
        <div class="panel-head"><div><h2>沙箱验证记录（{{ runs.length }}）</h2><p>指标只展示后端真实测量值；measured:false 显示「未测量」</p></div><button :disabled="runsState === 'loading'" @click="loadRuns"><RefreshCw :size="13" :class="{ spin: runsState === 'loading' }" />刷新</button></div>
        <LoadingState v-if="runsState === 'loading' && runs.length === 0" :rows="3" />
        <ErrorState v-else-if="runsState === 'error' && runs.length === 0" :description="runsError" @retry="loadRuns" />
        <div v-else-if="runs.length === 0" class="empty-block">尚无沙箱验证运行。选择一个编译版本运行验证。</div>
        <article v-for="run in runs" :key="run.id" class="run-card">
          <header>
            <div class="run-title"><span :class="['status-chip', run.status]">{{ sandboxStatusLabels[run.status] }}</span><b class="mono">{{ run.id }}</b><em>版本 {{ deploymentVersionLabel(run.ruleVersionId) }}</em></div>
            <div class="run-flags"><span v-if="run.syntaxPassed" class="ok-flag">语法通过</span><span v-else class="bad-flag">语法未通过</span><span v-if="!run.suricataAvailable" class="no-suricata">无 Suricata</span><span v-if="run.passed" class="ok-flag">验证通过</span></div>
          </header>
          <p v-if="run.blockedReason" class="blocked-note" role="note"><ShieldAlert :size="13" />{{ run.blockedReason }}</p>
          <p v-if="run.detail" class="detail-note">{{ run.detail }}</p>
          <dl class="metric-grid">
            <div v-for="row in metricRows(run.metrics)" :key="row.key">
              <dt>{{ row.label }}</dt>
              <dd :class="{ unmeasured: !row.view.measured }" :title="row.view.measured ? undefined : '该指标本次运行未测量'">{{ row.view.text }}</dd>
            </div>
          </dl>
          <div v-if="run.checks.length" class="checks-list">
            <div v-for="check in run.checks" :key="check.label" :class="{ failed: !check.passed }"><CheckCircle2 v-if="check.passed" :size="13" /><XCircle v-else :size="13" /><span><b>{{ check.label }}</b><small>{{ check.note }}</small></span></div>
          </div>
          <footer class="run-footer"><span>执行器 {{ run.executorVersion || '—' }} · {{ run.suricataVersion ? `Suricata ${run.suricataVersion}` : 'Suricata 未知' }} · {{ new Date(run.createdAt).toLocaleString('zh-CN') }}</span></footer>
        </article>
      </section>

      <section class="deployments surface-panel" aria-label="部署管理">
        <div class="panel-head"><div><h2>部署（{{ deployments.length }}）</h2><p>金丝雀 → 生产提升与回滚均需明确确认</p></div><button :disabled="deploymentsState === 'loading'" @click="loadDeployments"><RefreshCw :size="13" :class="{ spin: deploymentsState === 'loading' }" />刷新</button></div>
        <LoadingState v-if="deploymentsState === 'loading' && deployments.length === 0" :rows="2" />
        <ErrorState v-else-if="deploymentsState === 'error' && deployments.length === 0" :description="deploymentsError" @retry="loadDeployments" />
        <div v-else-if="deployments.length === 0" class="empty-block">尚无部署。先在版本卡片中选择目标传感器组创建金丝雀或生产部署。</div>
        <div v-else class="deploy-table">
          <article v-for="deployment in deployments" :key="deployment.id" class="deploy-row">
            <div class="deploy-main">
              <div class="deploy-title"><span :class="['state-pill', deployment.state]">{{ deploymentStateLabels[deployment.state] }}</span><b class="mono">{{ deployment.id }}</b></div>
              <p class="mono small">版本 {{ deploymentVersionLabel(deployment.ruleVersionId) }} → 组 {{ groupName(deployment.sensorGroupId) }}</p>
              <p class="small"><template v-if="deployment.promotedAt">提升于 {{ new Date(deployment.promotedAt).toLocaleString('zh-CN') }} · </template><template v-if="deployment.rolledBackAt">回滚于 {{ new Date(deployment.rolledBackAt).toLocaleString('zh-CN') }} · </template>创建于 {{ new Date(deployment.createdAt).toLocaleString('zh-CN') }} · 操作人 {{ deployment.deployedBy || '—' }}</p>
              <p v-if="deployment.rollbackReason" class="rollback-reason mono">回滚原因：{{ deployment.rollbackReason }}</p>
            </div>
            <div class="deploy-actions">
              <template v-if="deploymentsState === 'error' && deploymentsError">
                <span class="err-hint">{{ deploymentsError }}</span>
              </template>
              <button v-if="deployment.state === 'canary'" class="primary" @click="openPromoteDialog(deployment)"><Rocket :size="12" />提升到生产</button>
              <button v-if="deployment.state === 'canary' || deployment.state === 'deployed'" class="danger" @click="openRollbackDialog(deployment)"><RotateCcw :size="12" />回滚</button>
              <span v-else-if="deployment.state === 'rolled_back'" class="rolled-back-label">已回滚</span>
            </div>
          </article>
        </div>
      </section>
    </template>

    <div v-if="dialogOpen && dialogKind" class="dialog-overlay" @click.self="closeDialog">
      <div class="dialog-box" role="dialog" aria-modal="true" :aria-label="dialogKind === 'deploy' ? '创建部署' : dialogKind === 'promote' ? '提升到生产' : '回滚部署'">
        <header class="dialog-head">
          <div><b>{{ dialogKind === 'deploy' ? '创建规则部署' : dialogKind === 'promote' ? '提升到生产（高风险操作）' : '回滚部署（高风险操作）' }}</b><p>{{ dialogKind === 'rollback' ? '回滚需要 ≥10 个字符的原因，写入部署记录' : '该操作影响传感器上的实际检测规则' }}</p></div>
          <button aria-label="关闭" :disabled="dialogSubmitting" @click="closeDialog"><X :size="15" /></button>
        </header>
        <div class="dialog-body">
          <template v-if="dialogKind === 'deploy'">
            <label class="dialog-field"><span>传感器组</span>
              <select v-model="dialogGroupId">
                <option value="" disabled>选择目标传感器组…</option>
                <option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}（{{ stageLabels[group.stage] }} · {{ group.sensorIds.length }} 传感器）</option>
              </select>
              <small v-if="groups.length === 0">没有可用传感器组；请先在传感器页/后端创建组。</small>
            </label>
            <div class="dialog-radio">
              <span>部署状态</span>
              <label><input v-model="dialogState" type="radio" value="canary"><b>金丝雀</b><small>先在小范围观察指标</small></label>
              <label><input v-model="dialogState" type="radio" value="deployed"><b>直接部署</b><small>进入生产组</small></label>
            </div>
            <label class="dialog-field"><span>备注（可选）</span><input v-model="dialogNote" maxlength="500" placeholder="部署备注"></label>
            <p class="dialog-hint">后端会校验所选版本是否存在已通过的沙箱验证；未通过时返回 409 与拒绝原因。</p>
          </template>
          <template v-else-if="dialogKind === 'promote'">
            <p class="dialog-warning">提升将把金丝雀部署转为生产部署，推送范围扩大到生产组全部传感器。</p>
            <label class="dialog-field"><span>目标生产组（可选）</span>
              <select v-model="dialogGroupId">
                <option value="">使用默认生产组</option>
                <option v-for="group in groups.filter((item) => item.stage === 'production')" :key="group.id" :value="group.id">{{ group.name }}</option>
              </select>
            </label>
            <label class="dialog-field"><span>备注（可选）</span><input v-model="dialogNote" maxlength="500" placeholder="提升备注"></label>
          </template>
          <template v-else>
            <p class="dialog-warning">回滚会把该版本从目标传感器组撤下，并记录回滚原因。</p>
            <label class="dialog-field"><span>回滚原因（必填，≥10 个字符）</span><textarea v-model="dialogReason" rows="3" maxlength="1000" :class="{ invalid: dialogReason.trim() && dialogReason.trim().length < 10 }" placeholder="如：金丝雀观察期出现新的误报模式…" /></label>
          </template>
          <p v-if="dialogError" class="dialog-error" role="alert"><XCircle :size="13" />{{ dialogError }}</p>
        </div>
        <footer class="dialog-foot">
          <button :disabled="dialogSubmitting" @click="closeDialog">取消</button>
          <button class="primary" :disabled="dialogSubmitting" @click="submitDialog">{{ dialogSubmitting ? '提交中…' : '确认执行' }}</button>
        </footer>
      </div>
    </div>
  </section>
</template>

<style scoped>
.governance{display:grid;gap:12px}
.demo-banner{display:flex;gap:9px;padding:10px 11px;border:1px dashed color-mix(in srgb,var(--status-warning) 45%,var(--border-default));border-radius:8px;background:color-mix(in srgb,var(--status-warning) 7%,transparent);color:var(--status-warning);font-size:12px}.demo-banner>div{flex:1}.demo-banner b{display:block}.demo-banner p{margin:3px 0 0;color:var(--text-tertiary);line-height:1.55}
.gov-toast,.gov-error{display:flex;gap:6px;align-items:center;margin-bottom:2px;padding:8px 10px;border:1px solid color-mix(in srgb,var(--status-success) 35%,var(--border-default));border-radius:7px;background:color-mix(in srgb,var(--status-success) 7%,transparent);color:var(--status-success);font-size:12px}.gov-error{border-color:color-mix(in srgb,var(--status-error) 35%,var(--border-default));background:color-mix(in srgb,var(--status-error) 7%,transparent);color:var(--status-error)}
.surface-panel{overflow:hidden}
.panel-head{display:flex;justify-content:space-between;align-items:center;gap:10px;min-height:54px;padding:8px 13px;border-bottom:1px solid var(--border-subtle)}.panel-head h2,.panel-head p{margin:0}.panel-head h2{font-size:14px}.panel-head p{margin-top:3px;color:var(--text-tertiary);font-size:12px}.panel-head>span{color:var(--text-tertiary);font-size:12px}.panel-head button{display:flex;align-items:center;gap:5px;height:29px;padding:0 9px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer}.panel-head button:disabled{opacity:.55}.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.cap-banner{display:flex;gap:9px;align-items:flex-start;margin:11px 12px 0;padding:9px 11px;border-radius:8px}.cap-banner>div{flex:1}.cap-banner b{display:block;font-size:13px}.cap-banner p{margin:3px 0 0;color:var(--text-tertiary);font-size:12px;line-height:1.55}.cap-banner.off{border-left:3px solid var(--status-error);background:color-mix(in srgb,var(--status-error) 7%,transparent)}.cap-banner.off b,.cap-banner.off svg{color:var(--status-error)}.cap-banner.on{border-left:3px solid var(--status-success);background:color-mix(in srgb,var(--status-success) 7%,transparent)}.cap-banner.on b,.cap-banner.on svg{color:var(--status-success)}
.cap-details{display:grid;grid-template-columns:auto auto 1fr;gap:8px 16px;margin:0;padding:10px 12px}.cap-details dt{color:var(--text-tertiary);font-size:12px}.cap-details dd{margin:0;color:var(--text-secondary);font-size:12px}.cap-details div:first-child dt{min-width:70px}
.compile-body{display:grid;grid-template-columns:1fr 210px auto;gap:10px;align-items:end;padding:12px;border-top:1px solid var(--border-subtle)}.compile-body textarea{width:100%;min-height:180px;padding:9px;border:1px solid var(--border-default);border-radius:7px;background:#0a1017;color:#b8c6d8;font-size:12px;line-height:1.6;resize:vertical}.compile-body .sid-field>span{display:block;margin-bottom:4px;color:var(--text-tertiary);font-size:12px}.compile-body .sid-field input{width:100%;height:33px;padding:0 8px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-primary);font-size:13px}.compile-body .sid-field small{display:block;margin-top:4px;color:var(--text-disabled);font-size:11px}.compile-body>button{display:flex;gap:5px;align-items:center;height:34px;padding:0 12px;border:1px solid color-mix(in srgb,var(--accent) 55%,var(--border-default));border-radius:7px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px;cursor:pointer}.compile-body>button:disabled{opacity:.55;cursor:not-allowed}
.versions,.sandbox,.deployments{margin-top:0}
.empty-block{padding:16px;color:var(--text-tertiary);font-size:12px}
.version-card,.run-card{border-bottom:1px solid var(--border-subtle);padding:10px 12px}.version-card:last-child,.run-card:last-child{border-bottom:0}
.version-card>header{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.version-title{display:flex;align-items:center;gap:8px}.v-chip{padding:1px 7px;border-radius:4px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px}.version-title b{font-size:13px}.version-title em{color:var(--text-tertiary);font-size:11px;font-style:normal}.version-actions{display:flex;align-items:center;gap:8px}.state-tag{padding:1px 6px;border-radius:4px;background:var(--surface-3);color:var(--text-tertiary);font-size:11px}.version-actions button{display:flex;gap:4px;align-items:center;height:27px;padding:0 8px;border:1px solid color-mix(in srgb,var(--accent) 45%,var(--border-default));border-radius:6px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px;cursor:pointer}.version-actions button:disabled{opacity:.55;cursor:not-allowed}.version-actions button.deploy-version{border-color:color-mix(in srgb,var(--status-success) 45%,var(--border-default));background:color-mix(in srgb,var(--status-success) 8%,transparent);color:var(--status-success)}
.version-meta{display:grid;grid-template-columns:2fr 1fr 1.2fr;gap:8px;margin:8px 0 0;padding:0}.version-meta dt{color:var(--text-tertiary);font-size:11px}.version-meta dd{margin:2px 0 0;color:var(--text-secondary);font-size:12px}.digest{display:flex;align-items:center;gap:5px}.copy-mini{display:grid;width:17px;height:17px;place-items:center;border:0;background:transparent;color:var(--text-tertiary);cursor:pointer}
.suricata-text{margin-top:8px;border:1px solid var(--border-subtle);border-radius:7px}.suricata-text summary{padding:7px 10px;color:var(--accent-strong);font-size:12px;cursor:pointer}.suricata-body{position:relative}.suricata-body button{position:absolute;top:8px;right:8px;z-index:1;display:flex;gap:4px;align-items:center;padding:4px 8px;border:1px solid var(--border-default);border-radius:5px;background:var(--surface-2);color:var(--text-secondary);font-size:11px;cursor:pointer}.suricata-body pre{margin:0;padding:12px;overflow:auto;background:#0a1017;color:#b8c6d8;font-size:12px;line-height:1.6;white-space:pre-wrap}
.status-chip{padding:1px 7px;border-radius:4px;font-size:12px;background:var(--surface-3);color:var(--text-tertiary)}.status-chip.validated{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.status-chip.partial{background:color-mix(in srgb,var(--status-warning) 14%,transparent);color:var(--status-warning)}.status-chip.validation_failed,.status-chip.failed{background:color-mix(in srgb,var(--status-error) 12%,transparent);color:var(--status-error)}.status-chip.blocked{background:color-mix(in srgb,var(--text-tertiary) 16%,transparent);color:var(--text-tertiary)}
.run-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.run-title em{color:var(--text-tertiary);font-size:11px;font-style:normal}.run-flags{display:flex;gap:5px;align-items:center}.ok-flag,.bad-flag,.no-suricata{display:inline-flex;align-items:center;padding:1px 6px;border-radius:4px;font-size:11px}.ok-flag{background:color-mix(in srgb,var(--status-success) 10%,transparent);color:var(--status-success)}.bad-flag{background:color-mix(in srgb,var(--status-error) 10%,transparent);color:var(--status-error)}.no-suricata{background:color-mix(in srgb,var(--text-tertiary) 14%,transparent);color:var(--text-tertiary)}
.blocked-note{display:flex;gap:6px;align-items:center;margin:8px 0 0;color:var(--status-warning);font-size:12px}.detail-note{margin:8px 0 0;color:var(--text-tertiary);font-size:12px;line-height:1.5}
.metric-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:1px;margin:9px 0 0;border:1px solid var(--border-subtle);background:var(--border-subtle)}.metric-grid>div{min-width:0;padding:6px 8px;background:var(--surface-1)}.metric-grid dt{overflow:hidden;color:var(--text-tertiary);font-size:11px;text-overflow:ellipsis;white-space:nowrap}.metric-grid dd{margin:2px 0 0;color:var(--text-secondary);font-size:12px;font-weight:600;white-space:nowrap}.metric-grid dd.unmeasured{color:var(--text-disabled);font-weight:400}
.checks-list{display:grid;gap:1px;margin-top:8px;border:1px solid var(--border-subtle);background:var(--border-subtle)}.checks-list>div{display:flex;gap:7px;align-items:center;padding:6px 9px;background:var(--surface-1);color:var(--status-success)}.checks-list>div.failed{color:var(--status-error)}.checks-list span{flex:1}.checks-list b,.checks-list small{display:block}.checks-list b{font-size:12px}.checks-list small{color:var(--text-tertiary);font-size:11px}
.run-footer{padding:8px 0 2px;color:var(--text-disabled);font-size:11px}
.deploy-table .deploy-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:11px 12px;border-bottom:1px solid var(--border-subtle)}.deploy-row:last-child{border-bottom:0}.deploy-main{min-width:0}.deploy-title{display:flex;align-items:center;gap:8px}.state-pill{display:inline-flex;align-items:center;padding:1px 7px;border-radius:4px;font-size:12px;background:var(--surface-3);color:var(--text-tertiary)}.state-pill.canary{background:color-mix(in srgb,var(--status-warning) 14%,transparent);color:var(--status-warning)}.state-pill.deployed{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.state-pill.rolled_back{background:color-mix(in srgb,var(--status-error) 12%,transparent);color:var(--status-error)}
.deploy-main p{margin:4px 0 0}.small{color:var(--text-tertiary);font-size:11px}.rollback-reason{color:var(--status-error);font-size:11px}.deploy-actions{display:flex;gap:6px;align-items:center;flex:0 0 auto}.deploy-actions button{display:flex;gap:4px;align-items:center;height:28px;padding:0 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer}.deploy-actions button.primary{border-color:color-mix(in srgb,var(--accent) 50%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.deploy-actions button.danger{color:var(--status-error)}.err-hint{max-width:300px;color:var(--status-error);font-size:11px}.rolled-back-label{color:var(--text-disabled);font-size:12px}
.dialog-overlay{position:fixed;inset:0;z-index:80;display:grid;place-items:center;padding:18px;background:var(--overlay);backdrop-filter:blur(2px)}.dialog-box{width:min(560px,calc(100vw - 28px));max-height:calc(100vh - 40px);overflow:auto;border:1px solid var(--border-strong);border-radius:12px;background:var(--surface-1);box-shadow:0 26px 80px rgba(0,0,0,.35)}.dialog-head{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;padding:13px 16px;border-bottom:1px solid var(--border-subtle)}.dialog-head b{font-size:15px}.dialog-head p{margin:4px 0 0;color:var(--text-tertiary);font-size:12px}.dialog-head button{display:grid;width:28px;height:28px;place-items:center;border:0;background:transparent;color:var(--text-tertiary);cursor:pointer}.dialog-body{padding:14px 16px;display:grid;gap:11px}.dialog-field>span{display:block;margin-bottom:4px;color:var(--text-tertiary);font-size:12px}.dialog-field select,.dialog-field input,.dialog-field textarea{width:100%;padding:7px 9px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-primary);font-size:13px}.dialog-field textarea{resize:vertical}.dialog-field textarea.invalid{border-color:var(--status-error)}.dialog-field small{display:block;margin-top:4px;color:var(--text-disabled);font-size:11px}.dialog-radio{display:grid;grid-template-columns:auto 1fr 1fr;gap:6px 12px;align-items:center}.dialog-radio>span{color:var(--text-tertiary);font-size:12px}.dialog-radio label{display:flex;gap:5px;align-items:center;cursor:pointer}.dialog-radio label b{font-size:13px}.dialog-radio label small{margin-left:5px;color:var(--text-tertiary);font-size:11px}.dialog-warning{margin:0;padding:9px 11px;border-left:2px solid var(--status-warning);background:color-mix(in srgb,var(--status-warning) 7%,transparent);color:var(--status-warning);font-size:12px;line-height:1.5}.dialog-hint{margin:0;color:var(--text-tertiary);font-size:11px;line-height:1.5}.dialog-error{display:flex;gap:5px;align-items:center;margin:0;color:var(--status-error);font-size:12px}.dialog-foot{display:flex;justify-content:flex-end;gap:8px;padding:11px 16px;border-top:1px solid var(--border-subtle);background:var(--surface-2)}.dialog-foot button{height:33px;padding:0 12px;border-radius:7px;font-size:12px;cursor:pointer}.dialog-foot button:first-child{border:1px solid var(--border-default);background:var(--surface-1);color:var(--text-secondary)}.dialog-foot button.primary{border:1px solid color-mix(in srgb,var(--accent) 55%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.dialog-foot button:disabled{opacity:.55;cursor:not-allowed}
@media(max-width:1000px){.cap-details{grid-template-columns:1fr}.compile-body{grid-template-columns:1fr}.metric-grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:700px){.deploy-row{flex-direction:column;align-items:stretch}.metric-grid{grid-template-columns:1fr 1fr}.version-meta{grid-template-columns:1fr}.dialog-radio{grid-template-columns:1fr}}
</style>
