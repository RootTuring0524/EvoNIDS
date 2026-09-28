<script setup lang="ts">
import { CircleAlert, GitMerge, RefreshCw, ScanSearch, ShieldAlert, ShieldCheck } from '~/utils/icons'
import { detectionFlowDetailSchema, type DetectionFlowDetailApiResponse } from '~~/shared/schemas/security'
import type { AssessmentDecision, DetectionSignal, SignalDecision } from '~~/shared/types/security'

const props = defineProps<{ flowId: string }>()
const isMock = useRuntimeConfig().public.useMockApi

const data = ref<DetectionFlowDetailApiResponse | null>(null)
const loading = ref(false)
const failed = ref(false)
const notFound = ref(false)
const message = ref('')

interface ChainErrorShape {
  statusCode?: number
  statusMessage?: string
  message?: string
  data?: ChainErrorShape
}

async function load() {
  const flow = props.flowId.trim()
  if (!flow) {
    data.value = null
    notFound.value = true
    failed.value = true
    message.value = '缺少 Flow 标识。'
    return
  }
  loading.value = true
  failed.value = false
  notFound.value = false
  message.value = ''
  try {
    data.value = await validatedFetch(`/detections/flows/${encodeURIComponent(flow)}`, detectionFlowDetailSchema)
  } catch (error: unknown) {
    const shape = (typeof error === 'object' && error !== null ? error : {}) as ChainErrorShape
    const statusCode = shape.statusCode ?? shape.data?.statusCode
    const statusMessage = shape.data?.statusMessage ?? shape.statusMessage ?? shape.message
    notFound.value = statusCode === 404
    message.value = statusMessage || '检测证据链加载失败，请稍后重试。'
    data.value = null
    failed.value = true
  } finally {
    loading.value = false
  }
}

watch(() => props.flowId, () => { if (!loading.value) load() })
load()

const signalDecisionMeta: Record<SignalDecision, { label: string; tone: string }> = {
  alert: { label: '告警', tone: 'alert' },
  benign: { label: '正常', tone: 'benign' },
  abstain: { label: '弃权', tone: 'abstain' },
}
const assessmentDecisionMeta: Record<AssessmentDecision, { label: string; tone: string }> = {
  malicious: { label: '恶意', tone: 'malicious' },
  suspicious: { label: '可疑', tone: 'suspicious' },
  benign: { label: '良性', tone: 'benign' },
  abstain: { label: '弃权', tone: 'abstain' },
}
const channelNames: Record<string, string> = {
  baseline: '已知攻击基线',
  autoencoder: '未知异常 AE',
  suricata: '规则通道',
}
const modeNames: Record<string, string> = {
  enabled: '启用模式',
  shadow: '影子模式',
  disabled: '检测关闭',
}

function score(value: number): string { return value.toFixed(3) }
function pct(value: number): string { return `${Math.round(value * 100)}%` }
function latency(value: number): string { return value >= 100 ? `${Math.round(value)} ms` : `${value.toFixed(1)} ms` }
function channelLabel(channel: string): string { return channelNames[channel] ?? channel }
function topKItems(signal: DetectionSignal) { return signal.detail.topK ?? [] }
function devFeatures(signal: DetectionSignal) { return (signal.detail.deviatingFeatures ?? []).slice(0, 4) }
function devFeatureCount(signal: DetectionSignal): number { return signal.detail.deviatingFeatures?.length ?? 0 }
function contextCount(signal: DetectionSignal): number { return Object.keys(signal.detail.contextFeatures).length }
</script>

<template>
  <section class="chain surface-panel" aria-label="在线模型检测证据链">
    <header class="chain-head">
      <div><h2>检测证据链 · 在线模型</h2><p><code>{{ flowId }}</code><template v-if="data"><span> · </span>{{ data.signals.length }} 个通道信号 · {{ data.assessments.length }} 次融合评估</template></p></div>
      <button :disabled="loading" aria-label="刷新证据链" @click="load"><RefreshCw :size="13" :class="{ spin: loading }" />刷新</button>
    </header>

    <LoadingState v-if="loading && !data" :rows="4" label="正在加载检测证据链" />
    <div v-else-if="failed" class="chain-state" role="alert">
      <CircleAlert :size="20" />
      <div>
        <b>{{ notFound ? '该 Flow 暂无在线检测记录' : '检测证据链加载失败' }}</b>
        <p>{{ isMock && notFound ? '演示模式：证据链由真实后端在线评分时生成，此处不伪造信号与融合结果。' : message }}</p>
        <p v-if="notFound && !isMock" class="chain-tip">可能原因：该 Flow 早于在线检测启用、模型处于禁用/影子状态未评分，或 Flow 标识与模型记录不一致。</p>
      </div>
      <button @click="load"><RefreshCw :size="13" />重试</button>
    </div>
    <div v-else-if="!data" class="chain-state waiting"><ShieldCheck :size="20" /><div><b>等待 Flow 数据</b><p>加载检测证据链后将在此展示。</p></div></div>
    <div v-else class="chain-body">
      <section v-if="data.signals.length" class="signals" aria-label="各通道模型信号">
        <article v-for="signal in data.signals" :key="signal.id" class="signal-card" :class="`channel-${signal.channel}`">
          <header>
            <div class="signal-title"><ScanSearch :size="15" /><b>{{ channelLabel(signal.channel) }}</b><em class="mono">{{ signal.channelVersion }}</em></div>
            <div class="signal-flags">
              <span v-if="signal.degraded" class="chip degraded" :title="signal.degradedReason ?? ''"><ShieldAlert :size="12" />降级</span>
              <span v-else class="chip ok"><ShieldCheck :size="12" />健康</span>
              <span class="chip decision" :class="signalDecisionMeta[signal.decision].tone">{{ signalDecisionMeta[signal.decision].label }}</span>
            </div>
          </header>
          <dl class="signal-scores">
            <div><dt>原始分</dt><dd class="mono">{{ score(signal.rawScore) }}</dd></div>
            <div><dt>校准分</dt><dd class="mono">{{ score(signal.calibratedScore) }}</dd></div>
            <div><dt>阈值</dt><dd class="mono">{{ score(signal.threshold) }}</dd></div>
            <div><dt>不确定性</dt><dd class="mono">{{ score(signal.uncertainty) }}</dd></div>
            <div><dt>延迟</dt><dd class="mono">{{ latency(signal.latencyMs) }}</dd></div>
            <div><dt>特征版本</dt><dd class="mono">{{ signal.featureVersion }}<small v-if="signal.featureSource"> / {{ signal.featureSource }}</small></dd></div>
          </dl>
          <div class="signal-extra">
            <p v-if="signal.degraded && signal.degradedReason" class="degraded-reason"><ShieldAlert :size="12" />{{ signal.degradedReason }}</p>
            <template v-if="signal.channel === 'baseline'">
              <p v-if="signal.detail.prediction" class="baseline-prediction">分类结果 <b class="mono">{{ signal.detail.prediction }}</b></p>
              <div v-if="topKItems(signal).length" class="topk">
                <span v-for="item in topKItems(signal)" :key="item.label" class="prob-chip mono"><b>{{ item.label }}</b>{{ pct(item.probability) }}</span>
              </div>
            </template>
            <template v-else-if="signal.channel === 'autoencoder'">
              <p class="ae-line mono">重构误差 <b>{{ signal.detail.reconstructionError === undefined ? '—' : signal.detail.reconstructionError }}</b> · 阈值 <b>{{ signal.detail.errorThreshold === undefined ? '—' : signal.detail.errorThreshold }}</b> · 超阈值 <b :class="{ danger: signal.detail.exceedsThreshold }">{{ signal.detail.exceedsThreshold === undefined ? '—' : signal.detail.exceedsThreshold ? '是' : '否' }}</b></p>
              <div v-if="devFeatures(signal).length" class="dev-features">
                <span v-for="item in devFeatures(signal)" :key="item.field" class="mono" :title="`观测 ${item.observed} · 基线 ${item.baseline}`"><b>{{ item.field }}</b>× {{ item.deviation.toFixed(2) }}</span>
                <span v-if="devFeatureCount(signal) > 4" class="mono more">… 等 {{ devFeatureCount(signal) }} 个偏差特征</span>
              </div>
            </template>
            <p class="context-line">窗口 {{ signal.detail.windowSeconds }} s · 上下文特征 {{ contextCount(signal) }} 项<template v-if="signal.detail.missingFields.length"> · 缺失字段 {{ signal.detail.missingFields.length }} 项</template></p>
            <div v-if="signal.imputedFeatures.length" class="imputed">
              <p>补全特征 {{ signal.imputedFeatures.length }} 项</p>
              <div class="chip-row">
                <span v-for="field in signal.imputedFeatures.slice(0, 8)" :key="field" class="chip mono">{{ field }}</span>
                <span v-if="signal.imputedFeatures.length > 8" class="chip more">… 等 {{ signal.imputedFeatures.length }} 项</span>
              </div>
            </div>
          </div>
        </article>
      </section>
      <p v-else class="no-signals">该 Flow 没有通道信号记录。</p>

      <section v-if="data.assessments.length" class="assessments" aria-label="融合风险评估">
        <article v-for="assessment in data.assessments" :key="assessment.id" class="assessment-card">
          <header>
            <div class="assessment-title"><GitMerge :size="16" /><b>风险融合评估</b><code>{{ assessment.id }}</code></div>
            <div class="assessment-flags">
              <span v-if="assessment.mode === 'shadow'" class="chip shadow"><ShieldAlert :size="12" />影子模式</span>
              <span class="chip decision" :class="assessmentDecisionMeta[assessment.decision].tone">{{ assessmentDecisionMeta[assessment.decision].label }}</span>
            </div>
          </header>

          <div v-if="assessment.mode === 'shadow'" class="shadow-note" role="note">
            <ShieldAlert :size="14" /><span>影子模式：模型仅评分并留存证据，本次评估未产生在线告警（页面告警可能来自规则或采集侧其它检测器）。</span>
          </div>

          <div class="assessment-main">
            <div class="final-score"><small>融合风险分</small><b class="mono">{{ assessment.finalScore.toFixed(1) }}<em>/100</em></b></div>
            <dl class="assessment-facts">
              <div><dt>不确定性</dt><dd class="mono">{{ assessment.uncertainty.toFixed(3) }}</dd></div>
              <div><dt>参与信号</dt><dd class="mono">{{ assessment.signalIds.length }} 个</dd></div>
              <div><dt>模式</dt><dd><span :class="['mode-chip', assessment.mode]">{{ modeNames[assessment.mode] ?? assessment.mode }}</span></dd></div>
            </dl>
          </div>

          <div v-if="Object.keys(assessment.weights).length" class="weights" aria-label="通道权重">
            <span v-for="(weight, channel) in assessment.weights" :key="channel" class="weight-chip"><b>{{ channelLabel(channel) }}</b><em class="mono">{{ pct(weight) }}</em></span>
          </div>

          <div v-if="assessment.inputs.length" class="assessment-inputs">
            <p>融合输入</p>
            <div class="chip-row">
              <span v-for="(input, index) in assessment.inputs" :key="`${input.channel}-${index}`" class="input-chip">
                <b>{{ channelLabel(input.channel) }}</b><em class="mono">raw {{ score(input.rawScore) }}</em><em class="mono">cal {{ score(input.calibratedScore) }}</em><em :class="['mini-decision', input.decision]">{{ signalDecisionMeta[input.decision]?.label ?? input.decision }}</em>
              </span>
            </div>
          </div>

          <p class="explanation">{{ assessment.explanation }}</p>
          <ul v-if="assessment.degradedReasons.length" class="degraded-list">
            <li v-for="reason in assessment.degradedReasons" :key="reason" class="mono"><ShieldAlert :size="11" />{{ reason }}</li>
          </ul>
        </article>
      </section>
      <p v-else class="no-signals">该 Flow 没有融合评估记录。</p>
    </div>
  </section>
</template>

<style scoped>
.chain{overflow:hidden}
.chain-head{display:flex;justify-content:space-between;align-items:center;gap:10px;min-height:50px;padding:8px 12px;border-bottom:1px solid var(--border-subtle)}
.chain-head h2{margin:0;font-size:14px}.chain-head p{margin:2px 0 0;color:var(--text-tertiary);font-size:12px}.chain-head code{color:var(--text-secondary)}
.chain-head button{display:flex;gap:5px;align-items:center;height:29px;padding:0 9px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer}.chain-head button:disabled{opacity:.5}
.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.chain-state{display:flex;gap:10px;align-items:flex-start;min-height:110px;padding:18px;color:var(--status-error)}.chain-state>div{flex:1}.chain-state b{display:block;color:var(--text-primary);font-size:13px}.chain-state p{margin:3px 0 0;color:var(--text-tertiary);font-size:13px;line-height:1.5}.chain-state .chain-tip{margin-top:6px;font-size:12px}.chain-state button{display:flex;gap:4px;align-items:center;padding:5px 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-secondary);cursor:pointer}.chain-state.waiting{color:var(--text-tertiary)}
.chain-body{padding:12px;display:grid;gap:16px}
.signals,.assessments{display:grid;gap:10px}.no-signals{margin:0;color:var(--text-tertiary);font-size:13px}
.signal-card,.assessment-card{overflow:hidden;border:1px solid var(--border-subtle);border-radius:10px;background:var(--surface-1)}
.signal-card{border-left-width:3px}.signal-card.channel-baseline{border-left-color:var(--severity-info)}.signal-card.channel-autoencoder{border-left-color:var(--accent-strong)}.signal-card.channel-suricata{border-left-color:var(--status-warning)}
.signal-card>header,.assessment-card>header{display:flex;justify-content:space-between;gap:8px;align-items:center;min-height:41px;padding:6px 10px;border-bottom:1px solid var(--border-subtle);background:var(--surface-2)}
.signal-title,.assessment-title{display:flex;gap:6px;align-items:center;min-width:0}.signal-title b,.assessment-title b{font-size:13px}.signal-title em{color:var(--text-tertiary);font-size:12px;font-style:normal;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.assessment-title code{color:var(--text-tertiary);font-size:11px}
.signal-flags,.assessment-flags{display:flex;gap:5px;align-items:center;flex-wrap:wrap}
.chip{display:inline-flex;gap:3px;align-items:center;padding:1px 6px;border-radius:4px;font-size:12px;background:var(--surface-3);color:var(--text-secondary);white-space:nowrap}.chip.degraded{background:color-mix(in srgb,var(--status-warning) 12%,transparent);color:var(--status-warning)}.chip.ok{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.chip.shadow{background:color-mix(in srgb,var(--status-warning) 14%,transparent);color:var(--status-warning);border:1px dashed color-mix(in srgb,var(--status-warning) 45%,transparent)}.chip.decision.alert{background:color-mix(in srgb,var(--status-error) 14%,transparent);color:var(--status-error)}.chip.decision.benign{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.chip.decision.abstain{background:color-mix(in srgb,var(--text-tertiary) 16%,transparent);color:var(--text-tertiary)}.chip.more{color:var(--text-disabled)}
.signal-scores{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin:0;padding:9px 10px;border-bottom:1px solid var(--border-subtle)}.signal-scores>div{min-width:0}.signal-scores dt{color:var(--text-tertiary);font-size:12px}.signal-scores dd{margin:1px 0 0;color:var(--text-secondary);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.signal-scores dd small{color:var(--text-disabled);font-size:11px}
.signal-extra{padding:8px 10px 10px}.degraded-reason{display:flex;gap:5px;align-items:center;margin:0 0 6px;padding:4px 7px;border-radius:5px;background:color-mix(in srgb,var(--status-warning) 8%,transparent);color:var(--status-warning);font-size:12px}.baseline-prediction{margin:0 0 5px;color:var(--text-tertiary);font-size:12px}.baseline-prediction b{color:var(--text-secondary);font-weight:600}
.topk,.chip-row,.weights,.dev-features{display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.prob-chip{padding:2px 7px;border:1px solid var(--border-subtle);border-radius:5px;color:var(--text-tertiary);font-size:12px}.prob-chip b{margin-right:5px;color:var(--text-secondary);font-weight:600}.ae-line{margin:0 0 6px;color:var(--text-tertiary);font-size:12px}.ae-line b{color:var(--text-secondary);font-weight:600}.danger{color:var(--status-error)!important}
.dev-features>span{padding:2px 6px;border-radius:5px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px}.dev-features>span b{margin-right:4px;color:var(--text-secondary);font-weight:600}.dev-features>.more{background:transparent;color:var(--text-disabled)}
.context-line{margin:7px 0 0;color:var(--text-disabled);font-size:12px}.imputed{margin-top:5px}.imputed>p{margin:0 0 4px;color:var(--text-tertiary);font-size:12px}
.shadow-note{display:flex;gap:7px;align-items:flex-start;margin:10px;padding:8px 9px;border:1px dashed color-mix(in srgb,var(--status-warning) 45%,var(--border-default));border-radius:7px;background:color-mix(in srgb,var(--status-warning) 8%,transparent);color:var(--status-warning);font-size:12px;line-height:1.5}.shadow-note svg{flex:0 0 auto;margin-top:1px}
.assessment-main{display:flex;gap:16px;align-items:center;padding:11px 12px 8px}.final-score small{display:block;color:var(--text-tertiary);font-size:12px}.final-score b{color:var(--severity-high);font-size:27px;font-weight:700;line-height:1.1}.final-score em{color:var(--text-tertiary);font-size:12px;font-style:normal;font-weight:500}.assessment-facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;flex:1;margin:0}.assessment-facts>div{min-width:0}.assessment-facts dt{color:var(--text-tertiary);font-size:12px}.assessment-facts dd{margin:2px 0 0;color:var(--text-secondary);font-size:13px}.mode-chip{padding:1px 6px;border-radius:4px;background:var(--surface-3);color:var(--text-secondary);font-size:12px}.mode-chip.enabled{background:color-mix(in srgb,var(--status-success) 12%,transparent);color:var(--status-success)}.mode-chip.shadow{background:color-mix(in srgb,var(--status-warning) 14%,transparent);color:var(--status-warning)}
.weights{padding:0 12px 4px}.weight-chip{display:inline-flex;gap:6px;align-items:center;padding:2px 7px;border-radius:5px;background:var(--surface-2);color:var(--text-secondary);font-size:12px}.weight-chip b{font-weight:600}.weight-chip em{color:var(--text-tertiary);font-style:normal}
.assessment-inputs{padding:2px 12px 6px}.assessment-inputs>p{margin:4px 0;color:var(--text-tertiary);font-size:12px}.input-chip{display:inline-flex;gap:7px;align-items:center;padding:2px 7px;border:1px solid var(--border-subtle);border-radius:6px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px}.input-chip b{color:var(--text-secondary);font-weight:600}.mini-decision{font-style:normal}.mini-decision.alert{color:var(--status-error)}.mini-decision.benign{color:var(--status-success)}.mini-decision.abstain{color:var(--text-disabled)}
.explanation{margin:0;padding:8px 12px;color:var(--text-secondary);font-size:13px;line-height:1.6;border-top:1px solid var(--border-subtle)}
.degraded-list{margin:0;padding:6px 12px 10px;list-style:none;display:grid;gap:4px}.degraded-list li{display:flex;gap:5px;align-items:center;color:var(--status-warning);font-size:12px}
@media(max-width:900px){.signal-scores{grid-template-columns:repeat(3,1fr)}.assessment-main{flex-direction:column;align-items:stretch}}
@media(max-width:560px){.signal-scores{grid-template-columns:1fr 1fr}}
</style>
