<script setup lang="ts">
import { ArrowLeft, CheckCircle2, DatabaseZap, RefreshCw, ShieldAlert, TriangleAlert } from '~/utils/icons'
import { evidenceDetailSchema, type EvidenceDetailApiResponse } from '~~/shared/schemas/security'

const route = useRoute()
const id = computed(() => String(route.params.id))
const isMock = useRuntimeConfig().public.useMockApi

const data = ref<EvidenceDetailApiResponse | null>(null)
const loading = ref(false)
const failed = ref(false)
const message = ref('')

function readError(error: unknown) {
  const shape = (typeof error === 'object' && error !== null ? error : {}) as {
    data?: { statusMessage?: string; message?: string }
    statusMessage?: string
    message?: string
  }
  return shape.data?.statusMessage || shape.data?.message || shape.statusMessage || shape.message || '证据详情加载失败，请稍后重试。'
}

async function load() {
  loading.value = true
  failed.value = false
  message.value = ''
  try {
    data.value = await validatedFetch(`/evidence/${encodeURIComponent(id.value)}`, evidenceDetailSchema)
  } catch (error: unknown) {
    data.value = null
    failed.value = true
    message.value = readError(error)
  } finally {
    loading.value = false
  }
}

onMounted(load)

const fieldRows = computed(() => Object.entries(data.value?.fields ?? {}))
function valueText(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
function refTarget(): string | null {
  const record = data.value
  if (!record) return null
  return record.sourceRefType === 'alert' && record.sourceRefId ? `/alerts/${record.sourceRefId}` : null
}
function titleText(): string {
  return `证据详情 ${data.value?.id ?? id.value}`
}
</script>

<template>
  <div class="evidence-detail-page">
    <NuxtLink to="/evidence" class="back-link"><ArrowLeft :size="14" />返回证据检索</NuxtLink>

    <LoadingState v-if="loading && !data" :rows="6" label="正在加载证据详情" />
    <ErrorState v-else-if="failed && !data" title="无法加载证据详情" :description="message" @retry="load" />
    <template v-else-if="data">
      <div v-if="isMock" class="demo-notice" role="note"><TriangleAlert :size="14" /><div><b>演示模式</b><p>证据详情由真实后端提供；此处仅在连接真实后端后展示登记信息与原始工件。</p></div></div>
      <header class="ev-header">
        <div class="title-row"><DatabaseZap :size="20" /><h1>证据详情</h1><code class="mono">{{ data.id }}</code></div>
        <p>{{ data.sourceType }} · {{ data.eventType }} · 传感器 <code class="mono">{{ data.sensorId }}</code></p>
        <div class="ev-actions"><button :disabled="loading" @click="load"><RefreshCw :size="13" :class="{ spin: loading }" />刷新</button></div>
      </header>

      <section class="meta-panel surface-panel" aria-label="登记信息">
        <div><span>外部 ID</span><b class="mono">{{ data.externalId }}</b></div>
        <div><span>事件时间</span><b class="mono">{{ new Date(data.observedAt).toLocaleString('zh-CN') }}</b></div>
        <div><span>接收时间</span><b class="mono">{{ new Date(data.receivedAt).toLocaleString('zh-CN') }}</b></div>
        <div><span>完整性</span><b :class="['integrity', { ok: data.integrity === 'complete' }]">{{ data.integrity }}<template v-if="data.dataMissing !== 'none'">（{{ data.dataMissing }}）</template></b></div>
        <div><span>SHA-256</span><b class="mono hash">{{ data.contentSha256 }}</b></div>
        <div><span>解析器版本</span><b class="mono">{{ data.parserVersion }}</b></div>
        <div><span>原始工件</span><b>{{ data.artifactSizeBytes }} 字节<template v-if="data.redacted"> · 已脱敏</template></b></div>
        <div><span>创建时间</span><b class="mono">{{ new Date(data.createdAt).toLocaleString('zh-CN') }}</b></div>
      </section>

      <section v-if="data.integrity !== 'complete' || data.dataMissing !== 'none'" class="warn-note" role="note">
        <ShieldAlert :size="14" /><span>该证据登记不完整（{{ data.dataMissing }}）；原始内容可能缺失，展示值以数据库为准。</span>
      </section>

      <section class="detail-panel surface-panel" aria-label="字段内容">
        <div class="panel-head"><div><h2>事件字段</h2><p>由解析器提取的原始字段（不经改写）</p></div></div>
        <div v-if="fieldRows.length === 0" class="empty-hint">该证据没有字段内容。</div>
        <div v-else class="field-table">
          <div v-for="[key, value] in fieldRows" :key="key"><code class="mono">{{ key }}</code><pre class="mono">{{ valueText(value) }}</pre></div>
        </div>
      </section>

      <section class="detail-panel surface-panel" aria-label="原始事件文本">
        <div class="panel-head"><div><h2>原始事件文本</h2><p>超过 1 MiB 或未登记的原文不会展示</p></div></div>
        <pre v-if="data.artifactText" class="artifact mono">{{ data.artifactText }}</pre>
        <div v-else class="empty-hint">（未存储原文——超过 1 MiB 或已截断）</div>
      </section>

      <div v-if="refTarget()" class="related-row"><CheckCircle2 :size="14" /><span>该证据登记自告警</span><NuxtLink :to="refTarget()!">查看来源告警</NuxtLink></div>
    </template>
    <EmptyState v-else :title="titleText()" description="暂无该证据的详情数据。" />
  </div>
</template>

<style scoped>
.evidence-detail-page{padding:16px 22px 30px}.back-link{display:inline-flex;align-items:center;gap:5px;margin-bottom:12px;color:var(--text-tertiary);font-size:12px;text-decoration:none}.back-link:hover{color:var(--text-primary)}
.demo-notice{display:flex;gap:9px;margin-bottom:10px;padding:9px 11px;border:1px dashed color-mix(in srgb,var(--status-warning) 45%,var(--border-default));border-radius:8px;background:color-mix(in srgb,var(--status-warning) 7%,transparent);color:var(--status-warning);font-size:12px}.demo-notice>div{flex:1}.demo-notice b{display:block}.demo-notice p{margin:3px 0 0;color:var(--text-tertiary);line-height:1.55}
.ev-header{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:12px}.title-row{display:flex;align-items:center;gap:9px}.title-row svg{color:var(--accent-strong)}.title-row h1{margin:0;font-size:20px}.title-row code{color:var(--text-tertiary);font-size:12px}.ev-header p{margin:5px 0 0;color:var(--text-tertiary);font-size:12px}.ev-actions button{display:flex;align-items:center;gap:5px;height:30px;padding:0 9px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-secondary);font-size:12px;cursor:pointer}.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.meta-panel{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:12px;overflow:hidden}.meta-panel>div{min-width:0;padding:9px 11px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.meta-panel span,.meta-panel b{display:block}.meta-panel span{color:var(--text-tertiary);font-size:12px}.meta-panel b{margin-top:3px;overflow:hidden;color:var(--text-secondary);font-size:12px;font-weight:550;text-overflow:ellipsis;white-space:nowrap}.meta-panel .hash{font-size:11px}.meta-panel .integrity.ok{color:var(--status-success)}.meta-panel .integrity{color:var(--status-warning)}
.warn-note{display:flex;gap:7px;align-items:flex-start;margin-bottom:12px;padding:8px 10px;border-left:2px solid var(--status-warning);background:color-mix(in srgb,var(--status-warning) 7%,transparent);color:var(--status-warning);font-size:12px;line-height:1.5}
.detail-panel{margin-bottom:12px;overflow:hidden}.panel-head{display:flex;justify-content:space-between;align-items:center;min-height:50px;padding:8px 12px;border-bottom:1px solid var(--border-subtle)}.panel-head h2,.panel-head p{margin:0}.panel-head h2{font-size:14px}.panel-head p{margin-top:3px;color:var(--text-tertiary);font-size:12px}
.field-table{display:grid;grid-template-columns:1fr;max-height:420px;overflow:auto}.field-table>div{display:grid;grid-template-columns:minmax(150px,260px) 1fr;gap:10px;padding:7px 12px;border-bottom:1px solid var(--border-subtle)}.field-table code{overflow:hidden;color:var(--accent-strong);font-size:11px;text-overflow:ellipsis}.field-table pre{margin:0;overflow-wrap:anywhere;color:var(--text-secondary);font-size:11px;line-height:1.5;white-space:pre-wrap}
.artifact{margin:0;padding:13px;overflow:auto;background:var(--surface-2);color:var(--text-secondary);font-size:12px;line-height:1.6;white-space:pre-wrap;max-height:520px}.empty-hint{padding:14px;color:var(--text-tertiary);font-size:12px}
.related-row{display:flex;gap:8px;align-items:center;padding:10px 12px;border:1px solid var(--border-subtle);border-radius:8px;background:var(--surface-1);color:var(--text-secondary);font-size:13px}.related-row svg{color:var(--status-success)}.related-row a{color:var(--accent-strong);text-decoration:none}
@media(max-width:900px){.meta-panel{grid-template-columns:repeat(2,1fr)}}@media(max-width:600px){.evidence-detail-page{padding:14px 12px 24px}.meta-panel{grid-template-columns:1fr}.field-table>div{grid-template-columns:1fr}}
</style>
