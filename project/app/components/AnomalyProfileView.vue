<script setup lang="ts">
import { Check, Copy, Rows3, Table2, Braces } from '~/utils/icons'
import type { AnomalyProfile } from '~~/shared/types/security'
const props = defineProps<{ profile: AnomalyProfile }>()
const mode = ref<'grouped' | 'table' | 'json'>('grouped')
const copied = ref(false)
const componentId = useId()
const modes = ['grouped', 'table', 'json'] as const

const groups = [
  { label: 'Flow 标识', fields: ['flow_id', 'timestamp'] },
  { label: '五元组与服务', fields: ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service'] },
  { label: '流量统计', fields: ['flow_duration', 'forward_packet_count', 'backward_packet_count', 'forward_bytes', 'backward_bytes', 'packets_per_second', 'bytes_per_second', 'average_packet_size'] },
  { label: '时间窗行为', fields: ['syn_ratio', 'ack_ratio', 'rst_ratio', 'destination_port_count_60s', 'destination_ip_count_60s', 'flow_count_60s'] },
  { label: '模型输出', fields: ['transformer_prediction', 'transformer_confidence', 'autoencoder_reconstruction_error', 'autoencoder_anomaly_score', 'final_risk_score', 'suspected_attack_type'] },
]
const labels: Record<string, string> = {
  flow_id: 'Flow ID', timestamp: '时间戳', src_ip: '源 IP', src_port: '源端口', dst_ip: '目的 IP', dst_port: '目的端口', protocol: '协议', service: '服务', flow_duration: '流持续时间 (s)', forward_packet_count: '前向包数', backward_packet_count: '反向包数', forward_bytes: '前向字节', backward_bytes: '反向字节', packets_per_second: 'Packets/s', bytes_per_second: 'Bytes/s', syn_ratio: 'SYN 比例', ack_ratio: 'ACK 比例', rst_ratio: 'RST 比例', destination_port_count_60s: '60s 目的端口数', destination_ip_count_60s: '60s 目的 IP 数', flow_count_60s: '60s Flow 数', average_packet_size: '平均包长', transformer_prediction: 'Transformer 分类', transformer_confidence: '分类置信度', autoencoder_reconstruction_error: 'AE 重构误差', autoencoder_anomaly_score: 'AE 异常分数', final_risk_score: '最终风险分', suspected_attack_type: '疑似攻击类型',
}
const allFields = computed(() => groups.flatMap((group) => group.fields))
const value = (field: string) => (props.profile as unknown as Record<string, string | number>)[field]

async function copyJson() { await navigator.clipboard.writeText(JSON.stringify(props.profile, null, 2)); copied.value = true; setTimeout(() => copied.value = false, 1600) }

function tabId(value: typeof modes[number]) { return `${componentId}-${value}-tab` }
function panelId(value: typeof modes[number]) { return `${componentId}-${value}-panel` }
function selectMode(value: typeof modes[number]) {
  mode.value = value
  nextTick(() => document.getElementById(tabId(value))?.focus())
}
function onTabKeydown(event: KeyboardEvent, current: typeof modes[number]) {
  const index = modes.indexOf(current)
  if (event.key === 'ArrowRight') selectMode(modes[(index + 1) % modes.length]!)
  else if (event.key === 'ArrowLeft') selectMode(modes[(index - 1 + modes.length) % modes.length]!)
  else if (event.key === 'Home') selectMode(modes[0])
  else if (event.key === 'End') selectMode(modes.at(-1)!)
  else return
  event.preventDefault()
}
</script>

<template>
  <section class="profile-panel surface-panel">
    <div class="profile-head"><div><h2>结构化异常攻击画像</h2><p>模型与 Agent 之间的受控数据边界 · {{ allFields.length }} 个字段</p></div><div class="view-tabs" role="tablist" aria-label="异常画像视图"><button :id="tabId('grouped')" role="tab" :aria-selected="mode === 'grouped'" :aria-controls="panelId('grouped')" :tabindex="mode === 'grouped' ? 0 : -1" :class="{ active: mode === 'grouped' }" @click="mode = 'grouped'" @keydown="onTabKeydown($event, 'grouped')"><Rows3 :size="13" aria-hidden="true" />分组</button><button :id="tabId('table')" role="tab" :aria-selected="mode === 'table'" :aria-controls="panelId('table')" :tabindex="mode === 'table' ? 0 : -1" :class="{ active: mode === 'table' }" @click="mode = 'table'" @keydown="onTabKeydown($event, 'table')"><Table2 :size="13" aria-hidden="true" />数据表</button><button :id="tabId('json')" role="tab" :aria-selected="mode === 'json'" :aria-controls="panelId('json')" :tabindex="mode === 'json' ? 0 : -1" :class="{ active: mode === 'json' }" @click="mode = 'json'" @keydown="onTabKeydown($event, 'json')"><Braces :size="13" aria-hidden="true" />JSON</button></div></div>
    <div v-if="mode === 'grouped'" :id="panelId('grouped')" role="tabpanel" :aria-labelledby="tabId('grouped')" tabindex="0" class="grouped-view">
      <section v-for="group in groups" :key="group.label"><h3>{{ group.label }}</h3><dl><div v-for="field in group.fields" :key="field"><dt>{{ labels[field] }}</dt><dd class="mono">{{ value(field) }}</dd></div></dl></section>
    </div>
    <div v-else-if="mode === 'table'" :id="panelId('table')" role="tabpanel" :aria-labelledby="tabId('table')" tabindex="0" class="profile-table"><table><thead><tr><th>字段</th><th>业务含义</th><th>值</th><th>类型</th></tr></thead><tbody><tr v-for="field in allFields" :key="field"><td class="mono">{{ field }}</td><td>{{ labels[field] }}</td><td class="mono value">{{ value(field) }}</td><td>{{ typeof value(field) }}</td></tr></tbody></table></div>
    <div v-else :id="panelId('json')" role="tabpanel" :aria-labelledby="tabId('json')" tabindex="0" class="json-view"><button @click="copyJson"><component :is="copied ? Check : Copy" :size="13" aria-hidden="true" />{{ copied ? '已复制' : '复制 JSON' }}</button><pre><code>{{ JSON.stringify(profile, null, 2) }}</code></pre></div>
  </section>
</template>

<style scoped>
.profile-panel { overflow: hidden; }.profile-head { display: flex; justify-content: space-between; align-items: center; gap: 16px; min-height: 55px; padding: 10px 13px; border-bottom: 1px solid var(--border-subtle); }.profile-head h2 { margin: 0; font-size: 13px; }.profile-head p { margin: 2px 0 0; color: var(--text-tertiary); font-size:13px; }.view-tabs { display: flex; gap: 2px; padding: 2px; border: 1px solid var(--border-subtle); border-radius: 7px; background: var(--surface-2); }.view-tabs button { display: flex; align-items: center; gap: 4px; padding: 4px 7px; border: 0; border-radius: 5px; background: transparent; color: var(--text-tertiary); font-size:13px; cursor: pointer; }.view-tabs button.active { background: var(--surface-3); color: var(--text-primary); }
.grouped-view { display: grid; grid-template-columns: 1fr 1.45fr 1.25fr 1.25fr 1.35fr; gap: 0; }.grouped-view section { min-width: 0; padding: 11px 12px; border-right: 1px solid var(--border-subtle); }.grouped-view section:last-child { border-right: 0; }.grouped-view h3 { margin: 0 0 6px; color: var(--text-tertiary); font-size:12px; letter-spacing: .05em; text-transform: uppercase; }.grouped-view dl { display: grid; gap: 4px; margin: 0; }.grouped-view dl div { min-width: 0; }.grouped-view dt { color: var(--text-tertiary); font-size:12px; }.grouped-view dd { margin: 0; overflow: hidden; color: var(--text-secondary); font-size:13px; text-overflow: ellipsis; white-space: nowrap; }
.profile-table { max-height: 380px; overflow: auto; }.profile-table table { width: 100%; border-collapse: collapse; }.profile-table th { position: sticky; top: 0; z-index: 1; height: 30px; padding: 0 10px; background: var(--surface-2); color: var(--text-tertiary); font-size:13px; text-align: left; }.profile-table td { height: 31px; padding: 0 10px; border-top: 1px solid var(--border-subtle); color: var(--text-secondary); font-size:13px; }.profile-table .value { color: var(--text-primary); }
.json-view { position: relative; max-height: 430px; overflow: auto; background: #0a1017; }.json-view button { position: sticky; z-index: 1; top: 8px; float: right; display: flex; align-items: center; gap: 4px; margin: 8px; padding: 5px 7px; border: 1px solid #334254; border-radius: 6px; background: #151e29; color: #a7b3c2; font-size:13px; cursor: pointer; }.json-view pre { margin: 0; padding: 14px; color: #b8c6d8; font-size:13px; line-height: 1.65; white-space: pre-wrap; }
@media (max-width: 1000px) { .grouped-view { grid-template-columns: 1fr 1fr; }.grouped-view section { border-bottom: 1px solid var(--border-subtle); } }
@media (max-width: 650px) { .profile-head { align-items: flex-start; flex-direction: column; }.grouped-view { grid-template-columns: 1fr; } }
</style>
