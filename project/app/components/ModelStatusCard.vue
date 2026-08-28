<script setup lang="ts">
import type { ModelRecord } from '~~/shared/types/security'
defineProps<{ model:ModelRecord }>()
</script>

<template><article class="model-status-card"><header><div><b>{{model.name}}</b><code>{{model.id}} · {{model.version}}</code></div><StatusIndicator :status="model.state" :label="model.state==='healthy'?'健康':model.state==='training'?'训练中':'降级'"/></header><dl><div><dt>职责</dt><dd>{{model.role}}</dd></div><div><dt>P95 延迟</dt><dd class="mono">{{model.latency}} ms</dd></div><div><dt>吞吐</dt><dd class="mono">{{model.throughput.toLocaleString()}}/s</dd></div><div><dt>{{model.qualityLabel}}</dt><dd class="mono quality">{{model.qualityValue}}%</dd></div></dl></article></template>

<style scoped>
.model-status-card{border-top:1px solid var(--border-subtle);background:var(--surface-1)}.model-status-card header{display:flex;justify-content:space-between;align-items:center;padding:11px 12px}.model-status-card header b,.model-status-card header code{display:block}.model-status-card header b{font-size:14px}.model-status-card header code{margin-top:2px;color:var(--text-tertiary);font-size:12px}.model-status-card dl{display:grid;grid-template-columns:1fr 1fr;margin:0}.model-status-card dl div{padding:8px 12px;border-top:1px solid var(--border-subtle);border-right:1px solid var(--border-subtle)}.model-status-card dl div:nth-child(even){border-right:0}.model-status-card dt{color:var(--text-tertiary);font-size:12px}.model-status-card dd{margin:2px 0 0;color:var(--text-secondary);font-size:13px}.model-status-card .quality{color:var(--status-success)}
</style>
