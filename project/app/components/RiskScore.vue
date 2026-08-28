<script setup lang="ts">
import { ShieldAlert } from '~/utils/icons'
import type { Severity } from '~~/shared/types/security'
defineProps<{ value:number; severity:Severity; compact?:boolean }>()
</script>

<template><span :class="['risk-score',`risk-${severity}`,{compact}]" :aria-label="`风险分 ${value}`"><ShieldAlert v-if="!compact" :size="13"/><b class="mono">{{value}}</b></span></template>

<style scoped>
.risk-score{display:inline-flex;align-items:center;gap:5px;min-width:45px;height:28px;padding:0 7px;border-radius:6px;font-size:13px;font-weight:700}.risk-score.compact{display:inline-grid;min-width:30px;width:30px;height:25px;padding:0;place-items:center}.risk-critical{color:var(--severity-critical);background:color-mix(in srgb,var(--severity-critical) 10%,transparent)}.risk-high{color:var(--severity-high);background:color-mix(in srgb,var(--severity-high) 10%,transparent)}.risk-medium{color:var(--severity-medium);background:color-mix(in srgb,var(--severity-medium) 10%,transparent)}.risk-low,.risk-info{color:var(--severity-info);background:color-mix(in srgb,var(--severity-info) 9%,transparent)}
</style>
