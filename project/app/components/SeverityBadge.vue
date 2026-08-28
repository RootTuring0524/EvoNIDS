<script setup lang="ts">
import { AlertCircle, AlertOctagon, AlertTriangle, Info, MinusCircle } from '~/utils/icons'
import type { Severity } from '~~/shared/types/security'

const props = defineProps<{ level: Severity; compact?: boolean }>()
const config = {
  critical: { label: '严重', icon: AlertOctagon },
  high: { label: '高危', icon: AlertTriangle },
  medium: { label: '中危', icon: AlertCircle },
  low: { label: '低危', icon: MinusCircle },
  info: { label: '信息', icon: Info },
}
const item = computed(() => config[props.level])
</script>

<template>
  <span :class="['severity', `severity-${level}`]" :aria-label="`危险等级：${item.label}`"><component :is="item.icon" :size="compact ? 12 : 13" aria-hidden="true" /><span>{{ compact ? item.label : item.label }}</span></span>
</template>

<style scoped>
.severity { display: inline-flex; align-items: center; gap: 4px; width: max-content; padding: 2px 6px; border: 1px solid currentColor; border-radius: 5px; font-size:13px; font-weight: 650; white-space: nowrap; }.severity-critical { color: var(--severity-critical); background: color-mix(in srgb, var(--severity-critical) 10%, transparent); }.severity-high { color: var(--severity-high); background: color-mix(in srgb, var(--severity-high) 10%, transparent); }.severity-medium { color: var(--severity-medium); background: color-mix(in srgb, var(--severity-medium) 10%, transparent); }.severity-low { color: var(--severity-low); background: color-mix(in srgb, var(--severity-low) 9%, transparent); }.severity-info { color: var(--severity-info); background: color-mix(in srgb, var(--severity-info) 9%, transparent); }
</style>
