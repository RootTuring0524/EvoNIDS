<script setup lang="ts">
defineProps<{ status: string; label?: string }>()
</script>

<template><span :class="['status-indicator', `status-${status}`]" :aria-label="`状态：${label || status}`"><i aria-hidden="true" />{{ label || status }}</span></template>

<style scoped>
.status-indicator { display: inline-flex; align-items: center; gap: 5px; color: var(--text-secondary); font-size:14px; white-space: nowrap; }.status-indicator i { width: 6px; height: 6px; border-radius: 50%; background: var(--text-tertiary); }.status-healthy i, .status-published i, .status-closed i, .status-contained i { background: var(--status-success); }.status-new i, .status-degraded i { background: var(--severity-critical); }.status-investigating i, .status-validating i, .status-training i { background: var(--status-warning); }.status-candidate i { background: var(--severity-info); }.status-validated i { background: var(--accent); }
</style>
