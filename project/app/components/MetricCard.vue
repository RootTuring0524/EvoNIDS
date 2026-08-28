<script setup lang="ts">
defineProps<{ label: string; value: string; delta: string; tone: 'critical'|'high'|'good'|'info'|'accent' }>()
</script>

<template>
  <article class="metric-card">
    <p>{{label}}</p>
    <div><strong :class="`tone-${tone}`" class="mono">{{value}}</strong><span>{{delta}}</span></div>
  </article>
</template>

<style scoped>
.metric-card{min-width:0;padding:12px 14px;border-right:1px solid var(--border-subtle)}.metric-card:last-child{border-right:0}.metric-card p{margin:0 0 4px;color:var(--text-tertiary);font-size:12px;font-weight:600;letter-spacing:.02em}.metric-card div{display:flex;align-items:baseline;gap:9px}.metric-card strong{font-size:21px;font-weight:650;transition:color 160ms ease}.metric-card span{overflow:hidden;color:var(--text-tertiary);font-size:12px;text-overflow:ellipsis;white-space:nowrap}.tone-critical{color:var(--severity-critical)}.tone-high{color:var(--severity-high)}.tone-good{color:var(--status-success)}.tone-info{color:var(--severity-info)}.tone-accent{color:var(--accent-strong)}
</style>
