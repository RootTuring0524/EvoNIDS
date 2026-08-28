<script setup lang="ts">
withDefaults(defineProps<{
  rows?: number
  label?: string
}>(), {
  rows: 6,
  label: '正在加载数据',
})
</script>

<template>
  <div class="skeleton" role="status" aria-live="polite" :aria-label="label">
    <span class="sr-only">{{ label }}</span>
    <div v-for="index in rows" :key="index" class="skeleton-row" aria-hidden="true">
      <i /><span /><span /><span />
    </div>
  </div>
</template>

<style scoped>
.skeleton { padding: 7px 12px 12px; }
.skeleton-row { display: grid; grid-template-columns: 56px minmax(180px, 1.5fr) 1fr 90px; gap: 14px; align-items: center; height: 50px; border-bottom: 1px solid var(--border-subtle); }
.skeleton-row i, .skeleton-row span { height: 8px; border-radius: 4px; background: linear-gradient(90deg, var(--surface-2), var(--surface-3), var(--surface-2)); background-size: 240% 100%; animation: skeleton-shimmer 1.4s ease infinite; }
.skeleton-row span:nth-child(3) { width: 76%; }.skeleton-row span:nth-child(4) { width: 56%; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); }
@keyframes skeleton-shimmer { to { background-position: -240% 0; } }
</style>
