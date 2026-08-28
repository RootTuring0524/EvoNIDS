<script setup lang="ts">defineProps<{ rows?: number; label?: string }>()</script>
<template>
  <div class="loading-state" role="status" aria-live="polite">
    <span class="sr-only">{{ label || '正在加载' }}</span>
    <div v-for="index in (rows || 4)" :key="index" class="skeleton-row"><i /><span /></div>
  </div>
</template>
<style scoped>
.loading-state { padding: 12px; }.skeleton-row { display: grid; grid-template-columns: 86px 1fr; gap: 12px; height: 42px; align-items: center; border-bottom: 1px solid var(--border-subtle); }.skeleton-row i, .skeleton-row span { height: 8px; border-radius: 4px; background: linear-gradient(90deg, var(--surface-2), var(--surface-3), var(--surface-2)); background-size: 240% 100%; animation: shimmer 1.4s ease infinite; }.skeleton-row span { width: 72%; }.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); } @keyframes shimmer { to { background-position: -240% 0; } }
</style>
