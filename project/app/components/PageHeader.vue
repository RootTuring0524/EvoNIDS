<script setup lang="ts">
defineProps<{ eyebrow?: string; title: string; description: string }>()
</script>

<template>
  <div class="page-header">
    <div><p v-if="eyebrow">{{ eyebrow }}</p><h1>{{ title }}</h1><span>{{ description }}</span></div>
    <div class="page-actions"><slot /></div>
  </div>
</template>

<style scoped>
.page-header { display: flex; align-items: flex-end; justify-content: space-between; gap: 24px; margin-bottom: 18px; }.page-header p { margin: 0 0 3px; color: var(--accent-strong); font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }.page-header h1 { margin: 0; font-size: 24px; font-weight: 650; letter-spacing: -.02em; }.page-header span { display: block; margin-top: 3px; color: var(--text-secondary); font-size: 14px; }.page-actions { display: flex; gap: 8px; align-items: center; }
@media (max-width: 700px) { .page-header { align-items: flex-start; flex-direction: column; }.page-actions { width: 100%; } }
</style>
