<script setup lang="ts">
import { CircleAlert, RefreshCw } from '~/utils/icons'
defineProps<{ title?: string; description?: string }>()
const emit = defineEmits<{ retry: [] }>()
</script>
<template><div class="error-state" role="alert"><CircleAlert :size="20" /><div><b>{{ title || '数据加载失败' }}</b><p>{{ description || '服务暂时不可用，请稍后重试。' }}</p></div><button @click="emit('retry')"><RefreshCw :size="13" />重试</button></div></template>
<style scoped>
.error-state { display: flex; align-items: center; gap: 10px; min-height: 92px; padding: 16px; color: var(--status-error); }.error-state div { flex: 1; }.error-state b { color: var(--text-primary); font-size: 12px; }.error-state p { margin: 2px 0 0; color: var(--text-tertiary); font-size:13px; }.error-state button { display: flex; align-items: center; gap: 4px; padding: 5px 8px; border: 1px solid var(--border-default); border-radius: 6px; background: var(--surface-2); color: var(--text-secondary); cursor: pointer; }
</style>
