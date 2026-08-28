<script setup lang="ts">import { SearchX } from '~/utils/icons'; defineProps<{ title?: string; description?: string }>()</script>
<template><div class="empty-state"><SearchX :size="24" /><b>{{ title || '没有匹配结果' }}</b><p>{{ description || '调整筛选条件后再试。' }}</p><slot /></div></template>
<style scoped>.empty-state { display: grid; min-height: 180px; place-items: center; align-content: center; color: var(--text-tertiary); text-align: center; }.empty-state b { margin-top: 8px; color: var(--text-secondary); font-size: 12px; }.empty-state p { margin: 2px 0; font-size:13px; }</style>
