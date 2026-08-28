<script setup lang="ts">
import { ChevronRight, Home } from '~/utils/icons'

defineProps<{
  items: Array<{ label: string; to?: string }>
}>()
</script>

<template>
  <nav class="breadcrumb" aria-label="面包屑导航">
    <ol>
      <li>
        <NuxtLink to="/overview" aria-label="运营态势首页"><Home :size="12" aria-hidden="true" /></NuxtLink>
      </li>
      <li v-for="(item, index) in items" :key="`${item.label}-${index}`">
        <ChevronRight :size="11" aria-hidden="true" />
        <NuxtLink v-if="item.to && index < items.length - 1" :to="item.to">{{ item.label }}</NuxtLink>
        <span v-else :aria-current="index === items.length - 1 ? 'page' : undefined">{{ item.label }}</span>
      </li>
    </ol>
  </nav>
</template>

<style scoped>
.breadcrumb { margin-bottom: 9px; }
.breadcrumb ol { display: flex; align-items: center; gap: 4px; margin: 0; padding: 0; list-style: none; }
.breadcrumb li { display: flex; align-items: center; gap: 4px; color: var(--text-tertiary); font-size:13px; }
.breadcrumb a { display: inline-flex; align-items: center; min-height: 24px; color: var(--text-tertiary); text-decoration: none; }
.breadcrumb a:hover { color: var(--text-primary); }
.breadcrumb span[aria-current='page'] { color: var(--text-secondary); }
</style>
