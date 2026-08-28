<script setup lang="ts">
import { FilterX } from '~/utils/icons'

withDefaults(defineProps<{
  label?: string
  dirty?: boolean
  resetLabel?: string
}>(), {
  label: '数据筛选',
  dirty: false,
  resetLabel: '重置',
})

const emit = defineEmits<{ reset: [] }>()
</script>

<template>
  <section class="filter-bar-shell surface-panel" role="search" :aria-label="label">
    <div class="filter-fields"><slot /></div>
    <div class="filter-actions">
      <slot name="actions" />
      <button class="reset-control" type="button" :disabled="!dirty" @click="emit('reset')">
        <FilterX :size="13" aria-hidden="true" />{{ resetLabel }}
      </button>
    </div>
  </section>
</template>

<style scoped>
.filter-bar-shell { display: flex; gap: 8px; align-items: end; margin-bottom: 12px; padding: 10px; }
.filter-fields { display: grid; grid-template-columns: minmax(220px, 1fr) repeat(3, minmax(124px, auto)); gap: 8px; flex: 1; min-width: 0; }
.filter-actions { display: flex; gap: 6px; align-items: end; }
.reset-control { display: inline-flex; align-items: center; gap: 4px; height: 32px; padding: 0 9px; border: 1px solid var(--border-default); border-radius: 6px; background: var(--surface-2); color: var(--text-secondary); font-size:13px; cursor: pointer; }
.reset-control:disabled { color: var(--text-disabled); cursor: not-allowed; opacity: .7; }
@media (max-width: 1050px) {
  .filter-bar-shell { align-items: stretch; flex-direction: column; }
  .filter-fields { width: 100%; grid-template-columns: 1fr 1fr; }
  .filter-actions { justify-content: flex-end; }
}
@media (max-width: 650px) {
  .filter-fields { grid-template-columns: 1fr; }
  .filter-actions { justify-content: stretch; }
  .filter-actions :deep(button) { flex: 1; justify-content: center; }
}
</style>
