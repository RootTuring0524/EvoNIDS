<script setup lang="ts">
import { CheckCircle2, CircleAlert, Info, X } from '~/utils/icons'

const props = withDefaults(defineProps<{
  open: boolean
  title: string
  description?: string
  tone?: 'success' | 'error' | 'info'
  duration?: number
}>(), {
  description: '',
  tone: 'success',
  duration: 3200,
})

const emit = defineEmits<{ 'update:open': [value: boolean] }>()
const icon = computed(() => props.tone === 'error' ? CircleAlert : props.tone === 'info' ? Info : CheckCircle2)
let timer: ReturnType<typeof setTimeout> | undefined

watch(() => props.open, (open) => {
  if (timer) clearTimeout(timer)
  if (open && props.duration > 0) timer = setTimeout(() => emit('update:open', false), props.duration)
}, { immediate: true })

onBeforeUnmount(() => { if (timer) clearTimeout(timer) })
</script>

<template>
  <Teleport to="body">
    <Transition name="toast">
      <div v-if="open" :class="['toast', `toast-${tone}`]" :role="tone === 'error' ? 'alert' : 'status'" aria-live="polite">
        <component :is="icon" :size="16" aria-hidden="true" />
        <div><b>{{ title }}</b><p v-if="description">{{ description }}</p></div>
        <button type="button" aria-label="关闭提示" @click="emit('update:open', false)"><X :size="13" aria-hidden="true" /></button>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.toast { position: fixed; z-index: 100; top: 66px; right: 18px; display: grid; grid-template-columns: 18px minmax(180px, 1fr) 26px; gap: 8px; align-items: center; width: min(380px, calc(100vw - 28px)); padding: 10px 9px 10px 11px; border: 1px solid var(--border-default); border-radius: 9px; background: var(--surface-2); color: var(--text-secondary); box-shadow: 0 14px 34px rgba(0, 0, 0, .24); }
.toast > svg { color: var(--accent-strong); }.toast-success > svg { color: var(--status-success); }.toast-error > svg { color: var(--status-error); }
.toast b { display: block; color: var(--text-primary); font-size:14px; }.toast p { margin: 2px 0 0; color: var(--text-tertiary); font-size:13px; }
.toast button { display: grid; width: 26px; height: 26px; place-items: center; border: 0; border-radius: 6px; background: transparent; color: var(--text-tertiary); cursor: pointer; }.toast button:hover { background: var(--surface-3); color: var(--text-primary); }
.toast-enter-active, .toast-leave-active { transition: opacity 180ms ease, transform 180ms ease; }.toast-enter-from, .toast-leave-to { opacity: 0; transform: translateY(-5px); }
</style>
