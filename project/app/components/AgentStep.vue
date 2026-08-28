<script setup lang="ts">
import { Check, Circle, LoaderCircle, Wrench, XCircle } from '~/utils/icons'
import { Motion, useReducedMotion } from 'motion-v'
import { computed } from 'vue'
import type { AgentStepRecord } from '~~/shared/types/security'

const props = defineProps<{ step: AgentStepRecord; index: number }>()
const stateLabels = { completed: '已完成', active: '执行中', pending: '等待中', failed: '失败' }
const reducedMotion = useReducedMotion()
const rowAnimation = computed(() => ({
  opacity: props.step.state === 'pending' ? 0.66 : props.step.state === 'active' ? 0.86 : 1,
  scale: props.step.state === 'active' ? 0.995 : 1,
}))
const rowTransition = computed(() => ({ duration: reducedMotion.value ? 0 : 0.2, ease: 'easeOut' as const }))
</script>

<template>
  <Motion as="div" class="step-row" :initial="false" :animate="rowAnimation" :transition="rowTransition" :data-state="step.state" :aria-label="`${index + 1}. ${step.label}，${stateLabels[step.state]}`">
    <span :class="['step-icon', `step-${step.state}`]" aria-hidden="true">
      <Check v-if="step.state === 'completed'" :size="12" />
      <LoaderCircle v-else-if="step.state === 'active'" :size="12" />
      <XCircle v-else-if="step.state === 'failed'" :size="12" />
      <Circle v-else :size="10" />
    </span>
    <div class="step-main">
      <p><b>{{ index + 1 }}. {{ step.label }}</b><span :class="['state-label', `state-${step.state}`]">{{ stateLabels[step.state] }}</span><em class="mono">{{ step.durationMs }} ms</em></p>
      <span>{{ step.result }}</span>
    </div>
    <div class="tool-name"><Wrench :size="11" /><code>{{ step.tool }}</code></div>
  </Motion>
</template>

<style scoped>
.step-row { display: grid; grid-template-columns: 23px minmax(0,1fr) auto; gap: 8px; align-items: center; min-height: 48px; padding: 6px 12px; border-bottom: 1px solid var(--border-subtle); }
.step-row[data-state='failed'] { background: color-mix(in srgb, var(--status-error) 4%, transparent); }
.step-icon { display: grid; width: 20px; height: 20px; place-items: center; border-radius: 50%; background: color-mix(in srgb, var(--status-success) 10%, transparent); color: var(--status-success); }
.step-icon.step-active { background: color-mix(in srgb, var(--status-warning) 10%, transparent); color: var(--status-warning); }
.step-icon.step-active svg { animation: agent-step-spin 900ms linear infinite; }
.step-icon.step-pending { background: var(--surface-3); color: var(--text-disabled); }
.step-icon.step-failed { background: color-mix(in srgb, var(--status-error) 10%, transparent); color: var(--status-error); }
.step-main { min-width: 0; }
.step-main p { display: flex; align-items: center; gap: 6px; margin: 0; }
.step-main b { overflow: hidden; font-size:13px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.step-main em { margin-left: auto; color: var(--text-tertiary); font-size:12px; font-style: normal; white-space: nowrap; }
.step-main > span { display: block; margin-top: 2px; overflow: hidden; color: var(--text-tertiary); font-size:13px; text-overflow: ellipsis; white-space: nowrap; }
.state-label { flex: 0 0 auto; padding: 1px 4px; border-radius: 3px; background: var(--surface-3); color: var(--text-tertiary); font-size:12px; }
.state-completed { color: var(--status-success); }.state-active { color: var(--status-warning); }.state-failed { color: var(--status-error); }
.tool-name { display: flex; align-items: center; gap: 4px; padding: 3px 5px; border: 1px solid var(--border-subtle); border-radius: 4px; color: var(--text-tertiary); font-size:12px; }
.tool-name code { font-size:12px; }
@keyframes agent-step-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .step-icon.step-active svg { animation: none; } }
@media (max-width: 700px) { .tool-name { display: none; }.step-main > span { white-space: normal; } }
</style>
