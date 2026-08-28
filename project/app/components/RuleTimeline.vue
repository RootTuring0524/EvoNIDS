<script setup lang="ts">
import { CheckCircle2, CircleX, Clock3 } from '~/utils/icons'
import type { RuleStage } from '~~/shared/types/security'

interface TimelineEvent {
  id: string
  stage: RuleStage
  timestamp: string
  actor: string
  summary: string
  note?: string
  outcome: 'completed' | 'failed'
}

defineProps<{ items: TimelineEvent[]; currentStage: RuleStage }>()

const stageLabels: Record<RuleStage, string> = {
  candidate: 'Candidate',
  validating: 'Validating',
  validated: 'Validated',
  rejected: 'Rejected',
  repaired: 'Repaired',
  confirmed: 'Confirmed',
  deployed: 'Deployed',
  deprecated: 'Deprecated',
}

const shanghaiTimeFormatter = new Intl.DateTimeFormat('zh-CN-u-ca-iso8601', {
  timeZone: 'Asia/Shanghai',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
})

function formatTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  const parts = Object.fromEntries(
    shanghaiTimeFormatter
      .formatToParts(date)
      .filter(part => part.type !== 'literal')
      .map(part => [part.type, part.value]),
  )

  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} CST`
}
</script>

<template>
  <section class="timeline-panel surface-panel" aria-label="规则生命周期时间线">
    <header>
      <div>
        <h2>生命周期与 Lineage</h2>
        <p>每次状态迁移均由服务端校验并保留操作人、时间与备注</p>
      </div>
      <span class="current-stage"><Clock3 :size="14" />当前 {{ stageLabels[currentStage] }}</span>
    </header>
    <ol v-if="items.length" class="timeline-list">
      <li v-for="(item, index) in items" :key="item.id" :class="{ failed: item.outcome === 'failed', current: index === items.length - 1 }">
        <span class="event-mark">
          <CircleX v-if="item.outcome === 'failed'" :size="14" />
          <CheckCircle2 v-else :size="14" />
        </span>
        <div class="event-main">
          <p><b>{{ stageLabels[item.stage] }}</b><code>{{ item.id }}</code></p>
          <span>{{ item.summary }}</span>
          <blockquote v-if="item.note">{{ item.note }}</blockquote>
        </div>
        <div class="event-meta"><b>{{ item.actor }}</b><time :datetime="item.timestamp" class="mono">{{ formatTime(item.timestamp) }}</time></div>
      </li>
    </ol>
    <EmptyState v-else title="暂无生命周期记录" description="规则状态迁移后将在这里形成不可变记录。" />
  </section>
</template>

<style scoped>
.timeline-panel { overflow: hidden; }
.timeline-panel > header { display: flex; justify-content: space-between; align-items: center; min-height: 64px; padding: 12px 16px; border-bottom: 1px solid var(--border-subtle); }
.timeline-panel h2,.timeline-panel p { margin: 0; }.timeline-panel h2 { font-size: 15px; }.timeline-panel p { margin-top: 3px; color: var(--text-tertiary); font-size: 12px; }
.current-stage { display: inline-flex; align-items: center; gap: 6px; padding: 5px 8px; border: 1px solid var(--border-default); border-radius: 6px; color: var(--accent-strong); font-size: 12px; }
.timeline-list { margin: 0; padding: 0; list-style: none; }.timeline-list li { position: relative; display: grid; grid-template-columns: 28px minmax(0,1fr) auto; gap: 10px; min-height: 72px; padding: 12px 16px; border-bottom: 1px solid var(--border-subtle); }.timeline-list li:last-child { border-bottom: 0; }.timeline-list li.current { background: var(--accent-muted); }.timeline-list li::before { position: absolute; top: 38px; bottom: -13px; left: 29px; width: 1px; background: var(--border-default); content: ''; }.timeline-list li:last-child::before { display: none; }
.event-mark { position: relative; z-index: 1; display: grid; width: 28px; height: 28px; place-items: center; border-radius: 50%; background: color-mix(in srgb,var(--status-success) 12%,var(--surface-2)); color: var(--status-success); }.failed .event-mark { background: color-mix(in srgb,var(--status-error) 12%,var(--surface-2)); color: var(--status-error); }
.event-main { min-width: 0; }.event-main p { display: flex; gap: 8px; align-items: baseline; }.event-main p b { color: var(--text-primary); font-size: 13px; }.event-main code { color: var(--text-tertiary); font-size:14px; }.event-main > span { display: block; margin-top: 3px; color: var(--text-secondary); font-size: 12px; }.event-main blockquote { margin: 6px 0 0; padding-left: 8px; border-left: 2px solid var(--border-strong); color: var(--text-tertiary); font-size: 12px; }
.event-meta { display: grid; align-content: start; gap: 3px; text-align: right; }.event-meta b { color: var(--text-secondary); font-size: 12px; font-weight: 600; }.event-meta time { color: var(--text-tertiary); font-size:14px; }
@media(max-width:700px){.timeline-panel>header{align-items:flex-start;gap:10px;flex-direction:column}.timeline-list li{grid-template-columns:28px minmax(0,1fr)}.event-meta{grid-column:2;text-align:left}.timeline-list li::before{bottom:-37px}}
</style>
