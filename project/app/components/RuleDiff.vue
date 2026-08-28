<script setup lang="ts">
import { ArrowRight, Minus, Plus, SlidersHorizontal } from '~/utils/icons'
import type { RuleCondition, StructuredRule } from '~~/shared/types/security'

const props = defineProps<{ before: StructuredRule; after: StructuredRule; reason: string; coverageChange: string; falsePositiveRisk: string }>()

interface DiffRow {
  field: string
  kind: 'added' | 'removed' | 'changed'
  before?: RuleCondition
  after?: RuleCondition
  label: string
}

const serializeValue = (value: RuleCondition['value']) => Array.isArray(value) ? value.join(', ') : String(value)
const sameCondition = (before: RuleCondition, after: RuleCondition) => before.operator === after.operator && JSON.stringify(before.value) === JSON.stringify(after.value)

const rows = computed<DiffRow[]>(() => {
  const result: DiffRow[] = []
  const beforeByField = new Map(props.before.conditions.map((item) => [item.field, item]))
  const afterByField = new Map(props.after.conditions.map((item) => [item.field, item]))

  for (const condition of props.before.conditions) {
    const next = afterByField.get(condition.field)
    if (!next) {
      result.push({ field: condition.field, kind: 'removed', before: condition, label: '删除条件' })
    } else if (!sameCondition(condition, next)) {
      result.push({
        field: condition.field,
        kind: 'changed',
        before: condition,
        after: next,
        label: condition.operator === next.operator ? '阈值变化' : '运算符 / 阈值变化',
      })
    }
  }

  for (const condition of props.after.conditions) {
    if (!beforeByField.has(condition.field)) result.push({ field: condition.field, kind: 'added', after: condition, label: '新增条件' })
  }
  return result
})

const counts = computed(() => ({
  added: rows.value.filter((row) => row.kind === 'added').length,
  removed: rows.value.filter((row) => row.kind === 'removed').length,
  changed: rows.value.filter((row) => row.kind === 'changed').length,
  unchanged: props.after.conditions.filter((after) => props.before.conditions.some((before) => before.field === after.field && sameCondition(before, after))).length,
}))
</script>

<template>
  <section class="diff-panel surface-panel">
    <header class="diff-head">
      <div><h2>Rule Diff</h2><p><code>{{ before.rule_id }} v{{ before.version }}</code><ArrowRight :size="13" /><code>{{ after.rule_id }} v{{ after.version }}</code></p></div>
      <div class="diff-counts" aria-label="规则变更统计"><span class="added"><Plus :size="12" />新增 {{ counts.added }}</span><span class="removed"><Minus :size="12" />删除 {{ counts.removed }}</span><span class="changed"><SlidersHorizontal :size="12" />阈值 {{ counts.changed }}</span><span>未变 {{ counts.unchanged }}</span></div>
    </header>

    <div v-if="rows.length" class="diff-table" role="table" aria-label="结构化条件变更">
      <div class="diff-table-head" role="row"><span role="columnheader">变更</span><span role="columnheader">字段</span><span role="columnheader">修改前</span><span /><span role="columnheader">修改后</span></div>
      <div v-for="row in rows" :key="`${row.kind}-${row.field}`" :class="['diff-row', row.kind]" role="row">
        <span><em>{{ row.label }}</em></span>
        <code>{{ row.field }}</code>
        <span class="condition-value"><template v-if="row.before"><b>{{ row.before.operator }}</b><code>{{ serializeValue(row.before.value) }}</code></template><i v-else>—</i></span>
        <ArrowRight :size="14" />
        <span class="condition-value"><template v-if="row.after"><b>{{ row.after.operator }}</b><code>{{ serializeValue(row.after.value) }}</code></template><i v-else>—</i></span>
      </div>
    </div>
    <EmptyState v-else title="条件没有变化" description="当前版本与父版本的结构化条件一致。" />

    <div class="diff-notes"><div><span>修改原因</span><p>{{ reason }}</p></div><div><span>预期覆盖范围变化</span><p>{{ coverageChange }}</p></div><div class="risk"><span>潜在误报风险</span><p>{{ falsePositiveRisk }}</p></div></div>
  </section>
</template>

<style scoped>
.diff-panel{overflow:hidden}.diff-head{display:flex;justify-content:space-between;align-items:center;gap:16px;min-height:64px;padding:11px 15px;border-bottom:1px solid var(--border-subtle)}.diff-head h2,.diff-head p{margin:0}.diff-head h2{font-size:15px}.diff-head p{display:flex;align-items:center;gap:6px;margin-top:3px;color:var(--text-tertiary);font-size:12px}.diff-head code{font-size:14px}.diff-counts{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}.diff-counts span{display:inline-flex;align-items:center;gap:3px;padding:3px 6px;border:1px solid var(--border-subtle);border-radius:5px;color:var(--text-tertiary);font-size:14px}.diff-counts .added{color:var(--status-success)}.diff-counts .removed{color:var(--status-error)}.diff-counts .changed{color:var(--status-warning)}
.diff-table-head,.diff-row{display:grid;grid-template-columns:110px minmax(190px,1fr) minmax(120px,.7fr) 24px minmax(120px,.7fr);gap:10px;align-items:center}.diff-table-head{min-height:34px;padding:0 14px;background:var(--surface-2);color:var(--text-tertiary);font-size:14px;font-weight:650}.diff-row{min-height:52px;padding:8px 14px;border-top:1px solid var(--border-subtle);color:var(--text-secondary);font-size:12px}.diff-row>span:first-child em{display:inline-flex;padding:3px 6px;border-radius:4px;font-size:14px;font-style:normal}.diff-row.added>span:first-child em{background:color-mix(in srgb,var(--status-success) 10%,transparent);color:var(--status-success)}.diff-row.removed>span:first-child em{background:color-mix(in srgb,var(--status-error) 10%,transparent);color:var(--status-error)}.diff-row.changed>span:first-child em{background:color-mix(in srgb,var(--status-warning) 10%,transparent);color:var(--status-warning)}.diff-row>code{overflow:hidden;font-size:12px;text-overflow:ellipsis}.diff-row>svg{color:var(--border-strong)}.condition-value{display:flex;gap:7px;align-items:center}.condition-value b{min-width:22px;color:var(--text-secondary);font-size:12px}.condition-value code{color:var(--text-primary);font-size:12px}.condition-value i{color:var(--text-disabled);font-style:normal}
.diff-notes{display:grid;grid-template-columns:1.25fr 1fr 1fr;border-top:1px solid var(--border-subtle)}.diff-notes>div{padding:12px 14px;border-right:1px solid var(--border-subtle)}.diff-notes>div:last-child{border-right:0}.diff-notes span{color:var(--text-tertiary);font-size:14px;text-transform:uppercase}.diff-notes p{margin:5px 0 0;color:var(--text-secondary);font-size:12px;line-height:1.55}.diff-notes .risk p{color:var(--status-warning)}
@media(max-width:760px){.diff-head{align-items:flex-start;flex-direction:column}.diff-counts{justify-content:flex-start}.diff-table{overflow-x:auto}.diff-table-head,.diff-row{min-width:720px}.diff-notes{grid-template-columns:1fr}.diff-notes>div{border-right:0;border-bottom:1px solid var(--border-subtle)}}
</style>
