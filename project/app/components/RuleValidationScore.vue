<script setup lang="ts">
import { CheckCircle2, ShieldAlert, XCircle } from '~/utils/icons'
import type { RuleValidation } from '~~/shared/types/security'

const props = defineProps<{ validation: RuleValidation }>()
const weights = [
  { key: 'syntax', label: '语法与结构正确性', weight: 10 },
  { key: 'attackHitAbility', label: '攻击命中能力', weight: 30 },
  { key: 'lowFalsePositive', label: '低误报能力', weight: 25 },
  { key: 'coverage', label: '攻击覆盖率', weight: 15 },
  { key: 'nonRedundancy', label: '非冗余性', weight: 10 },
  { key: 'evidenceConsistency', label: 'RAG 证据一致性', weight: 10 },
] as const

const computedScore = computed(() => weights.reduce((total, item) => total + props.validation[item.key] * item.weight / 100, 0))
const gatePassed = computed(() => props.validation.qualityScore >= 85 && props.validation.falsePositiveRate <= 1 && props.validation.schemaChecks.every((check) => check.passed))
const width = (value: number) => `${Math.min(100, Math.max(0, value))}%`
</script>

<template>
  <section class="score-panel surface-panel">
    <header class="score-head">
      <div><h2>规则质量评分</h2><p>固定权重模型 · 计算值 {{ computedScore.toFixed(1) }} · 回放任务 <code>REPLAY-0716-042</code></p></div>
      <div :class="['total-score', { failed: !gatePassed }]" class="mono">{{ validation.qualityScore }}<small>/100</small><span><CheckCircle2 v-if="gatePassed" :size="13" /><XCircle v-else :size="13" />{{ gatePassed ? '达到人工确认门槛' : '未达到确认门槛' }}</span></div>
    </header>
    <div class="score-body">
      <div class="dimension-list"><div v-for="item in weights" :key="item.key"><p><span>{{ item.label }} <em>权重 {{ item.weight }}%</em></span><b class="mono">{{ validation[item.key] }}</b></p><i><span :style="{ width: width(validation[item.key]) }" /></i></div></div>
      <div class="metric-grid"><div><span>命中率</span><b class="mono">{{ validation.hitRate }}%</b></div><div><span>误报率</span><b class="mono good">{{ validation.falsePositiveRate }}%</b></div><div><span>Precision</span><b class="mono">{{ validation.precision }}%</b></div><div><span>Recall</span><b class="mono">{{ validation.recall }}%</b></div><div><span>F1</span><b class="mono">{{ validation.f1 }}%</b></div><div><span>覆盖率</span><b class="mono">{{ validation.attackCoverage }}%</b></div><div><span>冗余度</span><b class="mono">{{ validation.redundancy }}%</b></div><div><span>阈值稳健性</span><b class="mono">{{ validation.perturbationRobustness }}%</b></div></div>
    </div>
    <footer class="replay-foot"><span>历史攻击流量 <b class="mono">{{ validation.replayAttackFlows.toLocaleString() }}</b></span><span>正常流量 <b class="mono">{{ validation.replayNormalFlows.toLocaleString() }}</b></span><em><ShieldAlert :size="13" />误报主要来自服务网格健康检查</em></footer>
  </section>
</template>

<style scoped>
.score-panel{overflow:hidden}.score-head{display:flex;justify-content:space-between;align-items:center;min-height:78px;padding:12px 16px;border-bottom:1px solid var(--border-subtle)}.score-head h2,.score-head p{margin:0}.score-head h2{font-size:15px}.score-head p{margin-top:4px;color:var(--text-tertiary);font-size:12px}.score-head code{font-size:14px}.total-score{display:grid;grid-template-columns:auto auto;align-items:baseline;color:var(--status-success);font-size:30px;font-weight:700;line-height:1}.total-score.failed{color:var(--status-error)}.total-score small{color:var(--text-tertiary);font-size:12px}.total-score span{grid-column:1/-1;display:flex;align-items:center;gap:4px;margin-top:5px;font-family:inherit;font-size:14px;font-weight:500}.score-body{display:grid;grid-template-columns:1.35fr 1fr}.dimension-list{display:grid;gap:10px;padding:14px 16px;border-right:1px solid var(--border-subtle)}.dimension-list p{display:flex;justify-content:space-between;margin:0 0 4px;color:var(--text-secondary);font-size:12px}.dimension-list em{color:var(--text-tertiary);font-size:14px;font-style:normal}.dimension-list b{font-size:12px}.dimension-list i{display:block;height:4px;background:var(--surface-3)}.dimension-list i span{display:block;height:100%;background:var(--accent)}.metric-grid{display:grid;grid-template-columns:1fr 1fr}.metric-grid div{padding:11px 12px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.metric-grid div:nth-child(even){border-right:0}.metric-grid div:nth-last-child(-n+2){border-bottom:0}.metric-grid span,.metric-grid b{display:block}.metric-grid span{color:var(--text-tertiary);font-size:14px}.metric-grid b{margin-top:3px;font-size:14px}.metric-grid b.good{color:var(--status-success)}.replay-foot{display:flex;gap:18px;align-items:center;min-height:43px;padding:0 15px;border-top:1px solid var(--border-subtle);background:var(--surface-2);color:var(--text-tertiary);font-size:14px}.replay-foot b{color:var(--text-secondary)}.replay-foot em{display:flex;align-items:center;gap:4px;margin-left:auto;color:var(--status-warning);font-style:normal}
@media(max-width:700px){.score-head{align-items:flex-start;gap:12px}.score-body{grid-template-columns:1fr}.dimension-list{border-right:0;border-bottom:1px solid var(--border-subtle)}.replay-foot{flex-wrap:wrap;padding:8px 12px}.replay-foot em{width:100%;margin-left:0}}
</style>
