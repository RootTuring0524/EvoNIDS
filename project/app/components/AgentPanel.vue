<script setup lang="ts">
import { ClipboardList, ChevronRight, ShieldCheck, Sparkles } from '~/utils/icons'
import type { AgentAnalysis } from '~~/shared/types/security'
import type { AgentRuleProposal } from '~~/shared/schemas/security'
defineProps<{ analysis: AgentAnalysis, proposedRule?: AgentRuleProposal | null, saving?: boolean, canPersist?: boolean }>()
const emit = defineEmits<{ (e: 'saveRule'): void }>()
const decisionLabels = { new_pattern: '新攻击模式', rule_variant: '已有规则变体', known_match: '已知规则命中', benign: '正常 / 已解释行为' }
const runStates = {
  completed: { status: 'healthy', label: '分析完成' },
  running: { status: 'training', label: '运行中' },
  failed: { status: 'degraded', label: '分析失败' },
}
</script>

<template>
  <section class="agent-panel surface-panel">
    <div class="agent-head">
      <div class="model-id"><span><Sparkles :size="15" /></span><div><p>规则演进 Agent</p><h2>{{ analysis.displayModel }}</h2></div></div>
      <div class="run-state"><StatusIndicator :status="runStates[analysis.state].status" :label="runStates[analysis.state].label" /><span class="mono">{{ analysis.runId }}</span></div>
    </div>
    <div class="agent-summary">
      <div><span class="section-label">攻击假设</span><p>{{ analysis.hypothesis }}</p></div>
      <div class="decision"><span class="section-label">模式判断</span><b>{{ decisionLabels[analysis.patternDecision] }}</b></div>
      <div><span class="section-label">研判摘要</span><p>{{ analysis.summary }}</p></div>
      <div><span class="section-label">建议下一步</span><p class="recommendation">{{ analysis.recommendation }}</p></div>
    </div>
    <section v-if="proposedRule" class="rule-proposal" aria-label="候选规则提案">
      <div class="proposal-head">
        <span><ClipboardList :size="14" /></span>
        <div class="proposal-title"><p>候选规则提案</p><h3 class="mono">{{ proposedRule.structured.rule_id }}</h3></div>
        <SeverityBadge :level="proposedRule.structured.severity" />
      </div>
      <div class="proposal-meta">
        <div><span>规则名称</span><b>{{ proposedRule.structured.rule_name }}</b></div>
        <div><span>攻击类型 / 阶段</span><b>{{ proposedRule.structured.attack_type }} · {{ proposedRule.structured.attack_stage }}</b></div>
        <div><span>ATT&amp;CK 映射</span><b class="mono">{{ proposedRule.structured.mitre_technique_ids.join(' / ') || '—' }}</b></div>
        <div><span>关联证据</span><b>{{ proposedRule.structured.evidence_ids.length }} 条 · 仅可信证据</b></div>
      </div>
      <table class="proposal-conditions">
        <thead><tr><th scope="col">字段</th><th scope="col">运算符</th><th scope="col">阈值 / 取值</th></tr></thead>
        <tbody>
          <tr v-for="(condition, index) in proposedRule.structured.conditions" :key="index">
            <td><code>{{ condition.field }}</code></td>
            <td><code>{{ condition.operator }}</code></td>
            <td><b class="mono">{{ Array.isArray(condition.value) ? condition.value.join(', ') : condition.value }}</b></td>
          </tr>
        </tbody>
      </table>
      <p class="proposal-rationale">{{ proposedRule.rationale }}</p>
      <div class="proposal-actions">
        <button :disabled="saving || canPersist === false" @click="emit('saveRule')"><ClipboardList :size="13" />{{ saving ? '保存中…' : '存为候选规则' }}</button>
        <span v-if="canPersist === false">演示模式仅预览提案；连接真实后端后可保存为候选规则</span>
        <span v-else>创建后仍需回放验证与人工确认；Agent 无法直接部署规则</span>
      </div>
    </section>
    <div class="agent-steps">
      <h3>执行记录 <span>仅展示工具、证据与结果，不展示隐藏思维链</span></h3>
      <div class="step-list">
        <AgentStep v-for="(step, index) in analysis.steps" :key="step.id" :step="step" :index="index" />
      </div>
    </div>
    <div class="agent-foot"><ShieldCheck :size="14" /><span>Agent 只能生成建议和候选规则</span><ChevronRight :size="13" /><b>规则部署需要验证通过与人工确认</b></div>
  </section>
</template>

<style scoped>
.agent-panel { overflow: hidden; }.agent-head { display: flex; justify-content: space-between; align-items: center; min-height: 58px; padding: 10px 13px; border-bottom: 1px solid var(--border-subtle); }.model-id { display: flex; align-items: center; gap: 9px; }.model-id > span { display: grid; width: 30px; height: 30px; place-items: center; border: 1px solid color-mix(in srgb, var(--accent) 30%, var(--border-default)); border-radius: 7px; background: var(--accent-muted); color: var(--accent-strong); }.model-id p, .model-id h2 { margin: 0; }.model-id p { color: var(--text-tertiary); font-size:12px; letter-spacing: .06em; text-transform: uppercase; }.model-id h2 { font-size: 13px; }.run-state { display: flex; align-items: center; gap: 9px; color: var(--text-tertiary); font-size:12px; }
.agent-summary { display: grid; grid-template-columns: 1.6fr .55fr; border-bottom: 1px solid var(--border-subtle); }.agent-summary > div { padding: 10px 12px; border-right: 1px solid var(--border-subtle); border-bottom: 1px solid var(--border-subtle); }.agent-summary > div:nth-child(even) { border-right: 0; }.agent-summary > div:nth-last-child(-n+2) { border-bottom: 0; }.agent-summary p { margin: 4px 0 0; color: var(--text-secondary); font-size:13px; line-height: 1.5; }.decision b { display: block; margin-top: 5px; color: var(--accent-strong); font-size: 12px; }.recommendation { color: var(--text-primary) !important; }
.rule-proposal { border-bottom: 1px solid var(--border-subtle); background: var(--surface-2); }.proposal-head { display: flex; align-items: center; gap: 9px; min-height: 44px; padding: 6px 12px; border-bottom: 1px solid var(--border-subtle); }.proposal-head > span { display: grid; width: 26px; height: 26px; place-items: center; border: 1px solid color-mix(in srgb, var(--status-warning) 32%, var(--border-default)); border-radius: 6px; background: color-mix(in srgb, var(--status-warning) 10%, var(--surface-1)); color: var(--status-warning); }.proposal-title { margin-right: auto; }.proposal-title p { margin: 0; color: var(--text-tertiary); font-size:12px; letter-spacing: .06em; text-transform: uppercase; }.proposal-title h3 { margin: 1px 0 0; font-size: 13px; }
.proposal-meta { display: grid; grid-template-columns: 1.2fr 1.2fr .9fr .9fr; border-bottom: 1px solid var(--border-subtle); }.proposal-meta > div { padding: 8px 12px; border-right: 1px solid var(--border-subtle); }.proposal-meta > div:last-child { border-right: 0; }.proposal-meta span { display: block; color: var(--text-tertiary); font-size:12px; }.proposal-meta b { display: block; overflow: hidden; margin-top: 2px; color: var(--text-secondary); font-size:13px; font-weight: 550; text-overflow: ellipsis; white-space: nowrap; }
.proposal-conditions { width: 100%; border-collapse: collapse; }.proposal-conditions th { padding: 6px 12px; border-bottom: 1px solid var(--border-subtle); color: var(--text-tertiary); font-size:12px; font-weight: 500; text-align: left; }.proposal-conditions td { padding: 6px 12px; border-bottom: 1px solid var(--border-subtle); font-size:13px; }.proposal-conditions tbody tr:last-child td { border-bottom: 0; }.proposal-conditions code { color: var(--text-secondary); font-size:12.5px; }.proposal-conditions td b { color: var(--text-primary); font-weight: 550; }
.proposal-rationale { margin: 0; padding: 8px 12px; border-top: 1px solid var(--border-subtle); color: var(--text-secondary); font-size:12.5px; line-height: 1.55; }
.proposal-actions { display: flex; align-items: center; gap: 9px; padding: 8px 12px 10px; }.proposal-actions button { display: flex; align-items: center; gap: 5px; height: 30px; padding: 0 10px; border: 1px solid color-mix(in srgb, var(--accent) 48%, var(--border-default)); border-radius: 7px; background: var(--accent-muted); color: var(--accent-strong); font-size:13px; cursor: pointer; }.proposal-actions button:disabled { cursor: wait; opacity: .6; }.proposal-actions span { color: var(--text-tertiary); font-size:12px; }
.agent-steps h3 { display: flex; justify-content: space-between; margin: 0; padding: 9px 12px; border-bottom: 1px solid var(--border-subtle); font-size:13px; }.agent-steps h3 span { color: var(--text-tertiary); font-size:12px; font-weight: 400; }.agent-foot { display: flex; align-items: center; justify-content: center; gap: 6px; min-height: 38px; background: var(--surface-2); color: var(--text-tertiary); font-size:13px; }.agent-foot svg:first-child { color: var(--status-success); }.agent-foot b { color: var(--text-secondary); }
@media (max-width: 700px) { .agent-summary { grid-template-columns: 1fr; }.agent-summary > div { border-right: 0; }.tool-name { display: none; }.run-state .mono { display: none; }.agent-steps h3 span { display: none; }.proposal-meta { grid-template-columns: 1fr 1fr; }.proposal-meta > div { border-bottom: 1px solid var(--border-subtle); }.proposal-actions { flex-wrap: wrap; } }
</style>
