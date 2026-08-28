<script setup lang="ts">
import { Ban, CheckCircle2, ChevronDown, ChevronUp, ShieldAlert, ShieldCheck } from '~/utils/icons'
import type { RagEvidence } from '~~/shared/types/security'
defineProps<{ items: RagEvidence[]; query?: string; topK?: number }>()
const expanded = ref<string | null>(null)
</script>

<template>
  <section class="rag-panel surface-panel">
    <div class="rag-head">
      <div><h2>混合检索证据</h2><p>向量召回 + 关键词匹配 + 可信度重排</p></div>
      <div v-if="query" class="query-box"><span>查询</span><code>{{ query }}</code></div>
      <div class="rag-stats"><b>{{ items.filter((item) => item.usedByAgent).length }}</b><span>实际提供给 Agent</span><i /><b>{{ items.filter((item) => !item.allowed).length }}</b><span>已过滤</span><em v-if="topK">Top {{ topK }} 候选</em></div>
    </div>
    <div class="evidence-table">
      <div class="evidence-header"><span>排名 / 来源</span><span>可信度</span><span>检索评分</span><span>Agent 使用目的</span><span>Agent 决策</span><span /></div>
      <article v-for="(item, index) in items" :key="item.id" :class="{ blocked: !item.allowed, selected: item.usedByAgent }">
        <button class="evidence-row" :aria-expanded="expanded === item.id" @click="expanded = expanded === item.id ? null : item.id">
          <span class="source-cell"><em class="mono">{{ String(index + 1).padStart(2, '0') }}</em><i><b>{{ item.title }}</b><small>{{ item.sourceType }} · <code>{{ item.sourceId }}</code></small></i></span>
          <span><em :class="['trust', `trust-${item.trust}`]">{{ item.trust === 'high' ? '高可信' : item.trust === 'medium' ? '中可信' : '低可信' }}</em></span>
          <span class="score-cell"><b class="mono">{{ item.rerankScore.toFixed(2) }}</b><i><span :style="{ width: `${item.rerankScore * 100}%` }" /></i></span>
          <span class="purpose">{{ item.purpose }}</span>
          <span><em v-if="item.usedByAgent" class="safe"><ShieldCheck :size="12" />已采用</em><em v-else-if="!item.allowed" class="deny"><Ban :size="12" />隔离</em><em v-else-if="item.promptInjectionRisk === 'review'" class="review"><ShieldAlert :size="12" />待复核</em><em v-else class="candidate"><CheckCircle2 :size="12" />候选</em></span>
          <component :is="expanded === item.id ? ChevronUp : ChevronDown" :size="13" />
        </button>
        <div v-if="expanded === item.id" class="evidence-detail">
          <div><span class="section-label">命中文本片段</span><blockquote>{{ item.excerpt }}</blockquote></div>
          <dl><div><dt>向量分</dt><dd class="mono">{{ item.vectorScore.toFixed(2) }}</dd></div><div><dt>关键词分</dt><dd class="mono">{{ item.keywordScore.toFixed(2) }}</dd></div><div><dt>综合排序</dt><dd class="mono">{{ item.rerankScore.toFixed(2) }}</dd></div><div><dt>相关度</dt><dd class="mono">{{ item.relevance }}%</dd></div><div><dt>更新时间</dt><dd>{{ item.updatedAt }}</dd></div><div><dt>允许使用</dt><dd>{{ item.allowed ? '是' : '否' }}</dd></div><div><dt>实际提供给 Agent</dt><dd>{{ item.usedByAgent ? '是' : '否' }}</dd></div><div><dt>Prompt Injection</dt><dd>{{ item.promptInjectionRisk }}</dd></div></dl>
          <div class="keywords"><span v-for="keyword in item.matchedKeywords" :key="keyword">{{ keyword }}</span></div>
        </div>
      </article>
    </div>
    <div class="rag-foot"><CheckCircle2 :size="13" /><span>证据白名单在进入 Agent 上下文前执行；被隔离来源不会参与结论或规则生成。</span></div>
  </section>
</template>

<style scoped>
.rag-panel { overflow: hidden; }.rag-head { display: grid; grid-template-columns: auto minmax(260px,1fr) auto; gap: 18px; align-items: center; min-height: 63px; padding: 10px 13px; border-bottom: 1px solid var(--border-subtle); }.rag-head h2,.rag-head p { margin: 0; }.rag-head h2 { font-size: 13px; }.rag-head p { margin-top: 2px; color: var(--text-tertiary); font-size:13px; }.query-box { display: flex; gap: 8px; align-items: center; min-width: 0; padding: 7px 9px; border-left: 2px solid var(--accent); background: var(--surface-2); }.query-box span { color: var(--text-tertiary); font-size:12px; text-transform: uppercase; }.query-box code { overflow: hidden; color: var(--text-secondary); font-size:13px; text-overflow: ellipsis; white-space: nowrap; }.rag-stats { display: grid; grid-template-columns: auto auto 1px auto auto; gap: 5px; align-items: baseline; }.rag-stats b { font-size: 14px; }.rag-stats span { color: var(--text-tertiary); font-size:12px; }.rag-stats i { width: 1px; height: 18px; margin: 0 4px; background: var(--border-default); }.rag-stats em { grid-column: 1/-1; color: var(--text-tertiary); font-size:12px; font-style: normal; text-align: right; }
.evidence-header, .evidence-row { display: grid; grid-template-columns: minmax(240px,1.6fr) 70px 100px minmax(180px,1.2fr) 72px 18px; gap: 9px; align-items: center; }.evidence-header { min-height: 30px; padding: 0 12px; background: var(--surface-2); color: var(--text-tertiary); font-size:12px; font-weight: 650; }.evidence-row { width: 100%; min-height: 53px; padding: 6px 12px; border: 0; border-top: 1px solid var(--border-subtle); background: transparent; color: var(--text-secondary); cursor: pointer; text-align: left; }.evidence-row:hover { background: var(--surface-2); }.selected .evidence-row { box-shadow: inset 2px 0 var(--accent); }.blocked .evidence-row { opacity: .62; }.source-cell { display: grid; grid-template-columns: 24px 1fr; gap: 7px; min-width: 0; }.source-cell > em { color: var(--text-tertiary); font-size:13px; font-style: normal; }.source-cell i { min-width: 0; font-style: normal; }.source-cell b,.source-cell small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.source-cell b { color: var(--text-primary); font-size:13px; font-weight: 600; }.source-cell small { margin-top: 2px; color: var(--text-tertiary); font-size:12px; }.source-cell code { font-size:12px; }.trust { padding: 2px 5px; border-radius: 4px; font-size:12px; font-style: normal; }.trust-high { color: var(--status-success); background: color-mix(in srgb, var(--status-success) 9%, transparent); }.trust-medium { color: var(--status-warning); background: color-mix(in srgb, var(--status-warning) 9%, transparent); }.trust-low { color: var(--text-tertiary); background: var(--surface-3); }.score-cell { display: flex; align-items: center; gap: 6px; }.score-cell b { width: 24px; font-size:13px; }.score-cell i { flex: 1; height: 3px; background: var(--surface-3); }.score-cell i span { display: block; height: 100%; background: var(--accent); }.purpose { overflow: hidden; color: var(--text-tertiary); font-size:12px; text-overflow: ellipsis; white-space: nowrap; }.safe,.review,.deny,.candidate { display: flex; align-items: center; gap: 3px; font-size:12px; font-style: normal; }.safe { color: var(--status-success); }.review { color: var(--status-warning); }.deny { color: var(--status-error); }.candidate { color: var(--text-tertiary); }
.evidence-detail { display: grid; grid-template-columns: 1.5fr 1fr; gap: 12px; padding: 10px 43px; border-top: 1px dashed var(--border-default); background: var(--surface-2); }.evidence-detail blockquote { margin: 5px 0 0; padding-left: 9px; border-left: 1px solid var(--border-strong); color: var(--text-secondary); font-size:13px; line-height: 1.6; }.evidence-detail dl { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 12px; margin: 0; }.evidence-detail dl div { display: flex; justify-content: space-between; gap: 6px; }.evidence-detail dt,.evidence-detail dd { font-size:12px; }.evidence-detail dt { color: var(--text-tertiary); }.evidence-detail dd { margin: 0; color: var(--text-secondary); }.keywords { grid-column: 1/-1; display: flex; gap: 4px; }.keywords span { padding: 2px 5px; border: 1px solid var(--border-subtle); border-radius: 4px; color: var(--text-tertiary); font-size:12px; }.rag-foot { display: flex; align-items: center; gap: 5px; min-height: 35px; padding: 0 12px; border-top: 1px solid var(--border-subtle); color: var(--text-tertiary); font-size:12px; }.rag-foot svg { color: var(--status-success); }
@media (max-width: 900px) { .rag-head { grid-template-columns: 1fr; }.rag-stats { display: none; }.evidence-header { display: none; }.evidence-row { grid-template-columns: 1fr auto 18px; }.evidence-row > span:nth-child(2), .evidence-row > span:nth-child(3), .evidence-row > span:nth-child(4) { display: none; }.evidence-detail { grid-template-columns: 1fr; padding: 10px 16px; } }
</style>
