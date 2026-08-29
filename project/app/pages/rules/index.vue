<script setup lang="ts">
import { ArrowRight, Bot, CheckCircle2, ChevronRight, FileCheck2, RefreshCw, Search, ShieldCheck, XCircle } from '~/utils/icons'
import { rulesResponseSchema } from '~~/shared/schemas/security'
import type { RuleRecord, RuleStage } from '~~/shared/types/security'

const { data, status, error, refresh } = await useAsyncData('rules', () => validatedFetch('/rules', rulesResponseSchema))
const search = ref('')
const stageFilter = ref<'all' | RuleStage>('all')
const attackFilter = ref('all')
const detailRuleIds = new Set(['EVO-2026-0716-14'])
const config = useRuntimeConfig()
const router = useRouter()

const stageLabels: Record<RuleStage, string> = {
  candidate: 'Candidate', validating: 'Validating', validated: 'Validated', rejected: 'Rejected',
  repaired: 'Repaired', confirmed: 'Confirmed', deployed: 'Deployed', deprecated: 'Deprecated',
}
const sourceLabels = { agent: 'DeepSeek V4 Pro', analyst: '分析师', community: '社区规则' }

const items = computed(() => data.value?.items ?? [])
const attackOptions = computed(() => [...new Set(items.value.map((rule) => rule.coverage.split('/')[0]?.trim()).filter(Boolean))])
const filteredRules = computed(() => {
  const keyword = search.value.trim().toLowerCase()
  return items.value.filter((rule) => {
    const matchesSearch = !keyword || `${rule.id} ${rule.name} ${rule.coverage} ${rule.author}`.toLowerCase().includes(keyword)
    const matchesStage = stageFilter.value === 'all' || rule.stage === stageFilter.value
    const matchesAttack = attackFilter.value === 'all' || rule.coverage.startsWith(attackFilter.value)
    return matchesSearch && matchesStage && matchesAttack
  })
})

const countFor = (stage: RuleStage) => items.value.filter((rule) => rule.stage === stage).length
const primaryRule = computed(() => items.value.find((rule) => rule.id === 'EVO-2026-0716-14'))

const normalFlow: RuleStage[] = ['candidate', 'validating', 'validated', 'confirmed', 'deployed']
const failedFlow: RuleStage[] = ['candidate', 'validating', 'rejected']
const repairFlow: RuleStage[] = ['rejected', 'repaired', 'validating', 'validated', 'confirmed']

function quality(rule: RuleRecord) {
  return rule.qualityScore ?? null
}

function openRule(id: string) {
  return router.push(`/rules/${id}`)
}

function hasDetail(id: string) {
  return !config.public.useMockApi || detailRuleIds.has(id)
}
</script>

<template>
  <div class="rules-page">
    <PageHeader eyebrow="Rule Evolution" title="规则进化中心" description="从异常证据到结构化规则、回放验证、人工确认与受控部署的完整生命周期">
      <button class="page-button" :disabled="status === 'pending'" @click="() => refresh()"><RefreshCw :size="15" :class="{ spin: status === 'pending' }" />刷新规则状态</button>
    </PageHeader>

    <section class="lifecycle surface-panel" aria-labelledby="lifecycle-title">
      <header class="lifecycle-head"><div><h2 id="lifecycle-title">规则生命周期分支</h2><p>正常、失败与修复路径独立表达；任何迁移均由服务端状态机校验</p></div><span><ShieldCheck :size="14" />部署审批策略已启用</span></header>
      <div class="lifecycle-branches">
        <div class="branch normal"><div class="branch-label"><CheckCircle2 :size="15" /><span><b>正常流程</b><small>候选规则验证通过后必须先人工确认</small></span></div><div class="stage-track"><template v-for="(stage,index) in normalFlow" :key="stage"><div :class="['stage-node',`stage-${stage}`,{populated:countFor(stage)>0}]"><b class="mono">{{ countFor(stage) }}</b><span>{{ stageLabels[stage] }}</span></div><ArrowRight v-if="index<normalFlow.length-1" :size="14" /></template></div></div>
        <div class="branch failed"><div class="branch-label"><XCircle :size="15" /><span><b>失败流程</b><small>回放或结构门禁失败，不允许进入确认</small></span></div><div class="stage-track"><template v-for="(stage,index) in failedFlow" :key="stage"><div :class="['stage-node',`stage-${stage}`,{populated:countFor(stage)>0}]"><b class="mono">{{ countFor(stage) }}</b><span>{{ stageLabels[stage] }}</span></div><ArrowRight v-if="index<failedFlow.length-1" :size="14" /></template></div></div>
        <div class="branch repair"><div class="branch-label"><RefreshCw :size="15" /><span><b>修复流程</b><small>失败规则或旧规则创建新版本后重新回放</small></span></div><div class="stage-track"><template v-for="(stage,index) in repairFlow" :key="stage"><div :class="['stage-node',`stage-${stage}`,{populated:countFor(stage)>0}]"><b class="mono">{{ countFor(stage) }}</b><span>{{ stageLabels[stage] }}</span></div><ArrowRight v-if="index<repairFlow.length-1" :size="14" /></template></div></div>
      </div>
    </section>

    <section v-if="primaryRule" class="evolution-flow" aria-label="最近规则闭环">
      <div class="agent-run"><span class="agent-icon"><Bot :size="18" /></span><div><p>最近一次 Agent 产出</p><b>{{ primaryRule.name }}</b><small><code>AGENT-RUN-0716-0284</code> · 使用 4 条已授权证据 · 1.07 s</small></div><NuxtLink to="/alerts/ALT-78435">查看来源研判 <ChevronRight :size="14" /></NuxtLink></div>
      <div class="validation-run"><FileCheck2 :size="18" /><div><p>当前闭环阶段</p><b>{{ stageLabels[primaryRule.stage] }}</b><span>质量 {{ primaryRule.qualityScore ?? '—' }} · 误报 {{ primaryRule.falsePositiveRate }}%</span></div><NuxtLink to="/rules/EVO-2026-0716-14">打开规则详情</NuxtLink></div>
    </section>

    <section class="rule-toolbar surface-panel" aria-label="规则筛选">
      <label class="search-field"><span class="sr-only">搜索规则</span><Search :size="15" /><input v-model="search" placeholder="规则 ID、名称、MITRE 技术或作者…"></label>
      <label><span>生命周期</span><select v-model="stageFilter"><option value="all">全部生命周期</option><option v-for="(label,key) in stageLabels" :key="key" :value="key">{{ label }}</option></select></label>
      <label><span>攻击类型</span><select v-model="attackFilter"><option value="all">全部攻击类型</option><option v-for="attack in attackOptions" :key="attack" :value="attack">{{ attack }}</option></select></label>
      <button v-if="search || stageFilter !== 'all' || attackFilter !== 'all'" class="clear-button" @click="search='';stageFilter='all';attackFilter='all'">清除筛选</button>
    </section>

    <section class="rule-table surface-panel">
      <LoadingState v-if="status === 'pending'" :rows="5" />
      <ErrorState v-else-if="error" @retry="refresh" />
      <EmptyState v-else-if="filteredRules.length === 0" title="没有匹配规则" description="调整生命周期、攻击类型或搜索条件后重试。" />
      <template v-else>
        <div class="table-scroll"><table><thead><tr><th>规则 / 版本</th><th>生命周期</th><th>攻击覆盖</th><th>来源</th><th>质量分</th><th>命中率</th><th>误报率</th><th>更新</th><th>详情</th></tr></thead><tbody>
          <tr v-for="rule in filteredRules" :key="rule.id" :class="{ unavailable: !hasDetail(rule.id) }"><td><b>{{ rule.name }}</b><small><code>{{ rule.id }}</code> · revision {{ rule.revision }}</small></td><td><span :class="['stage-badge', `stage-${rule.stage}`]"><i />{{ stageLabels[rule.stage] }}</span></td><td>{{ rule.coverage }}</td><td>{{ sourceLabels[rule.source] }}</td><td><b v-if="quality(rule) !== null" class="mono quality">{{ quality(rule) }}</b><span v-else>—</span></td><td class="mono">{{ rule.hitRate }}%</td><td class="mono" :class="{ good: rule.falsePositiveRate < 1, warning: rule.falsePositiveRate >= 1 }">{{ rule.falsePositiveRate }}%</td><td class="mono subtle">{{ rule.updatedAt }}</td><td><a v-if="hasDetail(rule.id)" :href="`/rules/${rule.id}`" :aria-label="`打开 ${rule.name} 详情`" @click.prevent.stop="openRule(rule.id)">打开 <ChevronRight :size="14" /></a><span v-else class="unavailable-label" title="当前原型尚未提供该规则的一致详情数据">详情待接入</span></td></tr>
        </tbody></table></div>
        <footer>显示 {{ filteredRules.length }} / {{ data?.total ?? 0 }} 条规则 · 结构化 JSON v1 <span>仅带完整一致数据的规则允许进入详情</span></footer>
      </template>
    </section>
  </div>
</template>

<style scoped>
.rules-page{padding:20px 22px 28px}.page-button{display:flex;align-items:center;gap:6px;height:34px;padding:0 10px;border:1px solid var(--border-default);border-radius:8px;background:var(--surface-1);color:var(--text-secondary);font-size:12px;cursor:pointer}.page-button:disabled{cursor:wait;opacity:.65}.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.lifecycle{margin-bottom:12px;overflow:hidden}.lifecycle-head{display:flex;justify-content:space-between;align-items:center;min-height:62px;padding:10px 15px;border-bottom:1px solid var(--border-subtle)}.lifecycle-head h2,.lifecycle-head p{margin:0}.lifecycle-head h2{font-size:15px}.lifecycle-head p{margin-top:3px;color:var(--text-tertiary);font-size:12px}.lifecycle-head>span{display:flex;align-items:center;gap:5px;color:var(--status-success);font-size:12px}.lifecycle-branches{display:grid}.branch{display:grid;grid-template-columns:190px minmax(0,1fr);align-items:center;min-height:78px;padding:10px 14px;border-bottom:1px solid var(--border-subtle)}.branch:last-child{border-bottom:0}.branch-label{display:flex;gap:9px;align-items:center}.branch-label>svg{color:var(--status-success)}.branch.failed .branch-label>svg{color:var(--status-error)}.branch.repair .branch-label>svg{color:var(--status-warning)}.branch-label b,.branch-label small{display:block}.branch-label b{font-size:13px}.branch-label small{margin-top:2px;color:var(--text-tertiary);font-size:14px}.stage-track{display:flex;align-items:center;justify-content:flex-start;gap:7px;overflow-x:auto;padding:2px}.stage-track>svg{flex:0 0 auto;color:var(--border-strong)}.stage-node{flex:0 0 96px;padding:7px 9px;border:1px solid var(--border-subtle);border-radius:7px;background:var(--surface-2);color:var(--text-tertiary)}.stage-node.populated{border-color:color-mix(in srgb,var(--accent) 35%,var(--border-default));background:var(--accent-muted)}.stage-node b,.stage-node span{display:block}.stage-node b{color:var(--text-primary);font-size:15px}.stage-node span{font-size:14px}.stage-rejected.populated{border-color:color-mix(in srgb,var(--status-error) 35%,var(--border-default));background:color-mix(in srgb,var(--status-error) 7%,transparent)}.stage-deployed.populated{border-color:color-mix(in srgb,var(--status-success) 35%,var(--border-default));background:color-mix(in srgb,var(--status-success) 7%,transparent)}
.evolution-flow{display:grid;grid-template-columns:1.35fr 1fr;gap:12px;margin-bottom:12px}.agent-run,.validation-run{display:flex;gap:10px;align-items:center;min-height:70px;padding:10px 13px;border:1px solid var(--border-subtle);border-radius:10px;background:var(--surface-1)}.agent-icon{display:grid;width:34px;height:34px;place-items:center;border-radius:8px;background:var(--accent-muted);color:var(--accent-strong)}.agent-run div{flex:1}.agent-run p,.agent-run b,.agent-run small,.validation-run p{display:block;margin:0}.agent-run p,.validation-run p{color:var(--text-tertiary);font-size:14px}.agent-run b{font-size:13px}.agent-run small{margin-top:3px;color:var(--text-tertiary);font-size:14px}.agent-run a,.validation-run a{display:flex;align-items:center;gap:3px;color:var(--accent-strong);font-size:12px;text-decoration:none}.validation-run>svg{color:var(--status-success)}.validation-run div{display:grid;grid-template-columns:auto auto;gap:2px 9px;flex:1}.validation-run p{grid-column:1/-1}.validation-run b{font-size:13px}.validation-run span{align-self:center;color:var(--text-tertiary);font-size:14px}
.rule-toolbar{display:grid;grid-template-columns:minmax(260px,1fr) 170px 190px auto;gap:9px;align-items:end;margin-bottom:12px;padding:10px}.rule-toolbar label>span{display:block;margin:0 0 4px 2px;color:var(--text-tertiary);font-size:14px}.search-field{position:relative}.search-field>svg{position:absolute;bottom:9px;left:10px;color:var(--text-tertiary)}.rule-toolbar input,.rule-toolbar select,.clear-button{width:100%;height:34px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-secondary);font-size:12px}.rule-toolbar input{padding:0 10px 0 32px}.rule-toolbar select{padding:0 8px}.clear-button{padding:0 10px;cursor:pointer}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}
.rule-table{overflow:hidden}.table-scroll{overflow-x:auto}.rule-table table{width:100%;min-width:1050px;border-collapse:collapse}.rule-table th{height:36px;padding:0 11px;background:var(--surface-2);color:var(--text-tertiary);font-size:14px;font-weight:650;text-align:left}.rule-table td{height:54px;padding:7px 11px;border-top:1px solid var(--border-subtle);color:var(--text-secondary);font-size:12px;white-space:nowrap}.rule-table tr.unavailable{background:color-mix(in srgb,var(--surface-2) 45%,transparent)}.rule-table td:first-child{min-width:260px}.rule-table td b,.rule-table td small{display:block}.rule-table td:first-child b{color:var(--text-primary);font-size:13px;font-weight:600}.rule-table td small{margin-top:3px;color:var(--text-tertiary);font-size:14px}.stage-badge{display:inline-flex;align-items:center;gap:5px;font-size:14px}.stage-badge i{width:6px;height:6px;border-radius:50%;background:var(--text-tertiary)}.stage-validating i{background:var(--status-warning)}.stage-validated i,.stage-confirmed i{background:var(--accent)}.stage-deployed i{background:var(--status-success)}.stage-rejected i,.stage-deprecated i{background:var(--status-error)}.stage-candidate i,.stage-repaired i{background:var(--severity-info)}.quality{display:inline-grid;width:30px;height:26px;place-items:center;border-radius:5px;background:color-mix(in srgb,var(--status-success) 8%,transparent);color:var(--status-success);font-size:12px}.good{color:var(--status-success)!important}.warning{color:var(--status-warning)!important}.subtle{color:var(--text-tertiary)!important}.rule-table td a{display:inline-flex;align-items:center;gap:3px;color:var(--accent-strong);font-size:12px;text-decoration:none}.unavailable-label{color:var(--text-disabled);font-size:14px}.rule-table footer{display:flex;justify-content:space-between;min-height:42px;padding:0 12px;align-items:center;border-top:1px solid var(--border-subtle);background:var(--surface-2);color:var(--text-tertiary);font-size:14px}
@media(max-width:1050px){.branch{grid-template-columns:1fr;gap:9px}.evolution-flow{grid-template-columns:1fr}.rule-toolbar{grid-template-columns:1fr 1fr}.search-field{grid-column:1/-1}}@media(max-width:650px){.rules-page{padding:16px 12px 24px}.lifecycle-head>span{display:none}.branch{padding:12px}.stage-node{flex-basis:102px}.rule-toolbar{grid-template-columns:1fr}.search-field{grid-column:auto}.rule-table footer span{display:none}}
</style>
