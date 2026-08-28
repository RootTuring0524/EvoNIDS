<script setup lang="ts">
import { BookOpenCheck, Database, RefreshCw, Search, ShieldCheck } from '~/utils/icons'
import { ragResponseSchema } from '~~/shared/schemas/security'

const topK=ref(10)
const trustOnly=ref(false)
const sourceFilter=ref('all')
const searchInput=ref('Port Scan TCP destination port 445 T1046')
const submittedQuery=ref(searchInput.value)
const {data,status,error,refresh}=await useAsyncData(
  'rag-evidence',
  ()=>validatedFetch('/rag',ragResponseSchema,{query:{query:submittedQuery.value,topK:topK.value}}),
  {watch:[submittedQuery,topK]},
)
const queryText=computed(()=>data.value?.query||submittedQuery.value)
const isMock=computed(()=>data.value?.mode==='fixed_mock_sample')
const sourceTypes=computed(()=>Array.from(new Set(data.value?.items.map((item)=>item.sourceType)||[])))
const visibleItems=computed(()=>data.value?.items.filter((item)=>(!trustOnly.value||item.trust!=='low')&&(sourceFilter.value==='all'||item.sourceType===sourceFilter.value))||[])
const displayItems=computed(()=>{
  const ranked=visibleItems.value.filter((item)=>item.allowed).slice(0,topK.value)
  const filtered=visibleItems.value.filter((item)=>!item.allowed)
  return [...ranked,...filtered]
})
const usedCount=computed(()=>data.value?.retrieval.providedToAgent||0)
const mockSources=[{name:'MITRE ATT&CK',count:'726',fresh:'7 天前'},{name:'历史告警',count:'42,891',fresh:'实时'},{name:'已有检测规则',count:'326',fresh:'实时'},{name:'Snort / Suricata 样例',count:'18,420',fresh:'1 天前'},{name:'处置手册',count:'84',fresh:'3 天前'},{name:'协议与端口知识',count:'1,284',fresh:'1 天前'},{name:'CVE / CWE / CAPEC',count:'12,604',fresh:'1 天前'},{name:'已验证规则',count:'284',fresh:'实时'},{name:'失败规则与误报案例',count:'91',fresh:'实时'}]
const sources=computed(()=>{
  if(isMock.value)return mockSources
  const counts=new Map<string,{count:number;fresh:string}>()
  for(const item of data.value?.items||[]){
    const current=counts.get(item.sourceType)
    counts.set(item.sourceType,{count:(current?.count||0)+1,fresh:item.updatedAt})
  }
  return [...counts.entries()].map(([name,value])=>({name,count:String(value.count),fresh:value.fresh}))
})
function runSearch(){submittedQuery.value=searchInput.value.trim();if(submittedQuery.value===data.value?.query)refresh()}
</script>
<template>
  <div class="knowledge-page">
    <PageHeader eyebrow="Retrieval Evidence" title="RAG 知识检索" :description="isMock?'追踪固定 Mock 样例中进入 DeepSeek V4 Pro 上下文的证据与安全决策':'检索持久化安全证据，并追踪排序、可信度和 Prompt Injection 过滤结果'">
      <button class="page-button" :disabled="status==='pending'" @click="runSearch"><RefreshCw :size="13"/>{{status==='pending'?'检索中…':'执行检索'}}</button>
    </PageHeader>
    <section class="search-workbench surface-panel"><label><Search :size="16"/><input v-model="searchInput" aria-label="安全知识检索查询" @keyup.enter="runSearch"><kbd>{{isMock?'固定 Mock':'关键词检索'}}</kbd></label><div><label><span>Top-K 展示</span><select v-model="topK"><option :value="5">5</option><option :value="10">10</option></select></label><label><span>来源</span><select v-model="sourceFilter"><option value="all">全部来源</option><option v-for="item in sourceTypes" :key="item" :value="item">{{item}}</option></select></label><button :class="{active:trustOnly}" :aria-pressed="trustOnly" @click="trustOnly=!trustOnly"><ShieldCheck :size="13"/>仅高/中可信</button></div><p v-if="isMock">当前为固定演示查询；筛选只改变本页展示。</p><p v-else>当前使用数据库关键词回退检索；向量模型尚未配置，因此 vectorScore 明确为 0，不伪造语义召回结果。</p></section>
    <section v-if="data?.retrieval" class="retrieval-strip"><div><span>向量候选</span><b class="mono">{{data.retrieval.vectorCandidates}}</b><small>vectorScore ≥ 0.70</small></div><i>→</i><div><span>关键词补召回</span><b class="mono">+{{data.retrieval.keywordSupplementCandidates}}</b><small>未进入向量阈值</small></div><i>→</i><div><span>可信度与安全过滤</span><b class="mono">-{{data.retrieval.filteredCandidates}}</b><small>隔离不允许使用的来源</small></div><i>→</i><div><span>综合重排</span><b class="mono">{{data.retrieval.rerankedCandidates}} / Top {{topK}}</b><small>实际提供 {{usedCount}} 条给 Agent</small></div></section>
    <LoadingState v-if="status==='pending'" :rows="7"/><ErrorState v-else-if="error" @retry="refresh"/><RagEvidenceList v-else :items="displayItems" :query="queryText" :top-k="topK"/>
    <section class="source-registry surface-panel"><div class="registry-head"><div><h2>{{isMock?'固定 Mock 知识来源登记':'当前检索命中的知识来源'}}</h2><p>{{isMock?'样例索引规模，不表示实时生产库存':'仅统计本次查询返回的允许与隔离证据'}}</p></div><span><Database :size="13"/>{{isMock?'Mock 索引':'持久化证据库'}} <code>{{data?.mode}}</code></span></div><div class="source-grid"><div v-for="source in sources" :key="source.name"><BookOpenCheck :size="14"/><span><b>{{source.name}}</b><small>更新时间 {{source.fresh}}</small></span><em class="mono">{{source.count}}</em></div></div></section>
  </div>
</template>
<style scoped>
.knowledge-page{padding:20px 22px 28px}.page-button{display:flex;align-items:center;gap:5px;height:34px;padding:0 9px;border:1px solid var(--border-default);border-radius:8px;background:var(--surface-1);color:var(--text-secondary);font-size:13px;cursor:pointer}.search-workbench{display:grid;grid-template-columns:minmax(300px,1fr) auto;gap:8px;margin-bottom:12px;padding:10px}.search-workbench>label{position:relative}.search-workbench>label>svg{position:absolute;top:9px;left:10px;color:var(--text-tertiary)}.search-workbench input{width:100%;height:34px;padding:0 48px 0 32px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-primary);font:13px ui-monospace,monospace}.search-workbench kbd{position:absolute;top:9px;right:8px;padding:2px 4px;border:1px solid var(--border-default);border-radius:3px;color:var(--text-tertiary);font-size:12px}.search-workbench>div{display:flex;gap:6px}.search-workbench>div label{display:flex;align-items:center;gap:5px;padding:0 7px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px}.search-workbench select{border:0;background:transparent;color:var(--text-secondary);font-size:12px}.search-workbench button{display:flex;align-items:center;gap:4px;padding:0 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-tertiary);font-size:12px;cursor:pointer}.search-workbench button.active{border-color:color-mix(in srgb,var(--status-success) 35%,var(--border-default));color:var(--status-success)}.search-workbench>p{grid-column:1/-1;margin:0;color:var(--text-tertiary);font-size:12px}.search-workbench>p a{color:var(--accent-strong);text-decoration:none}.retrieval-strip{display:grid;grid-template-columns:1fr 30px 1fr 30px 1fr 30px 1fr;align-items:center;margin-bottom:12px;border-block:1px solid var(--border-default);background:var(--surface-1)}.retrieval-strip>div{padding:8px 12px}.retrieval-strip span,.retrieval-strip b,.retrieval-strip small{display:block}.retrieval-strip span{color:var(--text-tertiary);font-size:12px}.retrieval-strip b{font-size:14px}.retrieval-strip small{color:var(--text-tertiary);font-size:12px}.retrieval-strip>i{color:var(--border-strong);font-style:normal;text-align:center}.source-registry{margin-top:12px;overflow:hidden}.registry-head{display:flex;justify-content:space-between;align-items:center;min-height:48px;padding:8px 12px;border-bottom:1px solid var(--border-subtle)}.registry-head h2,.registry-head p{margin:0}.registry-head h2{font-size:14px}.registry-head p{margin-top:2px;color:var(--text-tertiary);font-size:12px}.registry-head>span{display:flex;align-items:center;gap:4px;color:var(--text-tertiary);font-size:12px}.registry-head code{font-size:12px}.source-grid{display:grid;grid-template-columns:repeat(3,1fr)}.source-grid>div{display:grid;grid-template-columns:24px 1fr auto;gap:6px;align-items:center;min-height:51px;padding:7px 10px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.source-grid>div:nth-child(3n){border-right:0}.source-grid svg{color:var(--accent-strong)}.source-grid b,.source-grid small{display:block}.source-grid b{font-size:13px}.source-grid small{color:var(--text-tertiary);font-size:12px}.source-grid em{color:var(--text-secondary);font-size:13px;font-style:normal}
@media(max-width:850px){.search-workbench{grid-template-columns:1fr}.search-workbench>div{flex-wrap:wrap}.retrieval-strip{grid-template-columns:1fr 1fr}.retrieval-strip>i{display:none}.source-grid{grid-template-columns:1fr 1fr}}@media(max-width:600px){.knowledge-page{padding:16px 12px 24px}.source-grid{grid-template-columns:1fr}.source-grid>div{border-right:0}}
</style>
