<script setup lang="ts">
withDefaults(defineProps<{
  source:string
  destination:string
  ports:number
  targets:number
  metricLabel?:string
  metricValue:string
  multiTarget?:boolean
}>(), { metricLabel: 'SYN 比例', multiTarget: false })
</script>

<template>
  <div class="attack-graph"><ClientOnly><ChartsTrafficGraph :source="source" :destination="destination" :multi-target="multiTarget"/><template #fallback><LoadingState :rows="3" label="正在加载通信关系"/></template></ClientOnly><dl><div><dt>目的端口</dt><dd class="mono">{{ports}}</dd></div><div><dt>目的 IP</dt><dd class="mono">{{targets}}</dd></div><div><dt>{{metricLabel}}</dt><dd class="mono">{{metricValue}}</dd></div></dl></div>
</template>

<style scoped>
.attack-graph dl{display:grid;grid-template-columns:repeat(3,1fr);margin:0;border-top:1px solid var(--border-subtle)}.attack-graph dl div{padding:8px 9px;border-right:1px solid var(--border-subtle)}.attack-graph dl div:last-child{border-right:0}.attack-graph dt{color:var(--text-tertiary);font-size:12px}.attack-graph dd{margin:2px 0 0;color:var(--text-secondary);font-size:14px;font-weight:650}
</style>
