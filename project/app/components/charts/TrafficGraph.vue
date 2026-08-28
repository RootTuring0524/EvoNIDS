<script setup lang="ts">
import * as echarts from 'echarts/core'
import { TooltipComponent } from 'echarts/components'
import { GraphChart } from 'echarts/charts'
import { CanvasRenderer } from 'echarts/renderers'
import VChart from 'vue-echarts'

echarts.use([TooltipComponent, GraphChart, CanvasRenderer])
const props=defineProps<{source:string;destination:string;multiTarget?:boolean}>()
const ui=useUiStore()
const option=shallowRef<Record<string,unknown>>({})
const nodes=computed(()=>[{id:'src',name:props.source,symbolSize:28,category:0},{id:'dst1',name:props.destination,symbolSize:22,category:1},...(props.multiTarget?[{id:'dst2',name:'10.0.0.14:22',symbolSize:14,category:1},{id:'dst3',name:'10.0.0.21:3389',symbolSize:14,category:1},{id:'dst4',name:'10.0.0.32:80',symbolSize:14,category:1},{id:'dst5',name:'+ 14 targets',symbolSize:18,category:2}]:[])])
const graphLabel=computed(()=>props.multiTarget?`源地址 ${props.source} 在 60 秒内连接多个目标；主要目标为 ${props.destination}`:`源地址 ${props.source} 与目标 ${props.destination} 的当前 Flow 通信关系`)
function render(){const s=getComputedStyle(document.documentElement);const text=s.getPropertyValue('--text-tertiary').trim(),accent=s.getPropertyValue('--severity-high').trim(),info=s.getPropertyValue('--severity-info').trim(),border=s.getPropertyValue('--border-strong').trim();option.value={animationDuration:220,tooltip:{formatter:'{b}',backgroundColor:s.getPropertyValue('--surface-1').trim(),borderColor:border,textStyle:{color:text,fontSize:12}},series:[{type:'graph',layout:'force',roam:false,label:{show:true,position:'bottom',color:text,fontSize:12},force:{repulsion:150,edgeLength:[55,90],gravity:.1},data:nodes.value.map((n)=>({...n,itemStyle:{color:n.category===0?accent:n.category===1?info:border}})),links:nodes.value.slice(1).map((n,i)=>({source:'src',target:n.id,lineStyle:{color:i===0?accent:border,width:i===0?2:1,opacity:.65}})),lineStyle:{curveness:.08}}]}}
watch([()=>ui.resolvedTheme,()=>props.source,()=>props.destination,()=>props.multiTarget],()=>nextTick(render));onMounted(render)
</script>
<template><div class="graph-wrap"><VChart class="traffic-graph" :option="option" autoresize role="img" :aria-label="graphLabel"/><ul class="graph-data"><li v-for="node in nodes.slice(1)" :key="node.id">{{source}} → {{node.name}}</li></ul></div></template>
<style scoped>.traffic-graph{width:100%;height:196px}.graph-data{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}</style>
