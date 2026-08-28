<script setup lang="ts">
import * as echarts from 'echarts/core'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { BarChart, LineChart } from 'echarts/charts'
import { CanvasRenderer } from 'echarts/renderers'
import type { ECharts } from 'echarts/core'

echarts.use([GridComponent, TooltipComponent, BarChart, LineChart, CanvasRenderer])

const ui = useUiStore()
const chartEl = ref<HTMLDivElement>()
let chart: ECharts | undefined
const seriesByRange = {
  '最近 1 小时': { labels: ['14:00','14:10','14:20','14:30','14:40','14:50'], all: [4,6,5,9,7,10], high: [1,1,2,3,2,4] },
  '最近 24 小时': { labels: ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00'], all: [14, 9, 7, 11, 26, 32, 28, 41], high: [3, 2, 1, 2, 5, 7, 6, 10] },
  '最近 7 天': { labels: ['周四','周五','周六','周日','周一','周二','周三'], all: [184,211,126,98,242,278,306], high: [31,42,18,14,46,54,61] },
} as const
const currentSeries = computed(()=>seriesByRange[ui.timeRange as keyof typeof seriesByRange] || seriesByRange['最近 24 小时'])

function colors() {
  const style = getComputedStyle(document.documentElement)
  return {
    text: style.getPropertyValue('--text-tertiary').trim(),
    grid: style.getPropertyValue('--chart-grid').trim(),
    accent: style.getPropertyValue('--accent').trim(),
    high: style.getPropertyValue('--severity-high').trim(),
    critical: style.getPropertyValue('--severity-critical').trim(),
    surface: style.getPropertyValue('--surface-1').trim(),
  }
}

function render() {
  if (!chartEl.value) return
  const c = colors()
  if (!chart) chart = echarts.init(chartEl.value, undefined, { renderer: 'canvas' })
  chart.setOption({
    animationDuration: 220,
    backgroundColor: 'transparent',
    grid: { left: 42, right: 16, top: 24, bottom: 30 },
    tooltip: {
      trigger: 'axis',
      backgroundColor: c.surface,
      borderColor: c.grid,
      textStyle: { color: c.text, fontSize: 11 },
      extraCssText: 'box-shadow: none;',
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: currentSeries.value.labels,
      axisLine: { lineStyle: { color: c.grid } },
      axisTick: { show: false },
      axisLabel: { color: c.text, fontSize: 10 },
    },
    yAxis: {
      type: 'value',
      splitNumber: 3,
      axisLabel: { color: c.text, fontSize: 10 },
      splitLine: { lineStyle: { color: c.grid } },
    },
    series: [
      {
        name: '全部告警', type: 'line', smooth: 0.25, showSymbol: false, data: currentSeries.value.all,
        lineStyle: { width: 2, color: c.accent }, areaStyle: { color: c.accent, opacity: 0.06 },
      },
      {
        name: '高危及以上', type: 'line', smooth: 0.25, showSymbol: false, data: currentSeries.value.high,
        lineStyle: { width: 1.5, color: c.high },
      },
    ],
  }, true)
}

const { stop } = useResizeObserver(chartEl, () => chart?.resize())
watch([() => ui.resolvedTheme, () => ui.timeRange], () => nextTick(render))
onMounted(render)
onBeforeUnmount(() => { stop(); chart?.dispose() })
</script>

<template><div class="chart-wrap"><div ref="chartEl" class="threat-chart" role="img" :aria-label="`${ui.timeRange}告警趋势折线图；总告警与高危告警按时间聚合`"/><table class="chart-data"><caption>{{ui.timeRange}}告警趋势数据</caption><thead><tr><th>时间</th><th>全部告警</th><th>高危及以上</th></tr></thead><tbody><tr v-for="(label,index) in currentSeries.labels" :key="label"><td>{{label}}</td><td>{{currentSeries.all[index]}}</td><td>{{currentSeries.high[index]}}</td></tr></tbody></table></div></template>

<style scoped>.threat-chart { width: 100%; height: 206px; }.chart-data{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}</style>
