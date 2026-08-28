<script setup lang="ts">
import { ArrowRight, CheckCircle2, CircleAlert, GitMerge, ScanSearch } from '~/utils/icons'
import type { AutoEncoderOutput, RiskFusion, TransformerOutput } from '~~/shared/types/security'
const props = defineProps<{ transformer: TransformerOutput; autoEncoder: AutoEncoderOutput; fusion: RiskFusion }>()
const pct = (value: number) => `${Math.round(value * 100)}%`
const leanLabels = { known_attack: '偏向已知攻击', unknown_anomaly: '偏向未知异常', dual_confirmed: '双通道一致', normal: '正常流量' }
const knownChannelLabel = computed(() =>
  props.transformer.pretrainingTask === 'Masked Feature Modeling' ? 'Flow Transformer' : 'CPU 分类基线',
)
</script>

<template>
  <section class="dual-channel" aria-label="双通道检测证据">
    <article class="channel transformer">
      <div class="channel-head"><span><ScanSearch :size="16" />已知攻击通道</span><em>{{ knownChannelLabel }}</em></div>
      <div class="channel-result"><div><small>分类结果</small><strong>{{ transformer.prediction }}</strong></div><div><small>置信度</small><strong class="mono">{{ pct(transformer.confidence) }}</strong></div><span :class="['class-state', { known: transformer.isKnownClass }]">{{ transformer.isKnownClass ? '已知类别' : '未达已知类阈值' }}</span></div>
      <div class="prob-list"><div v-for="item in transformer.topK" :key="item.label"><p><span>{{ item.label }}</span><b class="mono">{{ pct(item.probability) }}</b></p><i><span :style="{ width: pct(item.probability) }" /></i></div></div>
      <dl><div><dt>模型</dt><dd class="mono">{{ transformer.modelVersion }}</dd></div><div><dt>推理</dt><dd class="mono">{{ transformer.inferenceMs }} ms</dd></div><div><dt>预训练</dt><dd>{{ transformer.pretrainingTask }}</dd></div></dl>
      <div class="feature-list"><p>关键分类特征</p><span v-for="item in transformer.abnormalFeatures" :key="item.field"><b class="mono">{{ item.field }}</b><em class="mono">{{ item.value }}</em></span></div>
    </article>

    <div class="merge-line" aria-hidden="true"><ArrowRight :size="18" /></div>

    <article class="channel autoencoder">
      <div class="channel-head"><span><CircleAlert :size="16" />未知异常通道</span><em>AutoEncoder</em></div>
      <div class="channel-result"><div><small>重构误差</small><strong class="mono">{{ autoEncoder.reconstructionError.toFixed(2) }}</strong></div><div><small>异常分数</small><strong class="mono">{{ pct(autoEncoder.anomalyScore) }}</strong></div><span :class="['class-state', { known: autoEncoder.exceedsThreshold }]">{{ autoEncoder.exceedsThreshold ? `超过阈值 ${autoEncoder.threshold}` : '正常分布内' }}</span></div>
      <div class="threshold-scale"><span :style="{ left: pct(autoEncoder.threshold) }">阈值 {{ autoEncoder.threshold }}</span><i><b :style="{ width: pct(autoEncoder.anomalyScore) }" /></i></div>
      <dl><div><dt>模型</dt><dd class="mono">{{ autoEncoder.modelVersion }}</dd></div><div><dt>推理</dt><dd class="mono">{{ autoEncoder.inferenceMs }} ms</dd></div><div><dt>训练流量</dt><dd>仅正常样本</dd></div></dl>
      <div class="feature-list"><p>最大重构偏差</p><span v-for="item in autoEncoder.deviatingFeatures" :key="item.field"><b class="mono">{{ item.field }}</b><em class="mono">× {{ item.deviation.toFixed(1) }}</em></span></div>
    </article>

    <div class="merge-line" aria-hidden="true"><ArrowRight :size="18" /></div>

    <article class="fusion">
      <div class="fusion-head"><GitMerge :size="17" /><span>风险融合</span></div>
      <div class="risk-score mono">{{ fusion.finalScore }}<small>/100</small></div>
      <b>{{ leanLabels[fusion.lean] }}</b>
      <span class="agreement"><CheckCircle2 :size="13" />{{ fusion.agreement === 'consistent' ? '两通道结果一致' : fusion.agreement === 'partial' ? '证据部分一致' : '通道结果冲突' }}</span>
      <dl><div><dt>分类权重</dt><dd class="mono">{{ pct(fusion.transformerWeight) }}</dd></div><div><dt>异常权重</dt><dd class="mono">{{ pct(fusion.autoEncoderWeight) }}</dd></div><div><dt>上下文修正</dt><dd class="mono">+{{ fusion.contextAdjustment }}</dd></div></dl>
      <p>{{ fusion.explanation }}</p>
    </article>
  </section>
</template>

<style scoped>
.dual-channel { display: grid; grid-template-columns: minmax(0,1fr) 24px minmax(0,1fr) 24px 220px; align-items: stretch; }
.channel { min-width: 0; padding: 13px 14px; background: var(--surface-1); border: 1px solid var(--border-subtle); border-radius: 10px; }.channel-head { display: flex; justify-content: space-between; align-items: center; padding-bottom: 10px; border-bottom: 1px solid var(--border-subtle); }.channel-head span { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 650; }.channel-head em { color: var(--text-tertiary); font-size:13px; font-style: normal; }.transformer .channel-head svg { color: var(--severity-info); }.autoencoder .channel-head svg { color: var(--accent-strong); }
.channel-result { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 12px 0 8px; }.channel-result small, .channel-result strong { display: block; }.channel-result small { color: var(--text-tertiary); font-size:13px; }.channel-result strong { margin-top: 1px; font-size: 17px; }.class-state { grid-column: 1/-1; width: max-content; padding: 2px 6px; border-radius: 4px; background: color-mix(in srgb, var(--status-warning) 9%, transparent); color: var(--status-warning); font-size:13px; }.class-state.known { background: color-mix(in srgb, var(--status-success) 9%, transparent); color: var(--status-success); }
.prob-list { display: grid; gap: 6px; padding: 7px 0 10px; }.prob-list p { display: flex; justify-content: space-between; margin: 0; color: var(--text-secondary); font-size:13px; }.prob-list p b { font-weight: 500; }.prob-list i { display: block; height: 3px; background: var(--surface-3); }.prob-list i span { display: block; height: 100%; background: var(--severity-info); }.threshold-scale { position: relative; padding: 14px 0 11px; }.threshold-scale > span { position: absolute; top: 0; transform: translateX(-50%); color: var(--text-tertiary); font-size:12px; white-space: nowrap; }.threshold-scale i { display: block; height: 5px; background: var(--surface-3); }.threshold-scale i b { display: block; height: 100%; background: var(--accent); }
.channel dl, .fusion dl { display: grid; gap: 4px; margin: 0; padding: 8px 0; border-block: 1px solid var(--border-subtle); }.channel dl div, .fusion dl div { display: flex; justify-content: space-between; gap: 8px; }.channel dt, .fusion dt { color: var(--text-tertiary); font-size:13px; }.channel dd, .fusion dd { margin: 0; overflow: hidden; color: var(--text-secondary); font-size:13px; text-overflow: ellipsis; white-space: nowrap; }.feature-list { padding-top: 8px; }.feature-list p { margin: 0 0 4px; color: var(--text-tertiary); font-size:12px; text-transform: uppercase; }.feature-list span { display: flex; justify-content: space-between; gap: 8px; padding: 2px 0; }.feature-list b, .feature-list em { font-size:12px; font-style: normal; font-weight: 500; }.feature-list b { overflow: hidden; color: var(--text-secondary); text-overflow: ellipsis; }.feature-list em { color: var(--text-tertiary); white-space: nowrap; }
.merge-line { display: grid; place-items: center; color: var(--border-strong); }.fusion { padding: 13px; background: var(--surface-2); border: 1px solid var(--border-default); border-radius: 10px; }.fusion-head { display: flex; align-items: center; gap: 6px; color: var(--text-secondary); font-size:14px; }.fusion-head svg { color: var(--accent-strong); }.risk-score { margin-top: 14px; color: var(--severity-high); font-size: 31px; font-weight: 700; line-height: 1; }.risk-score small { color: var(--text-tertiary); font-size:13px; }.fusion > b { display: block; margin-top: 5px; font-size:14px; }.agreement { display: flex; align-items: center; gap: 4px; margin: 6px 0 10px; color: var(--status-success); font-size:13px; }.fusion p { margin: 9px 0 0; color: var(--text-tertiary); font-size:13px; line-height: 1.55; }
@media (max-width: 1100px) { .dual-channel { grid-template-columns: 1fr 1fr; gap: 12px; }.merge-line { display: none; }.fusion { grid-column: 1/-1; } }
@media (max-width: 700px) { .dual-channel { grid-template-columns: 1fr; }.fusion { grid-column: auto; } }
</style>
