<script setup lang="ts">
import {
  Activity,
  BrainCircuit,
  CheckCircle2,
  Database,
  FileCheck2,
  FolderPlus,
  HardDrive,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  TriangleAlert,
  Workflow,
  X,
} from '~/utils/icons'
import {
  datasetRecordSchema,
  datasetsResponseSchema,
  integrationSettingsSchema,
  modelsResponseSchema,
  trainingRunRecordSchema,
  trainingRunsResponseSchema,
} from '~~/shared/schemas/security'
import type {
  AutoEncoderTrainingMetrics,
  DatasetRecord,
  ModelRecord,
  TrainingMetrics,
  TrainingRunRecord,
  TrainingRunState,
} from '~~/shared/types/security'

const runtime = useRuntimeConfig()
const isMock = computed(() => Boolean(runtime.public.useMockApi))
const { data: models, status: modelStatus, error: modelError, refresh: refreshModels } = await useAsyncData(
  'models',
  () => validatedFetch('/models', modelsResponseSchema),
)
const { data: datasets, status: datasetStatus, error: datasetError, refresh: refreshDatasets } = await useAsyncData(
  'datasets',
  () => validatedFetch('/datasets', datasetsResponseSchema),
)
const { data: integration, refresh: refreshIntegration } = await useAsyncData(
  'model-integration-status',
  () => validatedFetch('/settings/integrations', integrationSettingsSchema),
)
const {
  data: trainingRuns,
  status: trainingStatus,
  error: trainingError,
  refresh: refreshTraining,
} = await useAsyncData('training-runs', () => validatedFetch('/training/runs', trainingRunsResponseSchema))

const selectedDataset = ref('')
const selectedTrainingRun = ref('')
const showRegistration = ref(false)
const registering = ref(false)
const trainingStarting = ref(false)
const trainingAcknowledged = ref(false)
const actionMessage = ref('')
const actionTone = ref<'success' | 'error' | 'info'>('info')
const registration = reactive({
  id: 'DS-CIC-2017',
  name: 'CICIDS2017',
  version: 'original-csv',
  relativePath: '',
  sourceUri: 'https://www.unb.ca/cic/datasets/ids-2017.html',
  labelColumn: 'Label',
  normalLabels: 'BENIGN',
  mainTrainingSet: true,
  unknownHoldout: true,
  ruleReplay: true,
})
const trainingForm = reactive({
  maxRows: 250_000,
  maxIter: 200,
  randomSeed: 42,
})

const activeDataset = computed(() => datasets.value?.items.find((item) => item.id === selectedDataset.value))
const readyDatasetItems = computed(() => datasets.value?.items.filter((item) => item.state === 'ready') || [])
const activeTrainingRun = computed(() => trainingRuns.value?.items.find((item) => item.id === selectedTrainingRun.value))
const hasActiveTraining = computed(() => trainingRuns.value?.items.some((item) => item.state === 'queued' || item.state === 'running'))
const transformer = computed(() => findModel('Flow Transformer'))
const knownBaseline = computed(() => findLatestModel('Known Attack CPU Baseline'))
const autoEncoder = computed(() => findLatestModel('AutoEncoder'))
const readyDatasets = computed(() => datasets.value?.items.filter((item) => item.state === 'ready').length || 0)
const profilingDatasets = computed(() => datasets.value?.items.filter((item) => item.state === 'profiling').length || 0)

watchEffect(() => {
  const items = datasets.value?.items || []
  if (!items.length) {
    selectedDataset.value = ''
    return
  }
  if (!items.some((item) => item.id === selectedDataset.value)) {
    selectedDataset.value = items.find((item) => item.mainTrainingSet)?.id || items[0]!.id
  }
})

watchEffect(() => {
  const items = trainingRuns.value?.items || []
  if (!items.length) {
    selectedTrainingRun.value = ''
    return
  }
  if (!items.some((item) => item.id === selectedTrainingRun.value)) selectedTrainingRun.value = items[0]!.id
})

function findModel(namePart: string): ModelRecord | undefined {
  return models.value?.items.find((item) => item.name.includes(namePart))
}

function findLatestModel(namePart: string): ModelRecord | undefined {
  return models.value?.items
    .filter((item) => item.name.includes(namePart))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
    .find((item) => item.state === 'healthy' && item.artifactState === 'available')
}

function modelLabel(model: ModelRecord | undefined) {
  if (!model) return '未登记'
  if (model.state === 'healthy') return '可用'
  if (model.state === 'training') return '尚无可用制品'
  return '降级'
}

function artifactLabel(model: ModelRecord | undefined) {
  if (!model) return '制品未登记'
  return ({ available: '本地制品已验证', missing: '制品缺失', unverified: '远程制品未验证', snapshot: '演示快照制品' })[model.artifactState]
}

function formatMetric(model: ModelRecord | undefined) {
  if (!model || model.qualityValue <= 0) return '未评估'
  return `${model.qualityLabel} ${model.qualityValue.toFixed(1)}%`
}

function formatCount(value: number) {
  return new Intl.NumberFormat('zh-CN', { notation: 'compact', maximumFractionDigits: 1 }).format(value)
}

function formatBytes(value: number) {
  if (!value) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index > 2 ? 2 : 1)} ${units[index]}`
}

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString('zh-CN') : '尚未完成'
}

function formatPercent(value: number) {
  return `${(value * 100).toFixed(1)}%`
}

function trainingStateLabel(state: TrainingRunState) {
  return ({ queued: '排队', running: '训练中', succeeded: '已完成', failed: '失败' })[state]
}

function isAutoEncoderMetrics(
  metrics: TrainingMetrics | AutoEncoderTrainingMetrics,
): metrics is AutoEncoderTrainingMetrics {
  return 'threshold' in metrics
}

function runMetricSummary(run: TrainingRunRecord) {
  if (!run.metrics) return run.state === 'failed' ? '未生成指标' : '指标计算中'
  if (isAutoEncoderMetrics(run.metrics)) {
    return `攻击召回 ${formatPercent(run.metrics.recall)} · 正常 FPR ${formatPercent(run.metrics.normalFalsePositiveRate)}`
  }
  return `测试 Macro F1 ${formatPercent(run.metrics.macroF1)}`
}

function runTaskLabel(run: TrainingRunRecord) {
  return run.task === 'unknown_anomaly_detection' ? 'UNKNOWN ANOMALY / PYTORCH CPU' : 'KNOWN ATTACK / CPU BASELINE'
}

function runDuration(run: TrainingRunRecord) {
  if (!run.startedAt) return '尚未开始'
  const end = run.completedAt ? new Date(run.completedAt).getTime() : Date.now()
  const seconds = Math.max(0, (end - new Date(run.startedAt).getTime()) / 1000)
  if (seconds < 60) return `${seconds.toFixed(1)} 秒`
  return `${(seconds / 60).toFixed(1)} 分钟`
}

function datasetStateLabel(state: DatasetRecord['state']) {
  return ({ profiling: '检查中', ready: '可用于实验', error: '检查失败', missing: '文件缺失', snapshot: '演示快照' })[state]
}

function datasetStateTone(state: DatasetRecord['state']) {
  if (state === 'ready') return 'ready'
  if (state === 'profiling') return 'profiling'
  if (state === 'snapshot') return 'snapshot'
  return 'error'
}

function notify(message: string, tone: 'success' | 'error' | 'info' = 'info') {
  actionMessage.value = message
  actionTone.value = tone
}

function safeError(error: unknown) {
  if (error && typeof error === 'object' && 'statusMessage' in error && typeof error.statusMessage === 'string') {
    return error.statusMessage
  }
  return '请求失败，请检查后台服务、管理员令牌和数据集目录。'
}

async function refreshAll() {
  await Promise.all([refreshModels(), refreshDatasets(), refreshIntegration(), refreshTraining()])
  notify('模型、数据集和 Agent 配置状态已刷新', 'success')
}

async function startTraining() {
  if (trainingStarting.value || !activeDataset.value || activeDataset.value.state !== 'ready') return
  trainingStarting.value = true
  try {
    const result = await validatedFetch('/training/runs', trainingRunRecordSchema, {
      method: 'POST',
      body: {
        datasetId: activeDataset.value.id,
        algorithm: 'hist_gradient_boosting',
        maxRows: trainingForm.maxRows,
        maxIter: trainingForm.maxIter,
        randomSeed: trainingForm.randomSeed,
        learningRate: 0.08,
        maxLeafNodes: 31,
        l2Regularization: 0.1,
        actor: 'local-ml-operator',
      },
    })
    selectedTrainingRun.value = result.id
    trainingAcknowledged.value = false
    notify('真实 CPU 基线训练已排队；后台会重新校验数据 SHA-256。', 'success')
    await refreshTraining()
    void pollTraining(result.id)
  } catch (error) {
    notify(safeError(error), 'error')
  } finally {
    trainingStarting.value = false
  }
}

async function registerDataset() {
  if (registering.value) return
  registering.value = true
  try {
    const result = await validatedFetch('/datasets', datasetRecordSchema, {
      method: 'POST',
      body: {
        id: registration.id,
        name: registration.name,
        version: registration.version,
        relativePath: registration.relativePath,
        sourceUri: registration.sourceUri,
        labelColumn: registration.labelColumn || null,
        normalLabels: registration.normalLabels.split(',').map((item) => item.trim()).filter(Boolean),
        split: { train: 70, validation: 15, test: 15 },
        mainTrainingSet: registration.mainTrainingSet,
        unknownHoldout: registration.unknownHoldout,
        ruleReplay: registration.ruleReplay,
        uses: ['模型训练', '独立测试与可复现评估'],
        actor: 'local-admin',
        note: 'Registered from the EvoNIDS model operations console.',
      },
    })
    selectedDataset.value = result.id
    showRegistration.value = false
    notify('真实文件已登记，后台正在计算校验和与数据画像。', 'success')
    await refreshDatasets()
    void pollDataset(result.id)
  } catch (error) {
    notify(safeError(error), 'error')
  } finally {
    registering.value = false
  }
}

async function reprofile(dataset: DatasetRecord) {
  try {
    await validatedFetch(`/datasets/${encodeURIComponent(dataset.id)}/reprofile`, datasetRecordSchema, { method: 'POST' })
    notify(`已重新提交 ${dataset.name} 的真实文件检查`, 'success')
    await refreshDatasets()
    void pollDataset(dataset.id)
  } catch (error) {
    notify(safeError(error), 'error')
  }
}

async function pollDataset(id: string) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2000))
    await refreshDatasets()
    const current = datasets.value?.items.find((item) => item.id === id)
    if (!current || current.state !== 'profiling') {
      if (current?.state === 'ready') notify(`${current.name} 已完成真实数据检查`, 'success')
      if (current?.state === 'error' || current?.state === 'missing') notify(current.inspectionError || '数据检查失败', 'error')
      return
    }
  }
  notify('数据量较大，后台仍在检查；可以离开页面，稍后刷新查看。', 'info')
}

async function pollTraining(id: string) {
  for (let attempt = 0; attempt < 900; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2000))
    await refreshTraining()
    const current = trainingRuns.value?.items.find((item) => item.id === id)
    if (!current || current.state === 'succeeded' || current.state === 'failed') {
      if (current?.state === 'succeeded') {
        notify('真实基线训练完成，测试集指标与本地制品已经登记。', 'success')
        await refreshModels()
      }
      if (current?.state === 'failed') notify(current.errorMessage || '训练失败', 'error')
      return
    }
  }
  notify('训练仍在后台运行，可以离开页面后稍后查看。', 'info')
}
</script>

<template>
  <div class="models-page">
    <PageHeader eyebrow="Detection Intelligence" title="模型与数据资产" description="模型制品、训练数据来源与可复现评估的真实运行台账">
      <button v-if="!isMock" class="page-button" @click="showRegistration = !showRegistration">
        <X v-if="showRegistration" :size="14"/><FolderPlus v-else :size="14"/>{{ showRegistration ? '关闭登记' : '登记数据集' }}
      </button>
      <button class="page-button primary" :disabled="modelStatus === 'pending' || datasetStatus === 'pending'" @click="refreshAll">
        <RefreshCw :size="14" :class="{ spin: modelStatus === 'pending' || datasetStatus === 'pending' }"/>刷新真实状态
      </button>
    </PageHeader>

    <div :class="['mode-banner', isMock ? 'mock' : 'real']">
      <TriangleAlert v-if="isMock" :size="15"/><ShieldCheck v-else :size="15"/>
      <div>
        <b>{{ isMock ? '显式演示模式' : '真实资产模式' }}</b>
        <span v-if="isMock">本页数据和成绩是固定快照，只用于交互演示，不得作为论文、比赛或部署结果。</span>
        <span v-else>只显示数据库中登记的模型和实际文件检查结果；未训练、未评估或文件缺失会原样呈现。</span>
      </div>
      <code>{{ isMock ? 'NUXT_PUBLIC_USE_MOCK_API=true' : 'FastAPI / persistent registry' }}</code>
    </div>

    <div v-if="actionMessage" :class="['action-message', actionTone]" role="status">{{ actionMessage }}</div>

    <section v-if="showRegistration && !isMock" class="registration-panel surface-panel">
      <header><div><h2>登记服务器本地数据集</h2><p>只允许 <code>EVONIDS_DATASET_ROOT</code> 内的 CSV/CSV.GZ；不会上传或修改源文件。</p></div><HardDrive :size="18"/></header>
      <form @submit.prevent="registerDataset">
        <label><span>资产 ID</span><input v-model.trim="registration.id" required pattern="[A-Za-z0-9][A-Za-z0-9._-]{2,95}" placeholder="DS-CIC-2017"><small>稳定标识，登记后不可重复</small></label>
        <label><span>数据集名称</span><input v-model.trim="registration.name" required placeholder="CICIDS2017"><small>使用发布方正式名称</small></label>
        <label><span>版本</span><input v-model.trim="registration.version" required placeholder="original-csv"><small>原始版本、日期或发布版本</small></label>
        <label class="wide"><span>相对文件路径</span><input v-model.trim="registration.relativePath" required placeholder="CICIDS2017/Friday-WorkingHours.csv"><small>相对于受控数据目录；禁止绝对路径和目录穿越</small></label>
        <label class="wide"><span>来源链接</span><input v-model.trim="registration.sourceUri" type="url" placeholder="https://官方发布页"><small>用于数据卡和来源追踪，不参与下载</small></label>
        <label><span>标签列</span><input v-model.trim="registration.labelColumn" placeholder="Label"><small>留空时自动查找 Label / attack_cat / class</small></label>
        <label><span>正常标签</span><input v-model.trim="registration.normalLabels" placeholder="BENIGN,NORMAL,0"><small>多个值用英文逗号分隔</small></label>
        <fieldset class="wide"><legend>使用边界</legend><label><input v-model="registration.mainTrainingSet" type="checkbox">主训练集</label><label><input v-model="registration.unknownHoldout" type="checkbox">未知类别留出</label><label><input v-model="registration.ruleReplay" type="checkbox">允许规则回放</label></fieldset>
        <footer class="wide"><span><ShieldCheck :size="13"/>后台将真实计算 SHA-256、行数、缺失值和标签分布</span><button type="submit" :disabled="registering"><RefreshCw v-if="registering" :size="13" class="spin"/><FileCheck2 v-else :size="13"/>{{ registering ? '提交中…' : '登记并检查' }}</button></footer>
      </form>
    </section>

    <section class="model-register surface-panel">
      <header class="section-head"><div><h2>检测与研判运行角色</h2><p>模型架构说明与实际制品状态分离，零指标不会被包装成已完成结果</p></div><span><Activity :size="13"/>{{ models?.items.length || 0 }} 个模型版本</span></header>
      <LoadingState v-if="modelStatus === 'pending'" :rows="3"/>
      <ErrorState v-else-if="modelError" @retry="refreshModels"/>
      <div v-else class="role-table">
        <article>
          <span class="role-icon transformer"><ScanSearch :size="18"/></span>
          <div class="role-copy"><p>已知攻击分类</p><h3>Flow Transformer</h3><span>Masked Feature Modeling → 分类微调 → 类别、置信度与异常特征</span></div>
          <div class="role-version"><small>登记版本 / 特征契约</small><code>{{ transformer?.version || '未登记' }} · {{ transformer?.featureVersion || '—' }}</code><em>{{ artifactLabel(transformer) }}</em></div>
          <div class="role-metric"><small>真实质量指标</small><b>{{ formatMetric(transformer) }}</b><span>{{ transformer?.throughput ? `${transformer.throughput.toLocaleString()}/s` : '无吞吐记录' }}</span></div>
          <StatusIndicator :status="transformer?.state || 'degraded'" :label="modelLabel(transformer)"/>
        </article>
        <article>
          <span class="role-icon transformer"><Workflow :size="18"/></span>
          <div class="role-copy"><p>CPU 对照与当前已知类通道</p><h3>Known Attack CPU Baseline</h3><span>HistGradientBoosting → 已知攻击类别与置信度；Transformer 完成前承担可复现分类基线</span></div>
          <div class="role-version"><small>登记版本 / 特征契约</small><code>{{ knownBaseline?.version || '未登记' }} · {{ knownBaseline?.featureVersion || '—' }}</code><em>{{ artifactLabel(knownBaseline) }}</em></div>
          <div class="role-metric"><small>真实质量指标</small><b>{{ formatMetric(knownBaseline) }}</b><span>{{ knownBaseline?.throughput ? `${knownBaseline.throughput.toLocaleString()}/s` : '无吞吐记录' }}</span></div>
          <StatusIndicator :status="knownBaseline?.state || 'degraded'" :label="modelLabel(knownBaseline)"/>
        </article>
        <article>
          <span class="role-icon autoencoder"><BrainCircuit :size="18"/></span>
          <div class="role-copy"><p>未知异常发现</p><h3>Flow AutoEncoder</h3><span>正常流量训练 → 特征重构 → 重构误差与异常阈值</span></div>
          <div class="role-version"><small>登记版本 / 特征契约</small><code>{{ autoEncoder?.version || '未登记' }} · {{ autoEncoder?.featureVersion || '—' }}</code><em>{{ artifactLabel(autoEncoder) }}</em></div>
          <div class="role-metric"><small>真实质量指标</small><b>{{ formatMetric(autoEncoder) }}</b><span>{{ autoEncoder?.throughput ? `${autoEncoder.throughput.toLocaleString()}/s` : '无吞吐记录' }}</span></div>
          <StatusIndicator :status="autoEncoder?.state || 'degraded'" :label="modelLabel(autoEncoder)"/>
        </article>
        <article>
          <span class="role-icon agent"><Workflow :size="18"/></span>
          <div class="role-copy"><p>下游研判与规则演进</p><h3>DeepSeek V4 Pro Agent</h3><span>只接收结构化画像与授权证据，不属于流量分类模型，也无权部署规则</span></div>
          <div class="role-version"><small>配置来源</small><code>Nuxt server runtime</code><em>真实 Model ID 和密钥不返回浏览器</em></div>
          <div class="role-metric"><small>调用边界</small><b>{{ integration?.configured ? '配置完整' : isMock ? '固定演示响应' : '尚未配置' }}</b><span>结构化响应强校验</span></div>
          <StatusIndicator :status="integration?.configured ? 'healthy' : 'degraded'" :label="integration?.configured ? '已配置' : isMock ? '演示模式' : '待配置'"/>
        </article>
      </div>
    </section>

    <section class="datasets-section surface-panel">
      <header class="section-head"><div><h2>训练数据资产</h2><p>文件身份、来源、数据画像和实验用途保存在数据库，训练程序只消费状态为“可用于实验”的版本</p></div><span><Database :size="13"/>{{ readyDatasets }} 可用<span v-if="profilingDatasets"> · {{ profilingDatasets }} 检查中</span></span></header>
      <LoadingState v-if="datasetStatus === 'pending'" :rows="5"/>
      <ErrorState v-else-if="datasetError" @retry="refreshDatasets"/>
      <EmptyState v-else-if="!datasets?.items.length" title="尚未登记真实数据集" description="把 CSV 放入后端受控数据目录，再通过“登记数据集”建立可审计的数据卡。">
        <button v-if="!isMock" class="empty-action" @click="showRegistration = true"><FolderPlus :size="13"/>登记第一个数据集</button>
      </EmptyState>
      <template v-else>
        <nav class="dataset-tabs" role="tablist" aria-label="数据集资产">
          <button v-for="dataset in datasets.items" :key="dataset.id" role="tab" :aria-selected="selectedDataset === dataset.id" :class="{ active: selectedDataset === dataset.id }" @click="selectedDataset = dataset.id">
            <span>{{ dataset.name }}</span><small>{{ dataset.version }} · {{ dataset.totalSamples ? `${formatCount(dataset.totalSamples)} 行` : '等待检查' }}</small><em :class="datasetStateTone(dataset.state)">{{ datasetStateLabel(dataset.state) }}</em>
          </button>
        </nav>
        <div v-if="activeDataset" class="dataset-detail">
          <div v-if="activeDataset.inspectionError" class="dataset-error"><TriangleAlert :size="14"/><span>{{ activeDataset.inspectionError }}</span></div>
          <div class="dataset-metrics">
            <div><span>总样本</span><b>{{ activeDataset.totalSamples.toLocaleString() }}</b></div><div><span>正常样本</span><b class="normal">{{ activeDataset.normalSamples.toLocaleString() }}</b></div><div><span>攻击样本</span><b class="attack">{{ activeDataset.attackSamples.toLocaleString() }}</b></div><div><span>特征数</span><b>{{ activeDataset.featureCount }}</b></div><div><span>缺失值</span><b :class="{ warning: activeDataset.missingValues > 0 }">{{ activeDataset.missingValues.toLocaleString() }}</b></div><div><span>数据切分</span><b>{{ activeDataset.split.train }} / {{ activeDataset.split.validation }} / {{ activeDataset.split.test }}</b></div>
          </div>
          <div class="dataset-provenance">
            <h3>文件身份与来源</h3>
            <dl><div><dt>相对路径</dt><dd><code>{{ activeDataset.relativePath || '演示快照无文件' }}</code></dd></div><div><dt>文件格式 / 大小</dt><dd>{{ activeDataset.format }} · {{ formatBytes(activeDataset.fileSizeBytes) }}</dd></div><div><dt>标签列</dt><dd>{{ activeDataset.labelColumn || '未识别或未配置' }}</dd></div><div><dt>SHA-256</dt><dd><code>{{ activeDataset.sha256 ? `${activeDataset.sha256.slice(0, 16)}…${activeDataset.sha256.slice(-8)}` : '尚未计算' }}</code></dd></div><div><dt>最近检查</dt><dd>{{ formatDate(activeDataset.inspectedAt) }}</dd></div><div><dt>来源</dt><dd><a v-if="activeDataset.sourceUri" :href="activeDataset.sourceUri" target="_blank" rel="noreferrer">发布页</a><span v-else>未登记</span></dd></div></dl>
          </div>
          <div class="distribution">
            <h3>真实标签分布</h3>
            <p v-if="!activeDataset.attackDistribution.length">尚无攻击标签统计</p>
            <div v-for="item in activeDataset.attackDistribution" :key="item.label"><span><b>{{ item.label }}</b><code>{{ item.count.toLocaleString() }}</code></span><i><em :style="{ width: `${Math.max(3, item.count / Math.max(...activeDataset.attackDistribution.map((row) => row.count)) * 100)}%` }"/></i></div>
          </div>
          <aside class="dataset-uses"><h3>实验边界</h3><span v-for="use in activeDataset.uses" :key="use"><CheckCircle2 :size="12"/>{{ use }}</span><div class="flags"><em :class="{ yes: activeDataset.mainTrainingSet }">主训练集</em><em :class="{ yes: activeDataset.unknownHoldout }">未知留出</em><em :class="{ yes: activeDataset.ruleReplay }">规则回放</em></div><button v-if="!isMock" :disabled="activeDataset.state === 'profiling'" @click="reprofile(activeDataset)"><RefreshCw :size="12" :class="{ spin: activeDataset.state === 'profiling' }"/>重新检查源文件</button></aside>
        </div>
      </template>
    </section>

    <section class="training-section surface-panel">
      <header class="section-head">
        <div><h2>可复现 CPU 基线训练</h2><p>真实 HistGradientBoosting 对照实验；用于证明数据与评估链路，不冒充 Flow Transformer</p></div>
        <span><Activity :size="13"/>{{ trainingRuns?.items.length || 0 }} 次运行<span v-if="hasActiveTraining"> · 进行中</span></span>
      </header>
      <form class="training-control" @submit.prevent="startTraining">
        <div class="baseline-boundary"><ShieldCheck :size="15"/><span><b>训练边界</b>重新计算源文件 SHA-256，扫描完整 CSV 后按全量标签分布进行固定种子分层配额抽样；明显标识符、时间列和目标代理列会被排除。</span></div>
        <label><span>已画像数据集</span><select v-model="selectedDataset" :disabled="!readyDatasetItems.length"><option v-for="dataset in readyDatasetItems" :key="dataset.id" :value="dataset.id">{{ dataset.name }} · {{ dataset.version }}</option></select></label>
        <label><span>最大训练样本</span><input v-model.number="trainingForm.maxRows" type="number" min="30" max="2000000" step="10000"><small>完整扫描，内存中最多保留该行数</small></label>
        <label><span>最大迭代次数</span><input v-model.number="trainingForm.maxIter" type="number" min="10" max="1000" step="10"><small>启用早停，实际可能提前结束</small></label>
        <label><span>随机种子</span><input v-model.number="trainingForm.randomSeed" type="number" min="0" max="2147483647"><small>分层配额抽样与切分可复现</small></label>
        <label class="training-ack"><input v-model="trainingAcknowledged" type="checkbox"><span>我已核对数据来源、标签列和切分比例；本操作会实际占用 CPU。</span></label>
        <button type="submit" :disabled="isMock || !activeDataset || activeDataset.state !== 'ready' || !trainingAcknowledged || trainingStarting || hasActiveTraining">
          <RefreshCw v-if="trainingStarting" :size="13" class="spin"/><Activity v-else :size="13"/>{{ trainingStarting ? '提交中…' : hasActiveTraining ? '已有训练进行中' : '启动真实基线训练' }}
        </button>
      </form>

      <LoadingState v-if="trainingStatus === 'pending'" :rows="4"/>
      <ErrorState v-else-if="trainingError" @retry="refreshTraining"/>
      <EmptyState v-else-if="!trainingRuns?.items.length" title="尚无真实训练运行" description="登记并完成数据画像后，才可以启动 CPU 基线。这里不会自动生成任何成绩。"/>
      <div v-else class="training-workbench">
        <nav class="run-list" aria-label="训练运行列表">
          <button v-for="run in trainingRuns.items" :key="run.id" :class="{ active: selectedTrainingRun === run.id }" @click="selectedTrainingRun = run.id">
            <span><b>{{ run.datasetName }}</b><em :class="run.state">{{ trainingStateLabel(run.state) }}</em></span>
            <small><code>{{ run.id.slice(0, 16) }}</code> · {{ formatDate(run.createdAt) }}</small>
            <span><i>{{ run.samplesUsed ? `${run.samplesUsed.toLocaleString()} 样本` : `${run.samplesSeen.toLocaleString()} 行已扫描` }}</i><i>{{ runMetricSummary(run) }}</i></span>
          </button>
        </nav>
        <article v-if="activeTrainingRun" class="run-detail">
          <header><div><p>{{ runTaskLabel(activeTrainingRun) }} / {{ activeTrainingRun.algorithm }}</p><h3>{{ activeTrainingRun.datasetName }}</h3></div><em :class="activeTrainingRun.state">{{ trainingStateLabel(activeTrainingRun.state) }}</em></header>
          <div v-if="activeTrainingRun.errorMessage" class="run-failure"><TriangleAlert :size="14"/>{{ activeTrainingRun.errorMessage }}</div>
          <div v-else-if="!activeTrainingRun.metrics" class="run-pending"><RefreshCw :size="15" :class="{ spin: activeTrainingRun.state === 'running' }"/><span>后台正在执行数据身份校验、分层切分、模型拟合和独立测试；尚未产生可展示指标。</span></div>
          <template v-else-if="isAutoEncoderMetrics(activeTrainingRun.metrics)">
            <div class="metric-strip">
              <div><span>攻击召回率</span><b>{{ formatPercent(activeTrainingRun.metrics.recall) }}</b></div>
              <div><span>正常流量误报率</span><b>{{ formatPercent(activeTrainingRun.metrics.normalFalsePositiveRate) }}</b></div>
              <div><span>AUROC</span><b>{{ activeTrainingRun.metrics.rocAuc.toFixed(4) }}</b></div>
              <div><span>异常阈值</span><b>{{ activeTrainingRun.metrics.threshold.toFixed(5) }}</b></div>
              <div><span>最佳 Epoch</span><b>{{ activeTrainingRun.metrics.bestEpoch }} / {{ activeTrainingRun.metrics.epochsCompleted }}</b></div>
            </div>
            <div class="run-provenance">
              <dl>
                <div><dt>扫描 / 使用</dt><dd>{{ activeTrainingRun.samplesSeen.toLocaleString() }} / {{ activeTrainingRun.samplesUsed.toLocaleString() }} 行</dd></div>
                <div><dt>正常训练 / 验证 / 测试</dt><dd>{{ activeTrainingRun.metrics.trainSamples }} / {{ activeTrainingRun.metrics.validationSamples }} / {{ activeTrainingRun.metrics.normalTestSamples }}</dd></div>
                <div><dt>攻击独立测试</dt><dd>{{ activeTrainingRun.metrics.attackTestSamples.toLocaleString() }} 条</dd></div>
                <div><dt>训练耗时</dt><dd>{{ activeTrainingRun.metrics.trainSeconds.toFixed(2) }}s</dd></div>
                <div class="hash"><dt>数据 SHA-256</dt><dd><code>{{ activeTrainingRun.datasetSha256 }}</code></dd></div>
                <div class="hash"><dt>制品 SHA-256</dt><dd><code>{{ activeTrainingRun.artifactSha256 || '未生成' }}</code></dd></div>
              </dl>
            </div>
            <div class="class-results">
              <header><h4>各攻击类别异常检出</h4><span>AUPRC {{ activeTrainingRun.metrics.averagePrecision.toFixed(4) }} · {{ activeTrainingRun.metrics.throughputFps.toLocaleString(undefined, { maximumFractionDigits: 0 }) }} flow/s</span></header>
              <table><thead><tr><th>攻击类别</th><th>Support</th><th>检出</th><th>Recall</th><th>中位重构误差</th></tr></thead><tbody><tr v-for="row in activeTrainingRun.metrics.perAttackClass" :key="row.label"><td>{{ row.label }}</td><td>{{ row.support }}</td><td>{{ row.detected }}</td><td>{{ formatPercent(row.recall) }}</td><td>{{ row.medianError.toFixed(5) }}</td></tr></tbody></table>
            </div>
            <footer class="feature-contract"><span><b>训练边界</b>仅使用 BENIGN 正常流量拟合网络参数与阈值</span><span><b>数值特征</b>{{ activeTrainingRun.metrics.numericFeatures.join(' · ') }}</span></footer>
          </template>
          <template v-else>
            <div class="metric-strip">
              <div><span>测试 Macro F1</span><b>{{ formatPercent(activeTrainingRun.metrics.macroF1) }}</b></div>
              <div><span>测试准确率</span><b>{{ formatPercent(activeTrainingRun.metrics.accuracy) }}</b></div>
              <div><span>验证 Macro F1</span><b>{{ formatPercent(activeTrainingRun.metrics.validationMacroF1) }}</b></div>
              <div><span>有效特征</span><b>{{ activeTrainingRun.metrics.featureCount }}</b></div>
              <div><span>训练耗时</span><b>{{ activeTrainingRun.metrics.trainSeconds.toFixed(2) }}s</b></div>
            </div>
            <div class="run-provenance">
              <dl>
                <div><dt>读取 / 使用</dt><dd>{{ activeTrainingRun.samplesSeen.toLocaleString() }} / {{ activeTrainingRun.samplesUsed.toLocaleString() }} 行</dd></div>
                <div><dt>训练 / 验证 / 测试</dt><dd>{{ activeTrainingRun.metrics.trainSamples }} / {{ activeTrainingRun.metrics.validationSamples }} / {{ activeTrainingRun.metrics.testSamples }}</dd></div>
                <div><dt>训练运行耗时</dt><dd>{{ runDuration(activeTrainingRun) }}</dd></div>
                <div><dt>制品状态</dt><dd>{{ activeTrainingRun.artifactState === 'available' ? '本地文件已验证存在' : '制品不可用' }}</dd></div>
                <div class="hash"><dt>数据 SHA-256</dt><dd><code>{{ activeTrainingRun.datasetSha256 }}</code></dd></div>
                <div class="hash"><dt>制品 SHA-256</dt><dd><code>{{ activeTrainingRun.artifactSha256 || '未生成' }}</code></dd></div>
              </dl>
            </div>
            <div class="class-results">
              <header><h4>独立测试集分类结果</h4><span>加权 F1 {{ formatPercent(activeTrainingRun.metrics.weightedF1) }} · {{ activeTrainingRun.metrics.throughputFps.toLocaleString(undefined, { maximumFractionDigits: 0 }) }} flow/s</span></header>
              <table><thead><tr><th>类别</th><th>Support</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody><tr v-for="row in activeTrainingRun.metrics.classMetrics" :key="row.label"><td>{{ row.label }}</td><td>{{ row.support }}</td><td>{{ formatPercent(row.precision) }}</td><td>{{ formatPercent(row.recall) }}</td><td>{{ formatPercent(row.f1) }}</td></tr></tbody></table>
            </div>
            <div class="confusion-results">
              <header><h4>测试集混淆矩阵</h4><span>行表示真实标签，列表示预测标签</span></header>
              <div class="matrix-scroll"><table><thead><tr><th>真实 \ 预测</th><th v-for="label in activeTrainingRun.metrics.labels" :key="`predicted-${label}`">{{ label }}</th></tr></thead><tbody><tr v-for="(row, rowIndex) in activeTrainingRun.metrics.confusionMatrix" :key="`actual-${activeTrainingRun.metrics.labels[rowIndex]}`"><th>{{ activeTrainingRun.metrics.labels[rowIndex] }}</th><td v-for="(count, columnIndex) in row" :key="`${rowIndex}-${columnIndex}`" :class="{ diagonal: rowIndex === columnIndex }">{{ count }}</td></tr></tbody></table></div>
            </div>
            <footer class="feature-contract"><span><b>数值特征</b>{{ activeTrainingRun.metrics.numericFeatures.join(' · ') }}</span><span><b>明确丢弃</b>{{ activeTrainingRun.metrics.droppedFeatures.length ? activeTrainingRun.metrics.droppedFeatures.join(' · ') : '无' }}</span></footer>
          </template>
        </article>
      </div>
    </section>
  </div>
</template>

<style scoped>
.models-page{padding:20px 22px 28px}.page-button{display:flex;align-items:center;gap:5px;height:34px;padding:0 9px;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-1);color:var(--text-secondary);font-size:13px;cursor:pointer}.page-button.primary{border-color:color-mix(in srgb,var(--accent) 50%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.page-button:disabled{opacity:.55;cursor:wait}.spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.mode-banner{display:grid;grid-template-columns:20px 1fr auto;gap:7px;align-items:center;margin-bottom:12px;padding:9px 11px;border:1px solid color-mix(in srgb,var(--status-success) 30%,var(--border-default));border-left:3px solid var(--status-success);background:color-mix(in srgb,var(--status-success) 5%,var(--surface-1));color:var(--status-success)}.mode-banner.mock{border-color:color-mix(in srgb,var(--status-warning) 35%,var(--border-default));border-left-color:var(--status-warning);background:color-mix(in srgb,var(--status-warning) 6%,var(--surface-1));color:var(--status-warning)}.mode-banner b,.mode-banner span{display:block}.mode-banner b{font-size:13px}.mode-banner span{margin-top:2px;color:var(--text-tertiary);font-size:12px}.mode-banner code{color:var(--text-tertiary);font-size:11px}.action-message{margin-bottom:10px;padding:8px 10px;border-left:2px solid var(--accent);background:var(--surface-1);color:var(--text-secondary);font-size:13px}.action-message.success{border-color:var(--status-success);color:var(--status-success)}.action-message.error{border-color:var(--status-error);color:var(--status-error)}
.registration-panel{margin-bottom:12px;overflow:hidden}.registration-panel>header{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid var(--border-subtle)}.registration-panel h2,.registration-panel p{margin:0}.registration-panel h2{font-size:14px}.registration-panel p{margin-top:2px;color:var(--text-tertiary);font-size:12px}.registration-panel>header svg{color:var(--accent-strong)}.registration-panel form{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;padding:12px}.registration-panel label>span{display:block;margin-bottom:4px;color:var(--text-secondary);font-size:12px}.registration-panel input{width:100%;height:33px;padding:0 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--surface-2);color:var(--text-primary);font-size:13px}.registration-panel small{display:block;margin-top:3px;color:var(--text-tertiary);font-size:11px}.registration-panel .wide{grid-column:span 2}.registration-panel fieldset{display:flex;align-items:center;gap:16px;margin:0;padding:7px 10px;border:1px solid var(--border-default);border-radius:6px}.registration-panel fieldset legend{padding:0 4px;color:var(--text-tertiary);font-size:11px}.registration-panel fieldset label{display:flex;align-items:center;gap:5px;color:var(--text-secondary);font-size:12px}.registration-panel fieldset input{width:14px;height:14px}.registration-panel footer{display:flex;justify-content:space-between;align-items:center;min-height:39px;padding-top:5px}.registration-panel footer>span{display:flex;align-items:center;gap:5px;color:var(--status-success);font-size:12px}.registration-panel footer button,.dataset-uses button,.empty-action{display:flex;align-items:center;gap:5px;height:30px;padding:0 8px;border:1px solid var(--accent);border-radius:5px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px;cursor:pointer}.registration-panel footer button:disabled,.dataset-uses button:disabled{opacity:.55;cursor:wait}
.model-register,.datasets-section,.training-section{margin-bottom:12px;overflow:hidden}.section-head{display:flex;justify-content:space-between;align-items:center;min-height:50px;padding:8px 12px;border-bottom:1px solid var(--border-subtle)}.section-head h2,.section-head p{margin:0}.section-head h2{font-size:13px}.section-head p{margin-top:2px;color:var(--text-tertiary);font-size:12px}.section-head>span{display:flex;align-items:center;color:var(--text-tertiary);font-size:12px}.role-table article{display:grid;grid-template-columns:38px minmax(260px,1.3fr) minmax(200px,.9fr) minmax(150px,.65fr) 110px;gap:10px;align-items:center;min-height:76px;padding:10px 12px;border-bottom:1px solid var(--border-subtle)}.role-table article:last-child{border-bottom:0}.role-icon{display:grid;width:34px;height:34px;place-items:center;border-radius:7px;background:var(--surface-2);color:var(--severity-info)}.role-icon.autoencoder,.role-icon.agent{color:var(--accent-strong)}.role-copy p,.role-copy h3,.role-copy span{display:block;margin:0}.role-copy p{color:var(--text-tertiary);font-size:11px;text-transform:uppercase}.role-copy h3{margin-top:1px;font-size:13px}.role-copy span,.role-version em,.role-metric span{margin-top:3px;color:var(--text-tertiary);font-size:12px;font-style:normal}.role-version small,.role-version code,.role-version em,.role-metric small,.role-metric b,.role-metric span{display:block}.role-version small,.role-metric small{color:var(--text-tertiary);font-size:11px}.role-version code{margin-top:2px;color:var(--text-secondary);font-size:12px}.role-version em{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.role-metric b{margin-top:2px;color:var(--text-secondary);font-size:13px}
.dataset-tabs{display:flex;overflow-x:auto;border-bottom:1px solid var(--border-subtle)}.dataset-tabs button{position:relative;flex:1;min-width:220px;min-height:61px;padding:9px 11px;border:0;border-right:1px solid var(--border-subtle);background:transparent;color:var(--text-secondary);cursor:pointer;text-align:left}.dataset-tabs button.active{background:var(--accent-muted)}.dataset-tabs button.active:after{position:absolute;right:10px;bottom:0;left:10px;height:2px;background:var(--accent);content:''}.dataset-tabs span,.dataset-tabs small{display:block}.dataset-tabs span{font-size:13px;font-weight:600}.dataset-tabs small{margin-top:3px;color:var(--text-tertiary);font-size:11px}.dataset-tabs em{position:absolute;top:9px;right:9px;padding:2px 5px;border-radius:4px;background:var(--surface-3);color:var(--text-tertiary);font-size:11px;font-style:normal}.dataset-tabs em.ready{background:color-mix(in srgb,var(--status-success) 10%,transparent);color:var(--status-success)}.dataset-tabs em.profiling{background:color-mix(in srgb,var(--severity-info) 10%,transparent);color:var(--severity-info)}.dataset-tabs em.error{background:color-mix(in srgb,var(--status-error) 9%,transparent);color:var(--status-error)}.dataset-tabs em.snapshot{background:color-mix(in srgb,var(--status-warning) 9%,transparent);color:var(--status-warning)}.dataset-detail{display:grid;grid-template-columns:1fr 1.1fr .9fr .8fr}.dataset-error{grid-column:1/-1;display:flex;gap:6px;align-items:center;padding:7px 10px;border-bottom:1px solid color-mix(in srgb,var(--status-error) 25%,var(--border-subtle));background:color-mix(in srgb,var(--status-error) 5%,transparent);color:var(--status-error);font-size:12px}.dataset-metrics{display:grid;grid-template-columns:1fr 1fr;border-right:1px solid var(--border-subtle)}.dataset-metrics div{padding:9px 10px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.dataset-metrics div:nth-child(even){border-right:0}.dataset-metrics span,.dataset-metrics b{display:block}.dataset-metrics span{color:var(--text-tertiary);font-size:11px}.dataset-metrics b{margin-top:2px;font:600 13px ui-monospace,monospace}.dataset-metrics .normal{color:var(--status-success)}.dataset-metrics .attack{color:var(--severity-high)}.dataset-metrics .warning{color:var(--status-warning)}.dataset-provenance,.distribution,.dataset-uses{padding:10px 12px;border-right:1px solid var(--border-subtle)}.dataset-uses{border-right:0}.dataset-provenance h3,.distribution h3,.dataset-uses h3{margin:0 0 7px;color:var(--text-tertiary);font-size:11px;text-transform:uppercase}.dataset-provenance dl{margin:0}.dataset-provenance dl>div{display:grid;grid-template-columns:100px 1fr;gap:5px;margin-bottom:5px}.dataset-provenance dt{color:var(--text-tertiary);font-size:11px}.dataset-provenance dd{min-width:0;margin:0;overflow:hidden;color:var(--text-secondary);font-size:11px;text-overflow:ellipsis;white-space:nowrap}.dataset-provenance a{color:var(--accent-strong)}.distribution>p{color:var(--text-tertiary);font-size:12px}.distribution>div{margin-bottom:7px}.distribution>div>span{display:flex;justify-content:space-between;font-size:11px}.distribution b{font-weight:500}.distribution code{color:var(--text-tertiary)}.distribution i{display:block;height:3px;margin-top:3px;background:var(--surface-3)}.distribution i em{display:block;height:100%;background:var(--severity-info)}.dataset-uses>span{display:flex;align-items:center;gap:4px;margin-bottom:6px;color:var(--text-secondary);font-size:12px}.dataset-uses>span svg{color:var(--status-success)}.flags{display:flex;gap:4px;flex-wrap:wrap;margin:9px 0}.flags em{padding:2px 5px;border:1px solid var(--border-subtle);border-radius:4px;color:var(--text-disabled);font-size:11px;font-style:normal}.flags em.yes{border-color:color-mix(in srgb,var(--accent) 35%,var(--border-subtle));background:var(--accent-muted);color:var(--accent-strong)}.dataset-uses button{margin-top:10px}.empty-action{margin:10px auto}
.training-control{display:grid;grid-template-columns:minmax(240px,1.4fr) repeat(3,minmax(120px,.55fr));gap:10px;align-items:end;padding:11px 12px;border-bottom:1px solid var(--border-subtle);background:color-mix(in srgb,var(--surface-2) 55%,transparent)}.training-control .baseline-boundary{grid-column:1/-1;display:flex;gap:7px;align-items:flex-start;padding:7px 8px;border-left:2px solid var(--severity-info);background:color-mix(in srgb,var(--severity-info) 5%,transparent);color:var(--text-secondary);font-size:12px}.baseline-boundary svg{flex:0 0 auto;color:var(--severity-info)}.baseline-boundary b{margin-right:5px;color:var(--text-primary)}.training-control label>span,.training-control label>small{display:block}.training-control label>span{margin-bottom:4px;color:var(--text-secondary);font-size:11px}.training-control label>small{margin-top:3px;color:var(--text-tertiary);font-size:10px}.training-control select,.training-control input[type=number]{width:100%;height:32px;padding:0 7px;border:1px solid var(--border-default);border-radius:5px;background:var(--surface-1);color:var(--text-primary);font-size:12px}.training-control .training-ack{grid-column:1/4;display:flex;gap:7px;align-items:center;min-height:31px}.training-control .training-ack>span{margin:0;color:var(--text-tertiary)}.training-control .training-ack input{accent-color:var(--accent)}.training-control>button{display:flex;align-items:center;justify-content:center;gap:5px;height:32px;border:1px solid var(--accent);border-radius:5px;background:var(--accent-muted);color:var(--accent-strong);font-size:12px;cursor:pointer}.training-control>button:disabled{border-color:var(--border-default);background:var(--surface-2);color:var(--text-disabled);cursor:not-allowed}.training-workbench{display:grid;grid-template-columns:310px minmax(0,1fr);min-height:350px}.run-list{border-right:1px solid var(--border-subtle);background:color-mix(in srgb,var(--surface-2) 35%,transparent)}.run-list button{display:block;width:100%;padding:9px 10px;border:0;border-bottom:1px solid var(--border-subtle);background:transparent;color:var(--text-secondary);cursor:pointer;text-align:left}.run-list button.active{background:var(--accent-muted);box-shadow:inset 2px 0 var(--accent)}.run-list button>span{display:flex;justify-content:space-between;gap:8px;align-items:center}.run-list b{overflow:hidden;font-size:12px;text-overflow:ellipsis;white-space:nowrap}.run-list em,.run-detail>header>em{padding:2px 5px;border-radius:4px;background:var(--surface-3);color:var(--text-tertiary);font-size:10px;font-style:normal}.run-list em.running,.run-list em.queued,.run-detail>header>em.running,.run-detail>header>em.queued{color:var(--severity-info)}.run-list em.succeeded,.run-detail>header>em.succeeded{color:var(--status-success)}.run-list em.failed,.run-detail>header>em.failed{color:var(--status-error)}.run-list small{display:block;margin:4px 0;color:var(--text-tertiary);font-size:10px}.run-list i{color:var(--text-tertiary);font-size:10px;font-style:normal}.run-detail{min-width:0}.run-detail>header{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid var(--border-subtle)}.run-detail p,.run-detail h3{margin:0}.run-detail p{color:var(--severity-info);font-size:10px;letter-spacing:.06em}.run-detail h3{margin-top:2px;font-size:14px}.run-failure,.run-pending{display:flex;gap:7px;align-items:center;padding:16px;color:var(--text-secondary);font-size:12px}.run-failure{color:var(--status-error)}.metric-strip{display:grid;grid-template-columns:repeat(5,1fr);border-bottom:1px solid var(--border-subtle)}.metric-strip div{padding:9px 10px;border-right:1px solid var(--border-subtle)}.metric-strip div:last-child{border-right:0}.metric-strip span,.metric-strip b{display:block}.metric-strip span{color:var(--text-tertiary);font-size:10px}.metric-strip b{margin-top:2px;font:600 14px ui-monospace,monospace}.run-provenance{padding:9px 11px;border-bottom:1px solid var(--border-subtle)}.run-provenance dl{display:grid;grid-template-columns:repeat(4,1fr);gap:6px 14px;margin:0}.run-provenance dl>div{min-width:0}.run-provenance .hash{grid-column:span 2}.run-provenance dt{color:var(--text-tertiary);font-size:10px}.run-provenance dd{margin:2px 0 0;color:var(--text-secondary);font-size:11px}.run-provenance code{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.class-results>header{display:flex;justify-content:space-between;align-items:center;padding:8px 11px}.class-results h4{margin:0;font-size:11px}.class-results header span{color:var(--text-tertiary);font-size:10px}.class-results table{width:100%;border-collapse:collapse}.class-results th,.class-results td{padding:6px 10px;border-top:1px solid var(--border-subtle);font-size:11px;text-align:right}.class-results th{color:var(--text-tertiary);font-weight:500}.class-results th:first-child,.class-results td:first-child{text-align:left}.class-results td:not(:first-child){font-family:ui-monospace,monospace}.feature-contract{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:9px 11px;border-top:1px solid var(--border-subtle);color:var(--text-tertiary);font-size:10px}.feature-contract span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.feature-contract b{margin-right:7px;color:var(--text-secondary)}
.confusion-results{border-top:1px solid var(--border-subtle)}.confusion-results>header{display:flex;justify-content:space-between;align-items:center;padding:8px 11px}.confusion-results h4{margin:0;font-size:11px}.confusion-results header span{color:var(--text-tertiary);font-size:10px}.matrix-scroll{overflow-x:auto;padding:0 11px 10px}.matrix-scroll table{min-width:100%;border-collapse:collapse;background:var(--surface-1)}.matrix-scroll th,.matrix-scroll td{min-width:68px;padding:5px 8px;border:1px solid var(--border-subtle);font-size:10px;text-align:right;white-space:nowrap}.matrix-scroll th{background:var(--surface-2);color:var(--text-tertiary);font-weight:500}.matrix-scroll th:first-child{text-align:left}.matrix-scroll td{font-family:ui-monospace,monospace;color:var(--text-secondary)}.matrix-scroll td.diagonal{background:color-mix(in srgb,var(--status-success) 8%,transparent);color:var(--status-success);font-weight:650}
@media(max-width:1100px){.role-table article{grid-template-columns:38px 1fr 1fr 100px}.role-metric{display:none}.dataset-detail{grid-template-columns:1fr 1fr}.dataset-metrics,.dataset-provenance{border-bottom:1px solid var(--border-subtle)}.dataset-provenance{border-right:0}.training-control{grid-template-columns:1fr 1fr}.training-control .training-ack{grid-column:1/-1}.training-workbench{grid-template-columns:260px minmax(0,1fr)}.metric-strip{grid-template-columns:repeat(3,1fr)}.metric-strip div{border-bottom:1px solid var(--border-subtle)}.run-provenance dl{grid-template-columns:1fr 1fr}}
@media(max-width:760px){.models-page{padding:16px 12px 24px}.mode-banner{grid-template-columns:20px 1fr}.mode-banner code{display:none}.registration-panel form{grid-template-columns:1fr}.registration-panel .wide{grid-column:auto}.registration-panel footer{align-items:flex-start;gap:8px}.role-table article{grid-template-columns:36px 1fr}.role-version,.role-table article>:last-child{grid-column:2}.dataset-detail{grid-template-columns:1fr}.dataset-metrics,.dataset-provenance,.distribution{border-right:0;border-bottom:1px solid var(--border-subtle)}.training-control{grid-template-columns:1fr}.training-control .baseline-boundary,.training-control .training-ack{grid-column:auto}.training-workbench{grid-template-columns:1fr}.run-list{max-height:220px;overflow:auto;border-right:0;border-bottom:1px solid var(--border-subtle)}.metric-strip{grid-template-columns:1fr 1fr}.run-provenance dl{grid-template-columns:1fr}.run-provenance .hash{grid-column:auto}.feature-contract{grid-template-columns:1fr}.class-results{overflow-x:auto}.class-results table{min-width:520px}}
</style>
