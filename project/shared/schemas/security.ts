import { z } from 'zod'
import { DETECTION_CATEGORIES } from '../types/security'

export const severitySchema = z.enum(['critical', 'high', 'medium', 'low', 'info'])
export const alertStatusSchema = z.enum(['new', 'investigating', 'contained', 'closed'])
export const detectionCategorySchema = z.enum(DETECTION_CATEGORIES)

export const alertSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  severity: severitySchema,
  status: alertStatusSchema,
  title: z.string(),
  category: detectionCategorySchema,
  sourceIp: z.string(),
  destinationIp: z.string(),
  destinationPort: z.number(),
  protocol: z.string(),
  sensor: z.string(),
  riskScore: z.number().min(0).max(100),
  confidence: z.number().min(0).max(100),
  detector: z.string(),
  owner: z.string().nullable(),
  evidence: z.array(z.string()),
  agentState: z.enum(['completed', 'running', 'failed', 'not_run']).default('not_run'),
  agentDecision: z.enum(['new_pattern', 'rule_variant', 'known_match', 'benign']).nullable().default(null),
  agentRunId: z.string().nullable().default(null),
})

export const alertsResponseSchema = z.object({
  items: z.array(alertSchema),
  total: z.number(),
  page: z.number(),
  pageSize: z.number(),
  agentCompleted: z.number().default(0),
  agentPending: z.number().default(0),
  agentDecisions: z.record(z.string(), z.number()).default({}),
})

export const flowSchema = z.object({
  id: z.string(),
  time: z.string(),
  source: z.string(),
  destination: z.string(),
  sourcePort: z.number(),
  destinationPort: z.number(),
  protocol: z.string(),
  service: z.string(),
  activity: z.string(),
  packets: z.number(),
  bytes: z.number(),
  durationMs: z.number(),
  verdict: z.enum(['benign', 'suspicious', 'malicious']),
  anomalyScore: z.number(),
})

export const flowsResponseSchema = z.object({ items: z.array(flowSchema), total: z.number() })

export const sensorStateSchema = z.enum(['online', 'degraded', 'offline', 'maintenance'])
export const sensorSchema = z.object({
  id: z.string(), name: z.string(), location: z.string().nullable(), version: z.string().nullable(),
  state: sensorStateSchema, healthReason: z.string(), lastSeenAt: z.string().nullable(), flowCount: z.number().int().nonnegative(),
  alertCount: z.number().int().nonnegative(), criticalAlerts: z.number().int().nonnegative(), acceptedEvents: z.number().int().nonnegative(),
  rejectedEvents: z.number().int().nonnegative(), ingestSource: z.string(), lastError: z.string().nullable(), createdAt: z.string(), updatedAt: z.string(),
  // Online ingestion-agent telemetry added by the backend heartbeat API. Optional
  // so pre-extension/mock registry payloads still parse; real backend always sends them.
  agentVersion: z.string().nullable().optional(),
  lastHeartbeatAt: z.string().nullable().optional(),
  clockSkewSeconds: z.number().nullable().optional(),
  spoolDepth: z.number().int().nonnegative().optional(),
  droppedEvents: z.number().int().nonnegative().optional(),
  expectedIntervalSeconds: z.number().int().positive().optional(),
  capabilities: z.array(z.string()).optional(),
})
export const sensorSummarySchema = z.object({
  total: z.number().int().nonnegative(), online: z.number().int().nonnegative(), degraded: z.number().int().nonnegative(),
  offline: z.number().int().nonnegative(), maintenance: z.number().int().nonnegative(), flows: z.number().int().nonnegative(),
  alerts: z.number().int().nonnegative(), rejectedEvents: z.number().int().nonnegative(),
})
export const sensorsResponseSchema = z.object({ items: z.array(sensorSchema), summary: sensorSummarySchema })

// ---- Sensor data-quality metrics (GET /sensors/health) ---------------------
// `measured: false` is an explicit "not measured" contract: the field carries no
// value in the window and must never be rendered as zero.
export const sensorMetricSchema = z.object({
  value: z.number().nullable(),
  measured: z.boolean(),
  unit: z.string(),
  note: z.string().nullable(),
})
export type SensorMetric = z.infer<typeof sensorMetricSchema>

export const sensorDataQualitySchema = z.object({
  sensorId: z.string(),
  state: sensorStateSchema,
  healthReason: z.string(),
  windowSeconds: z.number().int().min(60).max(604800),
  batches: z.number().int().nonnegative(),
  eventsAccepted: z.number().int().nonnegative(),
  eventsRejected: z.number().int().nonnegative(),
  eventsDuplicate: z.number().int().nonnegative(),
  rejectRate: sensorMetricSchema,
  duplicateRate: sensorMetricSchema,
  ingestLatencyP50Ms: sensorMetricSchema,
  ingestLatencyP95Ms: sensorMetricSchema,
  clockSkewSeconds: sensorMetricSchema,
  gapCount: sensorMetricSchema,
  estimatedMissingSeconds: sensorMetricSchema,
  spoolDepth: z.number().int().nonnegative(),
  droppedEvents: z.number().int().nonnegative(),
  expectedIntervalSeconds: z.number().int().positive(),
  lastBatchAt: z.string().nullable(),
  lastEventAt: z.string().nullable(),
  lastHeartbeatAt: z.string().nullable(),
})

export const sensorHealthResponseSchema = z.object({
  items: z.array(sensorDataQualitySchema),
})
export type SensorHealthApiResponse = z.infer<typeof sensorHealthResponseSchema>

// ---- Ingestion batch ledger (GET /sensors/{sensorId}/batches) --------------
export const ingestionBatchStatusSchema = z.enum(['accepted', 'partial', 'rejected'])
export const ingestionBatchSchema = z.object({
  id: z.string(),
  sensorId: z.string(),
  batchId: z.string(),
  receivedAt: z.string(),
  contentSha256: z.string(),
  encoding: z.string(),
  payloadBytes: z.number().int().nonnegative(),
  eventCount: z.number().int().nonnegative(),
  acceptedCount: z.number().int().nonnegative(),
  duplicateCount: z.number().int().nonnegative(),
  rejectedCount: z.number().int().nonnegative(),
  createdFlows: z.number().int().nonnegative(),
  createdAlerts: z.number().int().nonnegative(),
  firstEventAt: z.string().nullable(),
  lastEventAt: z.string().nullable(),
  clockSkewSeconds: z.number().nullable(),
  status: ingestionBatchStatusSchema,
})

export const ingestionBatchesResponseSchema = z.object({
  items: z.array(ingestionBatchSchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
})
export type IngestionBatchesApiResponse = z.infer<typeof ingestionBatchesResponseSchema>

// ---- Online detection status (GET /detections/status) ----------------------
export const detectionModeSchema = z.enum(['disabled', 'shadow', 'enabled'])
export const detectionChannelSchema = z.enum(['suricata', 'baseline', 'autoencoder'])
export const detectionChannelStatusSchema = z.object({
  available: z.boolean(),
  modelId: z.string().nullable(),
  version: z.string().nullable(),
  contractMatches: z.boolean(),
  reason: z.string().nullable(),
})

export const detectionStatusSchema = z.object({
  mode: detectionModeSchema,
  featureVersion: z.string(),
  channels: z.record(z.string(), detectionChannelStatusSchema),
  alerting: z.boolean(),
  notes: z.array(z.string()),
})
export type DetectionStatusApiResponse = z.infer<typeof detectionStatusSchema>

// ---- Detection signals / risk assessments ----------------------------------
export const signalDecisionSchema = z.enum(['alert', 'benign', 'abstain'])
export const assessmentDecisionSchema = z.enum(['malicious', 'suspicious', 'benign', 'abstain'])

export const detectionSignalDetailSchema = z.object({
  missingFields: z.array(z.string()),
  windowSeconds: z.number(),
  contextFeatures: z.record(z.string(), z.number()),
  prediction: z.string().optional(),
  topK: z.array(z.object({ label: z.string(), probability: z.number() })).optional(),
  reconstructionError: z.number().optional(),
  errorThreshold: z.number().optional(),
  exceedsThreshold: z.boolean().optional(),
  deviatingFeatures: z.array(z.object({
    field: z.string(), observed: z.number(), baseline: z.number(), deviation: z.number(),
  })).optional(),
  calibration: z.string().optional(),
  featureContract: z.string().optional(),
})

export const detectionSignalSchema = z.object({
  id: z.string(),
  createdAt: z.string(),
  flowId: z.string().nullable(),
  alertId: z.string().nullable(),
  sensorId: z.string(),
  channel: detectionChannelSchema,
  channelVersion: z.string(),
  modelId: z.string().nullable(),
  rawScore: z.number(),
  calibratedScore: z.number(),
  threshold: z.number(),
  decision: signalDecisionSchema,
  uncertainty: z.number(),
  featureVersion: z.string(),
  featureSource: z.string(),
  imputedFeatures: z.array(z.string()),
  latencyMs: z.number(),
  degraded: z.boolean(),
  degradedReason: z.string().nullable(),
  detail: detectionSignalDetailSchema,
})

export const detectionSignalsResponseSchema = z.object({
  items: z.array(detectionSignalSchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
})
export type DetectionSignalsApiResponse = z.infer<typeof detectionSignalsResponseSchema>

export const riskAssessmentInputSchema = z.object({
  signalId: z.string().nullable(),
  channel: detectionChannelSchema,
  channelVersion: z.string(),
  modelId: z.string().nullable(),
  rawScore: z.number(),
  calibratedScore: z.number(),
  decision: signalDecisionSchema,
  imputedFeatures: z.array(z.string()),
  degradedReason: z.string().nullable(),
})

export const riskAssessmentSchema = z.object({
  id: z.string(),
  createdAt: z.string(),
  flowId: z.string().nullable(),
  alertId: z.string().nullable(),
  sensorId: z.string(),
  signalIds: z.array(z.string()),
  inputs: z.array(riskAssessmentInputSchema),
  weights: z.record(z.string(), z.number()),
  finalScore: z.number(),
  uncertainty: z.number(),
  decision: assessmentDecisionSchema,
  explanation: z.string(),
  degradedReasons: z.array(z.string()),
  mode: z.string(),
})

export const detectionFlowDetailSchema = z.object({
  flowId: z.string(),
  signals: z.array(detectionSignalSchema),
  assessments: z.array(riskAssessmentSchema),
})
export type DetectionFlowDetailApiResponse = z.infer<typeof detectionFlowDetailSchema>
export const overviewMetricsSchema = z.object({
  pendingAlerts: z.number().int().nonnegative(), highRiskAlerts: z.number().int().nonnegative(), unassignedAlerts: z.number().int().nonnegative(),
  flows: z.number().int().nonnegative(), anomalousFlows: z.number().int().nonnegative(), candidateRules: z.number().int().nonnegative(),
  deployedRules: z.number().int().nonnegative(), sensors: sensorSummarySchema,
})
export const readinessResponseSchema = z.object({
  status: z.enum(['ready', 'attention']), environment: z.string(), checkedAt: z.string(), blockers: z.number().int().nonnegative(),
  warnings: z.number().int().nonnegative(), checks: z.array(z.object({ id: z.string(), label: z.string(), status: z.enum(['pass', 'warn', 'block']), detail: z.string() })),
})
export const eveIngestionResponseSchema = z.object({
  sensorId: z.string(), acceptedEvents: z.number().int(), createdFlows: z.number().int(), createdAlerts: z.number().int(),
  duplicateEvents: z.number().int(), rejectedEvents: z.number().int(),
  failures: z.array(z.object({ lineNumber: z.number().int(), reason: z.string() })),
})

export const ruleSchema = z.object({
  id: z.string(),
  name: z.string(),
  stage: z.enum(['candidate', 'validating', 'validated', 'rejected', 'repaired', 'confirmed', 'deployed', 'deprecated']),
  source: z.enum(['agent', 'analyst', 'community']),
  severity: severitySchema,
  coverage: z.string(),
  hitRate: z.number(),
  falsePositiveRate: z.number(),
  updatedAt: z.string(),
  author: z.string(),
  revision: z.number(),
  content: z.string(),
  rationale: z.string(),
  qualityScore: z.number().nullable().optional(),
})

export const rulesResponseSchema = z.object({ items: z.array(ruleSchema), total: z.number() })

export const modelSchema = z.object({
  id: z.string(),
  name: z.string(),
  role: z.string(),
  version: z.string(),
  state: z.enum(['healthy', 'degraded', 'training']),
  latency: z.number(),
  throughput: z.number(),
  qualityLabel: z.string(),
  qualityValue: z.number(),
  artifactState: z.enum(['available', 'missing', 'unverified', 'snapshot']),
  featureVersion: z.string(),
  trainingRunId: z.string().nullable().optional(),
  datasetId: z.string().nullable().optional(),
  algorithm: z.string().nullable().optional(),
  artifactSha256: z.string().length(64).nullable().optional(),
  updatedAt: z.string(),
})

export const modelsResponseSchema = z.object({ items: z.array(modelSchema) })

const transformerSchema = z.object({
  prediction: z.string(), confidence: z.number(), topK: z.array(z.object({ label: z.string(), probability: z.number() })),
  modelVersion: z.string(), inferenceMs: z.number(), abnormalFeatures: z.array(z.object({ field: z.string(), value: z.string(), contribution: z.number() })),
  isKnownClass: z.boolean(), pretrainingTask: z.string(),
})

const autoEncoderSchema = z.object({
  reconstructionError: z.number(), threshold: z.number(), anomalyScore: z.number(), exceedsThreshold: z.boolean(),
  deviatingFeatures: z.array(z.object({ field: z.string(), observed: z.number(), baseline: z.number(), deviation: z.number() })),
  modelVersion: z.string(), inferenceMs: z.number(), trainedOn: z.literal('normal_traffic'),
})

export const anomalyProfileSchema = z.object({
  flow_id: z.string(), timestamp: z.string(), src_ip: z.string(), src_port: z.number(), dst_ip: z.string(), dst_port: z.number(),
  protocol: z.string(), service: z.string(), flow_duration: z.number(), forward_packet_count: z.number(), backward_packet_count: z.number(),
  forward_bytes: z.number(), backward_bytes: z.number(), packets_per_second: z.number(), bytes_per_second: z.number(), syn_ratio: z.number(),
  ack_ratio: z.number(), rst_ratio: z.number(), destination_port_count_60s: z.number(), destination_ip_count_60s: z.number(), flow_count_60s: z.number(),
  average_packet_size: z.number(), transformer_prediction: z.string(), transformer_confidence: z.number(), autoencoder_reconstruction_error: z.number(),
  autoencoder_anomaly_score: z.number(), final_risk_score: z.number(), suspected_attack_type: z.string(),
})

export const ragEvidenceSchema = z.object({
  id: z.string(), title: z.string(), sourceType: z.enum(['MITRE ATT&CK', '历史告警', '检测规则', 'Snort / Suricata', '处置手册', '协议知识', 'CVE / CWE / CAPEC', '已验证规则', '失败规则']),
  sourceId: z.string(), relevance: z.number(), trust: z.enum(['high', 'medium', 'low']), excerpt: z.string(), updatedAt: z.string(), purpose: z.string(),
  allowed: z.boolean(), usedByAgent: z.boolean(), promptInjectionRisk: z.enum(['none', 'review', 'blocked']), vectorScore: z.number(), keywordScore: z.number(), rerankScore: z.number(), matchedKeywords: z.array(z.string()),
})

export const agentAnalysisSchema = z.object({
  // Resolved on the server from the configured NUXT_DEEPSEEK_MODEL; the mock data keeps the default label.
  displayModel: z.string().trim().min(1).max(80), runId: z.string(), state: z.enum(['completed', 'running', 'failed']), hypothesis: z.string(),
  patternDecision: z.enum(['new_pattern', 'rule_variant', 'known_match', 'benign']), summary: z.string(), recommendation: z.string(), evidenceIds: z.array(z.string()),
  steps: z.array(z.object({ id: z.string(), label: z.string(), state: z.enum(['completed', 'active', 'pending', 'failed']), tool: z.string(), durationMs: z.number(), result: z.string() })),
})

export const deepSeekChatCompletionSchema = z.object({
  choices: z.array(z.object({ message: z.object({ content: z.string().min(1) }) })).min(1),
})

export const alertDetailSchema = z.object({
  alert: alertSchema, profile: anomalyProfileSchema, transformer: transformerSchema, autoEncoder: autoEncoderSchema,
  fusion: z.object({ finalScore: z.number(), transformerWeight: z.number(), autoEncoderWeight: z.number(), contextAdjustment: z.number(), agreement: z.enum(['consistent', 'partial', 'conflicting']), lean: z.enum(['known_attack', 'unknown_anomaly', 'dual_confirmed', 'normal']), explanation: z.string() }),
  rag: z.array(ragEvidenceSchema), agent: agentAnalysisSchema, ragQuery: z.string(),
  relatedRule: z.object({ recordId: z.string().nullable(), ruleId: z.string(), label: z.string() }).nullable(),
})

const datasetSplitSchema = z.object({
  train: z.number().int().min(0).max(100),
  validation: z.number().int().min(0).max(100),
  test: z.number().int().min(0).max(100),
}).refine((value) => value.train + value.validation + value.test === 100, '数据切分比例之和必须为 100')

export const datasetRecordSchema = z.object({
  id: z.string(), name: z.string(), version: z.string(),
  state: z.enum(['profiling', 'ready', 'error', 'missing', 'snapshot']),
  format: z.string(), relativePath: z.string(), sourceUri: z.string(), fileSizeBytes: z.number().int().nonnegative(),
  sha256: z.string().length(64).nullable(), labelColumn: z.string().nullable(),
  totalSamples: z.number().int().nonnegative(), normalSamples: z.number().int().nonnegative(), attackSamples: z.number().int().nonnegative(),
  featureCount: z.number().int().nonnegative(), missingValues: z.number().int().nonnegative(), split: datasetSplitSchema,
  mainTrainingSet: z.boolean(), unknownHoldout: z.boolean(), ruleReplay: z.boolean(), uses: z.array(z.string()),
  attackDistribution: z.array(z.object({ label: z.string(), count: z.number().int().nonnegative() })),
  inspectedAt: z.string().nullable(), inspectionError: z.string().nullable(), updatedAt: z.string(),
})

export const datasetsResponseSchema = z.object({ items: z.array(datasetRecordSchema) })

export const trainingMetricsSchema = z.object({
  accuracy: z.number().min(0).max(1),
  macroPrecision: z.number().min(0).max(1),
  macroRecall: z.number().min(0).max(1),
  macroF1: z.number().min(0).max(1),
  weightedF1: z.number().min(0).max(1),
  validationMacroF1: z.number().min(0).max(1),
  trainSamples: z.number().int().nonnegative(),
  validationSamples: z.number().int().nonnegative(),
  testSamples: z.number().int().nonnegative(),
  droppedTargetRows: z.number().int().nonnegative(),
  featureCount: z.number().int().nonnegative(),
  labels: z.array(z.string()),
  classMetrics: z.array(z.object({
    label: z.string(), support: z.number().int().nonnegative(), precision: z.number(), recall: z.number(), f1: z.number(),
  })),
  confusionMatrix: z.array(z.array(z.number().int().nonnegative())),
  numericFeatures: z.array(z.string()),
  droppedFeatures: z.array(z.string()),
  trainSeconds: z.number().nonnegative(),
  testPredictMs: z.number().nonnegative(),
  throughputFps: z.number().nonnegative(),
}).superRefine((metrics, context) => {
  const labelCount = metrics.labels.length
  if (metrics.classMetrics.length !== labelCount) {
    context.addIssue({ code: 'custom', path: ['classMetrics'], message: 'classMetrics must align with labels' })
  }
  if (metrics.confusionMatrix.length !== labelCount) {
    context.addIssue({ code: 'custom', path: ['confusionMatrix'], message: 'confusionMatrix must align with labels' })
  }
  metrics.confusionMatrix.forEach((row, index) => {
    if (row.length !== labelCount) {
      context.addIssue({ code: 'custom', path: ['confusionMatrix', index], message: 'confusionMatrix must be square' })
    }
  })
})

export const autoEncoderTrainingMetricsSchema = z.object({
  accuracy: z.number().min(0).max(1),
  precision: z.number().min(0).max(1),
  recall: z.number().min(0).max(1),
  f1: z.number().min(0).max(1),
  rocAuc: z.number().min(0).max(1),
  averagePrecision: z.number().min(0).max(1),
  normalFalsePositiveRate: z.number().min(0).max(1),
  threshold: z.number().nonnegative(),
  thresholdQuantile: z.number().min(0).max(1),
  normalValidationErrorMean: z.number().nonnegative(),
  normalValidationErrorStd: z.number().nonnegative(),
  normalTestErrorMean: z.number().nonnegative(),
  attackTestErrorMean: z.number().nonnegative(),
  trainSamples: z.number().int().nonnegative(),
  validationSamples: z.number().int().nonnegative(),
  normalTestSamples: z.number().int().nonnegative(),
  attackTestSamples: z.number().int().nonnegative(),
  featureCount: z.number().int().nonnegative(),
  numericFeatures: z.array(z.string()),
  bestEpoch: z.number().int().positive(),
  epochsCompleted: z.number().int().positive(),
  epochHistory: z.array(z.record(z.string(), z.number())),
  confusionMatrix: z.array(z.array(z.number().int().nonnegative())),
  perAttackClass: z.array(z.object({
    label: z.string(),
    support: z.number().int().nonnegative(),
    detected: z.number().int().nonnegative(),
    recall: z.number().min(0).max(1),
    medianError: z.number().nonnegative(),
  })),
  trainSeconds: z.number().nonnegative(),
  testPredictMs: z.number().nonnegative(),
  throughputFps: z.number().nonnegative(),
})

export const trainingRunRecordSchema = z.object({
  id: z.string(), datasetId: z.string(), datasetName: z.string(), modelId: z.string().nullable(),
  task: z.enum(['known_attack_classification_baseline', 'unknown_anomaly_detection']),
  algorithm: z.enum(['hist_gradient_boosting', 'mlp_autoencoder']),
  state: z.enum(['queued', 'running', 'succeeded', 'failed']), requestedBy: z.string(), datasetSha256: z.string().length(64),
  featureVersion: z.string(), config: z.record(z.string(), z.unknown()), samplesSeen: z.number().int().nonnegative(),
  samplesUsed: z.number().int().nonnegative(), startedAt: z.string().nullable(), completedAt: z.string().nullable(),
  metrics: z.union([trainingMetricsSchema, autoEncoderTrainingMetricsSchema]).nullable(),
  artifactState: z.enum(['available', 'missing', 'unverified']),
  artifactSha256: z.string().length(64).nullable(), errorMessage: z.string().nullable(), createdAt: z.string(), updatedAt: z.string(),
})

export const trainingRunsResponseSchema = z.object({ items: z.array(trainingRunRecordSchema) })

export const trainingRunCreateSchema = z.object({
  datasetId: z.string().min(1).max(96),
  algorithm: z.literal('hist_gradient_boosting').default('hist_gradient_boosting'),
  maxRows: z.number().int().min(30).max(2_000_000).default(250_000),
  randomSeed: z.number().int().min(0).max(2_147_483_647).default(42),
  maxIter: z.number().int().min(10).max(1_000).default(200),
  learningRate: z.number().positive().max(1).default(0.08),
  maxLeafNodes: z.number().int().min(2).max(255).default(31),
  l2Regularization: z.number().min(0).max(100).default(0.1),
  actor: z.string().trim().min(1).max(120).default('local-ml-operator'),
})

export const datasetRegistrationSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{2,95}$/),
  name: z.string().trim().min(1).max(160),
  version: z.string().trim().min(1).max(64),
  relativePath: z.string().trim().min(1).max(1000),
  sourceUri: z.string().trim().max(2000).default(''),
  labelColumn: z.string().trim().max(160).nullable().optional(),
  normalLabels: z.array(z.string().trim().min(1)).max(20).default(['BENIGN', 'NORMAL', '0']),
  split: datasetSplitSchema.default({ train: 70, validation: 15, test: 15 }),
  mainTrainingSet: z.boolean().default(false),
  unknownHoldout: z.boolean().default(true),
  ruleReplay: z.boolean().default(false),
  uses: z.array(z.string().trim().min(1)).max(20).default([]),
  actor: z.string().trim().min(1).max(120).default('local-admin'),
  note: z.string().trim().max(500).nullable().optional(),
})

export const structuredRuleSchema = z.object({
  rule_id: z.string(), rule_name: z.string(), description: z.string(), attack_type: z.string(), severity: severitySchema, attack_stage: z.string(), mitre_technique_ids: z.array(z.string()),
  conditions: z.array(z.object({ field: z.string(), operator: z.enum(['>', '>=', '<', '<=', '==', '!=', 'in']), value: z.union([z.number(), z.string(), z.array(z.string())]) })),
  evidence_ids: z.array(z.string()), generated_by: z.string(), version: z.number(), parent_rule_id: z.string().nullable(),
})

// Mirrors backend app/domain/features.py FEATURES: the backend structural check stays authoritative.
export const RULE_CONDITION_FIELDS = {
  src_port: 'integer', dst_port: 'integer', protocol: 'string', service: 'string',
  flow_duration: 'number', forward_packet_count: 'integer', backward_packet_count: 'integer',
  forward_bytes: 'integer', backward_bytes: 'integer', packets_per_second: 'number',
  bytes_per_second: 'number', syn_ratio: 'number', ack_ratio: 'number', rst_ratio: 'number',
  destination_port_count_60s: 'integer', destination_ip_count_60s: 'integer',
  flow_count_60s: 'integer', average_packet_size: 'number',
} as const

export type RuleConditionField = keyof typeof RULE_CONDITION_FIELDS

export const agentProposedRuleSchema = z.object({
  ruleName: z.string().trim().min(4).max(120),
  description: z.string().trim().min(10).max(600),
  attackType: z.string().trim().min(2).max(60),
  severity: severitySchema,
  attackStage: z.string().trim().min(2).max(60),
  mitreTechniqueIds: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).max(6).default([]),
  conditions: z.array(z.object({
    field: z.string().trim(),
    operator: z.enum(['>', '>=', '<', '<=', '==', '!=', 'in']),
    value: z.union([z.number(), z.string(), z.array(z.string())]),
  })).min(1).max(6),
  rationale: z.string().trim().max(600).default(''),
}).superRefine((proposal, ctx) => {
  proposal.conditions.forEach((condition, index) => {
    const kind = RULE_CONDITION_FIELDS[condition.field as RuleConditionField]
    if (!kind) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['conditions', index, 'field'], message: `field ${condition.field} is not in the rule feature schema` })
      return
    }
    if (condition.operator === 'in') {
      if (!Array.isArray(condition.value) || condition.value.length === 0) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['conditions', index, 'value'], message: "operator 'in' requires a non-empty string list" })
      }
      return
    }
    if (Array.isArray(condition.value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['conditions', index, 'value'], message: 'only operator in accepts a list' })
      return
    }
    if (kind !== 'string' && typeof condition.value !== 'number') {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['conditions', index, 'value'], message: `field ${condition.field} requires a numeric value` })
    }
    if (kind === 'string' && typeof condition.value !== 'string') {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['conditions', index, 'value'], message: `field ${condition.field} requires a string value` })
    }
  })
})

export type AgentProposedRule = z.infer<typeof agentProposedRuleSchema>

export const agentRuleProposalSchema = z.object({
  structured: structuredRuleSchema,
  sourceAlertId: z.string(),
  rationale: z.string().max(2000),
})
export type AgentRuleProposal = z.infer<typeof agentRuleProposalSchema>

export const agentAnalysisResponseSchema = agentAnalysisSchema.extend({
  proposedRule: agentRuleProposalSchema.optional(),
})

export const ruleDetailSchema = z.object({
  record: ruleSchema, structured: structuredRuleSchema,
  validation: z.object({ qualityScore: z.number(), syntax: z.number(), attackHitAbility: z.number(), lowFalsePositive: z.number(), coverage: z.number(), nonRedundancy: z.number(), evidenceConsistency: z.number(), hitRate: z.number(), falsePositiveRate: z.number(), precision: z.number(), recall: z.number(), f1: z.number(), attackCoverage: z.number(), redundancy: z.number(), perturbationRobustness: z.number(), replayAttackFlows: z.number(), replayNormalFlows: z.number(), schemaChecks: z.array(z.object({ label: z.string(), passed: z.boolean(), note: z.string() })) }),
  sourceAlertId: z.string(), previousVersion: structuredRuleSchema.nullable(), diffReason: z.string(), expectedCoverageChange: z.string(), falsePositiveRisk: z.string(),
})

export const ragResponseSchema = z.object({
  query: z.string(),
  topK: z.number(),
  mode: z.enum(['fixed_mock_sample', 'keyword_fallback', 'hybrid']),
  retrieval: z.object({
    vectorCandidates: z.number().int().nonnegative(),
    keywordSupplementCandidates: z.number().int().nonnegative(),
    filteredCandidates: z.number().int().nonnegative(),
    rerankedCandidates: z.number().int().nonnegative(),
    providedToAgent: z.number().int().nonnegative(),
  }),
  items: z.array(ragEvidenceSchema),
})

export const integrationSettingsSchema = z.object({
  displayName: z.literal('DeepSeek V4 Pro'),
  useMockApi: z.boolean(),
  configured: z.boolean(),
  apiBaseState: z.enum(['configured', 'missing', 'invalid']),
  modelIdState: z.enum(['configured', 'missing']),
  apiKeyState: z.enum(['configured', 'missing']),
})

// Server-side status of the DeepSeek integration. Never contains the API key or the full base URL.
export const integrationsStatusSchema = integrationSettingsSchema.extend({
  deepseek: z.object({
    configured: z.boolean(),
    model: z.string(),
    baseUrlHost: z.string(),
    displayModel: z.string().trim().min(1),
  }),
})

export const auditEventsResponseSchema = z.object({
  items: z.array(z.object({
    id: z.string(),
    createdAt: z.string(),
    actor: z.string(),
    action: z.string(),
    objectType: z.string(),
    objectId: z.string(),
    outcome: z.string(),
    requestId: z.string().nullable(),
    note: z.string().nullable(),
  })),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
})

export type AlertsApiResponse = z.infer<typeof alertsResponseSchema>
export type FlowsApiResponse = z.infer<typeof flowsResponseSchema>
export type RulesApiResponse = z.infer<typeof rulesResponseSchema>
export type ModelsApiResponse = z.infer<typeof modelsResponseSchema>
export type DatasetsApiResponse = z.infer<typeof datasetsResponseSchema>
export type TrainingRunsApiResponse = z.infer<typeof trainingRunsResponseSchema>
export type AlertDetailApiResponse = z.infer<typeof alertDetailSchema>
export type RuleDetailApiResponse = z.infer<typeof ruleDetailSchema>
export type RagApiResponse = z.infer<typeof ragResponseSchema>
export type AgentApiResponse = z.infer<typeof agentAnalysisSchema>
export type SettingsApiResponse = z.infer<typeof integrationSettingsSchema>
export type IntegrationsStatusResponse = z.infer<typeof integrationsStatusSchema>
export type AuditEventsApiResponse = z.infer<typeof auditEventsResponseSchema>

// Case identifiers follow the backend CASE-<12 uppercase hex> format
// (mirrors CASE_ID_PATTERN in backend/app/api/routes/audit.py).
export const caseIdSchema = z
  .string()
  .regex(/^CASE-[A-F0-9]{12}$/, '案件编号格式应为 CASE- 后跟 12 位大写十六进制字符')
export type CaseId = z.infer<typeof caseIdSchema>

export const caseSeveritySchema = z.enum(['critical', 'high', 'medium', 'low'])
export const caseStatusSchema = z.enum(['open', 'investigating', 'contained', 'closed', 'archived'])

export const caseRecordSchema = z.object({
  id: z.string(),
  title: z.string(),
  summary: z.string(),
  severity: caseSeveritySchema,
  status: caseStatusSchema,
  assignee: z.string().nullable(),
  createdBy: z.string(),
  alertCount: z.number().int().nonnegative(),
  highestRiskScore: z.number().nonnegative(),
  createdAt: z.string(),
  updatedAt: z.string(),
})

export const casesResponseSchema = z.object({
  items: z.array(caseRecordSchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
})

export type CasesApiResponse = z.infer<typeof casesResponseSchema>

export const caseTimelineEventSchema = z.object({
  id: z.string(),
  eventType: z.string(),
  actor: z.string(),
  note: z.string().nullable(),
  createdAt: z.string(),
})

export const caseDetailSchema = z.object({
  case: caseRecordSchema,
  alerts: z.array(alertSchema),
  timeline: z.array(caseTimelineEventSchema),
})

export const caseSuggestionSchema = z.object({
  caseId: z.string(),
  caseTitle: z.string(),
  caseStatus: caseStatusSchema,
  sharedIps: z.array(z.string()),
  matchingAlertIds: z.array(z.string()),
  updatedAt: z.string(),
})

export const caseSuggestionResponseSchema = z.object({
  items: z.array(caseSuggestionSchema),
})

export const entityRecordSchema = z.object({
  id: z.string(),
  entityType: z.string(),
  value: z.string(),
  firstSeenAt: z.string(),
  lastSeenAt: z.string(),
  eventCount: z.number().int().nonnegative(),
  sensorIds: z.array(z.string()),
  createdAt: z.string(),
})

export const entitiesResponseSchema = z.object({
  items: z.array(entityRecordSchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
})

export const entityRelationItemSchema = z.object({
  id: z.string(),
  relationType: z.string(),
  otherEntityId: z.string(),
  otherEntityValue: z.string(),
  eventCount: z.number().int().nonnegative(),
  firstSeenAt: z.string(),
  lastSeenAt: z.string(),
})

export const entityDetailSchema = entityRecordSchema.extend({
  relations: z.array(entityRelationItemSchema),
})

export const evidenceRecordSchema = z.object({
  id: z.string(),
  sourceType: z.string(),
  sensorId: z.string(),
  eventType: z.string(),
  externalId: z.string(),
  observedAt: z.string(),
  receivedAt: z.string(),
  contentSha256: z.string().length(64),
  integrity: z.string(),
  dataMissing: z.string(),
  parserVersion: z.string(),
  redacted: z.boolean(),
  sourceRefType: z.string().nullable(),
  sourceRefId: z.string().nullable(),
  artifactSizeBytes: z.number().int().nonnegative(),
  createdAt: z.string(),
})

export const evidenceListResponseSchema = z.object({
  items: z.array(evidenceRecordSchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
})

export const evidenceDetailSchema = evidenceRecordSchema.extend({
  fields: z.record(z.unknown()),
  artifactText: z.string().nullable(),
})

export type EntitiesApiResponse = z.infer<typeof entitiesResponseSchema>
export type EvidenceListApiResponse = z.infer<typeof evidenceListResponseSchema>
export type EvidenceDetailApiResponse = z.infer<typeof evidenceDetailSchema>

// ---- Phase 4: AI investigations -------------------------------------------
// FastAPI /investigations contracts: run records, per-claim evidence
// citations, tool executions, analyst feedback and their read envelopes.
export const investigationStateSchema = z.enum([
  'queued', 'running', 'succeeded', 'insufficient_evidence', 'degraded', 'failed', 'cancelled',
])
export const investigationClaimTypeSchema = z.enum(['observation', 'inference', 'recommendation', 'rejected'])
export const feedbackVerdictSchema = z.enum(['agree', 'disagree', 'unsure'])

export const investigationRunSchema = z.object({
  id: z.string().min(1),
  alertId: z.string().min(1),
  caseId: z.string().nullable(),
  requestedBy: z.string().min(1),
  state: investigationStateSchema,
  mode: z.string(),
  provider: z.string(),
  modelId: z.string(),
  promptTemplateVersion: z.string(),
  toolRegistryVersion: z.string(),
  knowledgeVersion: z.string(),
  maxToolCalls: z.number().int().min(1).max(6),
  budgetUsd: z.number().nullable(),
  inputEvidenceIds: z.array(z.string()),
  // Retrieval snapshot is an opaque backend object; scalar/leaf values are
  // rendered verbatim by the UI without assuming its internal keys.
  retrieval: z.record(z.string(), z.unknown()),
  summary: z.string().nullable(),
  uncertainty: z.number().nullable(),
  promptTokens: z.number().int().nonnegative(),
  completionTokens: z.number().int().nonnegative(),
  costEstimateUsd: z.number().nullable(),
  latencyMs: z.number().nullable(),
  attempts: z.number().int().nonnegative(),
  degradedReasons: z.array(z.string()),
  errorMessage: z.string().nullable(),
  startedAt: z.string().nullable(),
  completedAt: z.string().nullable(),
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
})

export const investigationClaimSchema = z.object({
  id: z.string().min(1),
  runId: z.string().min(1),
  claimIndex: z.number().int().nonnegative(),
  claimType: investigationClaimTypeSchema,
  statement: z.string().min(1),
  evidenceIds: z.array(z.string()),
  confidence: z.number(),
  uncertainty: z.number(),
  mitreTechniques: z.array(z.string()),
  verified: z.boolean(),
  rejectionReason: z.string().nullable(),
  createdAt: z.string().min(1),
})

export const toolExecutionStateSchema = z.enum(['completed', 'rejected', 'failed'])
export const toolExecutionSchema = z.object({
  id: z.string().min(1),
  runId: z.string().min(1),
  toolName: z.string().min(1),
  toolVersion: z.string(),
  arguments: z.record(z.string(), z.unknown()),
  resultSummary: z.string().nullable(),
  state: toolExecutionStateSchema,
  durationMs: z.number().nonnegative(),
  error: z.string().nullable(),
  createdAt: z.string().min(1),
})

export const feedbackReadSchema = z.object({
  id: z.string().min(1),
  objectType: z.string().min(1),
  objectId: z.string().min(1),
  verdict: feedbackVerdictSchema,
  label: z.string().nullable(),
  comment: z.string().nullable(),
  actor: z.string(),
  createdAt: z.string().min(1),
})

export const investigationsListResponseSchema = z.object({
  items: z.array(investigationRunSchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
})

export const investigationDetailResponseSchema = z.object({
  run: investigationRunSchema,
  claims: z.array(investigationClaimSchema),
  tools: z.array(toolExecutionSchema),
  feedback: z.array(feedbackReadSchema),
})

// Request bodies accepted by the BFF (backend keeps authority on further rules).
export const investigationCreateRequestSchema = z.object({
  alertId: z.string().trim().min(1).max(160),
  caseId: z.string().trim().max(32).optional(),
  maxToolCalls: z.number().int().min(1).max(6).optional(),
  budgetUsd: z.number().positive().optional(),
})

export const feedbackCreateRequestSchema = z.object({
  objectType: z.string().trim().min(1).max(64),
  objectId: z.string().trim().min(1).max(160),
  verdict: feedbackVerdictSchema,
  label: z.string().trim().max(200).optional(),
  comment: z.string().trim().max(2000).optional(),
})

// ---- Phase 4: LLM gateway --------------------------------------------------
export const llmCircuitStateSchema = z.enum(['open', 'closed'])
export const llmStatusBudgetSchema = z.object({
  day: z.string(),
  spentUsd: z.number().nonnegative(),
  dailyBudgetUsd: z.number().nonnegative(),
  runBudgetUsd: z.number().nonnegative(),
  remainingUsd: z.number(),
})
export const llmStatusSchema = z.object({
  provider: z.string(),
  model: z.string(),
  available: z.boolean(),
  circuit: z.object({
    state: llmCircuitStateSchema,
    consecutiveFailures: z.number().int().nonnegative(),
    resetInSeconds: z.number().nullable(),
  }),
  concurrencyLimit: z.number().int().nonnegative(),
  timeoutSeconds: z.number().int().nonnegative(),
  maxAttempts: z.number().int().nonnegative(),
  budget: llmStatusBudgetSchema,
  stats: z.record(z.string(), z.number()),
  pricingKnown: z.boolean(),
})
export const llmProbeResultSchema = z.object({
  available: z.boolean(),
  models: z.array(z.string()),
  configuredModelExists: z.boolean(),
  error: z.string().nullable(),
})

// ---- Phase 5: rule governance ----------------------------------------------
export const sandboxCapabilitySchema = z.object({
  suricataAvailable: z.boolean(),
  binary: z.string().nullable(),
  executorVersion: z.string(),
  note: z.string().nullable(),
})

export const ruleIRVersionSchema = z.object({
  id: z.string().min(1),
  ruleId: z.string().min(1),
  version: z.number().int().positive(),
  sid: z.number().int().nullable(),
  rev: z.number().int().nullable(),
  irDigest: z.string(),
  irDocument: z.record(z.string(), z.unknown()),
  suricataText: z.string().nullable(),
  state: z.string(),
  createdBy: z.string(),
  createdAt: z.string().min(1),
})

export const ruleSandboxRunStatusSchema = z.enum([
  'blocked', 'partial', 'validated', 'validation_failed', 'failed',
])
export const ruleSandboxMetricsSchema = z.object({
  normalFlows: z.number().int().nonnegative(),
  maliciousFlows: z.number().int().nonnegative(),
  truePositives: z.number().int().nonnegative(),
  falsePositives: z.number().int().nonnegative(),
  falseNegatives: z.number().int().nonnegative(),
  // Unmeasured metrics are serialised as null by the backend and must stay null
  // so the UI can render 未测量 instead of a fabricated 0.
  recall: z.number().nullable(),
  precision: z.number().nullable(),
  f1: z.number().nullable(),
  falsePositiveRate: z.number().nullable(),
  falsePositivesPerMillion: z.number().nullable(),
  replaySeconds: z.number().nonnegative().nullable(),
  peakRssKb: z.number().nonnegative().nullable(),
  // Explicit per-metric measurement flags; measured:false must render as 未测量.
  measured: z.record(z.string(), z.boolean()),
})
export const ruleSandboxCheckSchema = z.object({
  label: z.string(),
  passed: z.boolean(),
  note: z.string(),
})
export const ruleSandboxRunSchema = z.object({
  id: z.string().min(1),
  ruleId: z.string().min(1),
  ruleVersionId: z.string().min(1),
  status: ruleSandboxRunStatusSchema,
  suricataAvailable: z.boolean(),
  suricataVersion: z.string().nullable(),
  syntaxPassed: z.boolean(),
  executorVersion: z.string(),
  // The API stores the PCAP paths it was given (or null); it is not a boolean
  // switch, so the response schema must accept a string or null.
  normalPcap: z.string().nullable(),
  maliciousPcap: z.string().nullable(),
  metrics: ruleSandboxMetricsSchema,
  checks: z.array(ruleSandboxCheckSchema),
  passed: z.boolean(),
  blockedReason: z.string().nullable(),
  detail: z.string().nullable(),
  createdAt: z.string().min(1),
})

export const ruleDeploymentStateSchema = z.enum(['canary', 'deployed', 'rolled_back'])
export const ruleDeploymentSchema = z.object({
  id: z.string().min(1),
  ruleId: z.string().min(1),
  ruleVersionId: z.string().min(1),
  sensorGroupId: z.string().min(1),
  state: ruleDeploymentStateSchema,
  deployedBy: z.string(),
  deployedAt: z.string(),
  promotedAt: z.string().nullable(),
  rolledBackAt: z.string().nullable(),
  rollbackReason: z.string().nullable(),
  monitoring: z.record(z.string(), z.unknown()),
  previousVersionId: z.string().nullable(),
  createdAt: z.string().min(1),
})
export const ruleDeploymentsResponseSchema = z.object({
  items: z.array(ruleDeploymentSchema),
})

export const sensorGroupStageSchema = z.enum(['canary', 'production'])
export const sensorGroupSchema = z.object({
  id: z.string().min(1),
  name: z.string(),
  description: z.string().nullable(),
  sensorIds: z.array(z.string()),
  stage: sensorGroupStageSchema,
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
})

// Request bodies accepted by the BFF for rule-governance actions.
export const irCompileRequestSchema = z.object({
  ir: z.record(z.string(), z.unknown()),
  sid: z.number().int().positive().max(2147483647).optional(),
})
export const sandboxRunRequestSchema = z.object({
  normalPcap: z.boolean().optional(),
  maliciousPcap: z.boolean().optional(),
  maliciousFlows: z.number().int().nonnegative().optional(),
  normalFlows: z.number().int().nonnegative().optional(),
  recallFloor: z.number().min(0).max(1).optional(),
  falsePositivesPerMillionCeiling: z.number().min(0).max(1000000).optional(),
})
export const ruleDeploymentCreateRequestSchema = z.object({
  ruleVersionId: z.string().trim().min(1).max(160),
  sensorGroupId: z.string().trim().min(1).max(160),
  state: z.enum(['canary', 'deployed']),
  note: z.string().trim().max(500).optional(),
})
export const ruleDeploymentPromoteRequestSchema = z.object({
  note: z.string().trim().max(500).optional(),
  targetGroupId: z.string().trim().max(160).optional(),
})
export const ruleDeploymentRollbackRequestSchema = z.object({
  reason: z.string().trim().min(10).max(1000),
})
export const sensorGroupCreateRequestSchema = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(500).optional(),
  sensorIds: z.array(z.string().trim().min(1)).max(1000).default([]),
  stage: sensorGroupStageSchema,
})

export type InvestigationRunApiResponse = z.infer<typeof investigationRunSchema>
export type InvestigationClaimApiResponse = z.infer<typeof investigationClaimSchema>
export type ToolExecutionApiResponse = z.infer<typeof toolExecutionSchema>
export type FeedbackApiResponse = z.infer<typeof feedbackReadSchema>
export type InvestigationsListApiResponse = z.infer<typeof investigationsListResponseSchema>
export type InvestigationDetailApiResponse = z.infer<typeof investigationDetailResponseSchema>
export type LlmStatusApiResponse = z.infer<typeof llmStatusSchema>
export type LlmProbeApiResponse = z.infer<typeof llmProbeResultSchema>
export type SandboxCapabilityApiResponse = z.infer<typeof sandboxCapabilitySchema>
export type RuleIRVersionApiResponse = z.infer<typeof ruleIRVersionSchema>
export type RuleSandboxRunApiResponse = z.infer<typeof ruleSandboxRunSchema>
export type RuleDeploymentApiResponse = z.infer<typeof ruleDeploymentSchema>
export type RuleDeploymentsApiResponse = z.infer<typeof ruleDeploymentsResponseSchema>
export type SensorGroupApiResponse = z.infer<typeof sensorGroupSchema>
