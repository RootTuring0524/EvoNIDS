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
})
export const sensorSummarySchema = z.object({
  total: z.number().int().nonnegative(), online: z.number().int().nonnegative(), degraded: z.number().int().nonnegative(),
  offline: z.number().int().nonnegative(), maintenance: z.number().int().nonnegative(), flows: z.number().int().nonnegative(),
  alerts: z.number().int().nonnegative(), rejectedEvents: z.number().int().nonnegative(),
})
export const sensorsResponseSchema = z.object({ items: z.array(sensorSchema), summary: sensorSummarySchema })
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
  qualityScore: z.number().optional(),
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
  displayModel: z.literal('DeepSeek V4 Pro'), runId: z.string(), state: z.enum(['completed', 'running', 'failed']), hypothesis: z.string(),
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
export type AuditEventsApiResponse = z.infer<typeof auditEventsResponseSchema>
