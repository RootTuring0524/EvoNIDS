export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type AlertStatus = 'new' | 'investigating' | 'contained' | 'closed'
export const DETECTION_CATEGORIES = [
  'DoS',
  'DDoS',
  'Port Scan',
  'Brute Force',
  'Botnet',
  'C2 Communication',
  'Web Attack',
  'Infiltration',
  'Abnormal Outbound Connection',
  'Unknown Anomaly',
] as const
export type DetectionCategory = (typeof DETECTION_CATEGORIES)[number]
export type RuleStage =
  | 'candidate'
  | 'validating'
  | 'validated'
  | 'rejected'
  | 'repaired'
  | 'confirmed'
  | 'deployed'
  | 'deprecated'

export interface Alert {
  id: string
  timestamp: string
  severity: Severity
  status: AlertStatus
  title: string
  category: DetectionCategory
  sourceIp: string
  destinationIp: string
  destinationPort: number
  protocol: string
  sensor: string
  riskScore: number
  confidence: number
  detector: string
  owner: string | null
  evidence: string[]
  agentState?: 'completed' | 'running' | 'failed' | 'not_run'
  agentDecision?: 'new_pattern' | 'rule_variant' | 'known_match' | 'benign' | null
  agentRunId?: string | null
}

export interface FlowRecord {
  id: string
  time: string
  source: string
  destination: string
  sourcePort: number
  destinationPort: number
  protocol: string
  service: string
  activity: string
  packets: number
  bytes: number
  durationMs: number
  verdict: 'benign' | 'suspicious' | 'malicious'
  anomalyScore: number
}

export interface RuleRecord {
  id: string
  name: string
  stage: RuleStage
  source: 'agent' | 'analyst' | 'community'
  severity: Severity
  coverage: string
  hitRate: number
  falsePositiveRate: number
  updatedAt: string
  author: string
  revision: number
  content: string
  rationale: string
  qualityScore?: number
}

export interface ModelRecord {
  id: string
  name: string
  role: string
  version: string
  state: 'healthy' | 'degraded' | 'training'
  latency: number
  throughput: number
  qualityLabel: string
  qualityValue: number
  artifactState: 'available' | 'missing' | 'unverified' | 'snapshot'
  featureVersion: string
  trainingRunId?: string | null
  datasetId?: string | null
  algorithm?: string | null
  artifactSha256?: string | null
  updatedAt: string
}

export type DetectionLean = 'known_attack' | 'unknown_anomaly' | 'dual_confirmed' | 'normal'

export interface TransformerOutput {
  prediction: string
  confidence: number
  topK: Array<{ label: string; probability: number }>
  modelVersion: string
  inferenceMs: number
  abnormalFeatures: Array<{ field: string; value: string; contribution: number }>
  isKnownClass: boolean
  pretrainingTask: string
}

export interface AutoEncoderOutput {
  reconstructionError: number
  threshold: number
  anomalyScore: number
  exceedsThreshold: boolean
  deviatingFeatures: Array<{ field: string; observed: number; baseline: number; deviation: number }>
  modelVersion: string
  inferenceMs: number
  trainedOn: 'normal_traffic'
}

export interface RiskFusion {
  finalScore: number
  transformerWeight: number
  autoEncoderWeight: number
  contextAdjustment: number
  agreement: 'consistent' | 'partial' | 'conflicting'
  lean: DetectionLean
  explanation: string
}

export interface AnomalyProfile {
  flow_id: string
  timestamp: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: string
  service: string
  flow_duration: number
  forward_packet_count: number
  backward_packet_count: number
  forward_bytes: number
  backward_bytes: number
  packets_per_second: number
  bytes_per_second: number
  syn_ratio: number
  ack_ratio: number
  rst_ratio: number
  destination_port_count_60s: number
  destination_ip_count_60s: number
  flow_count_60s: number
  average_packet_size: number
  transformer_prediction: string
  transformer_confidence: number
  autoencoder_reconstruction_error: number
  autoencoder_anomaly_score: number
  final_risk_score: number
  suspected_attack_type: string
}

export interface RagEvidence {
  id: string
  title: string
  sourceType:
    | 'MITRE ATT&CK'
    | '历史告警'
    | '检测规则'
    | 'Snort / Suricata'
    | '处置手册'
    | '协议知识'
    | 'CVE / CWE / CAPEC'
    | '已验证规则'
    | '失败规则'
  sourceId: string
  relevance: number
  trust: 'high' | 'medium' | 'low'
  excerpt: string
  updatedAt: string
  purpose: string
  allowed: boolean
  usedByAgent: boolean
  promptInjectionRisk: 'none' | 'review' | 'blocked'
  vectorScore: number
  keywordScore: number
  rerankScore: number
  matchedKeywords: string[]
}

export interface AgentStepRecord {
  id: string
  label: string
  state: 'completed' | 'active' | 'pending' | 'failed'
  tool: string
  durationMs: number
  result: string
}

export interface AgentAnalysis {
  displayModel: 'DeepSeek V4 Pro'
  runId: string
  state: 'completed' | 'running' | 'failed'
  hypothesis: string
  patternDecision: 'new_pattern' | 'rule_variant' | 'known_match' | 'benign'
  summary: string
  recommendation: string
  evidenceIds: string[]
  steps: AgentStepRecord[]
}

export interface AlertDetail {
  alert: Alert
  profile: AnomalyProfile
  transformer: TransformerOutput
  autoEncoder: AutoEncoderOutput
  fusion: RiskFusion
  rag: RagEvidence[]
  agent: AgentAnalysis
  ragQuery: string
  relatedRule: {
    recordId: string | null
    ruleId: string
    label: string
  } | null
}

export interface DatasetRecord {
  id: string
  name: string
  version: string
  state: 'profiling' | 'ready' | 'error' | 'missing' | 'snapshot'
  format: string
  relativePath: string
  sourceUri: string
  fileSizeBytes: number
  sha256: string | null
  labelColumn: string | null
  totalSamples: number
  normalSamples: number
  attackSamples: number
  featureCount: number
  missingValues: number
  split: { train: number; validation: number; test: number }
  mainTrainingSet: boolean
  unknownHoldout: boolean
  ruleReplay: boolean
  uses: string[]
  attackDistribution: Array<{ label: string; count: number }>
  inspectedAt: string | null
  inspectionError: string | null
  updatedAt: string
}

export interface DatasetRegistration {
  id: string
  name: string
  version: string
  relativePath: string
  sourceUri?: string
  labelColumn?: string | null
  normalLabels?: string[]
  split?: { train: number; validation: number; test: number }
  mainTrainingSet?: boolean
  unknownHoldout?: boolean
  ruleReplay?: boolean
  uses?: string[]
  actor?: string
  note?: string | null
}

export type TrainingRunState = 'queued' | 'running' | 'succeeded' | 'failed'

export interface TrainingClassMetric {
  label: string
  support: number
  precision: number
  recall: number
  f1: number
}

export interface TrainingMetrics {
  accuracy: number
  macroPrecision: number
  macroRecall: number
  macroF1: number
  weightedF1: number
  validationMacroF1: number
  trainSamples: number
  validationSamples: number
  testSamples: number
  droppedTargetRows: number
  featureCount: number
  labels: string[]
  classMetrics: TrainingClassMetric[]
  confusionMatrix: number[][]
  numericFeatures: string[]
  droppedFeatures: string[]
  trainSeconds: number
  testPredictMs: number
  throughputFps: number
}

export interface AutoEncoderAttackMetric {
  label: string
  support: number
  detected: number
  recall: number
  medianError: number
}

export interface AutoEncoderTrainingMetrics {
  accuracy: number
  precision: number
  recall: number
  f1: number
  rocAuc: number
  averagePrecision: number
  normalFalsePositiveRate: number
  threshold: number
  thresholdQuantile: number
  normalValidationErrorMean: number
  normalValidationErrorStd: number
  normalTestErrorMean: number
  attackTestErrorMean: number
  trainSamples: number
  validationSamples: number
  normalTestSamples: number
  attackTestSamples: number
  featureCount: number
  numericFeatures: string[]
  bestEpoch: number
  epochsCompleted: number
  epochHistory: Array<Record<string, number>>
  confusionMatrix: number[][]
  perAttackClass: AutoEncoderAttackMetric[]
  trainSeconds: number
  testPredictMs: number
  throughputFps: number
}

export interface TrainingRunRecord {
  id: string
  datasetId: string
  datasetName: string
  modelId: string | null
  task: 'known_attack_classification_baseline' | 'unknown_anomaly_detection'
  algorithm: 'hist_gradient_boosting' | 'mlp_autoencoder'
  state: TrainingRunState
  requestedBy: string
  datasetSha256: string
  featureVersion: string
  config: Record<string, unknown>
  samplesSeen: number
  samplesUsed: number
  startedAt: string | null
  completedAt: string | null
  metrics: TrainingMetrics | AutoEncoderTrainingMetrics | null
  artifactState: 'available' | 'missing' | 'unverified'
  artifactSha256: string | null
  errorMessage: string | null
  createdAt: string
  updatedAt: string
}

export interface TrainingRunCreate {
  datasetId: string
  algorithm?: 'hist_gradient_boosting'
  maxRows?: number
  randomSeed?: number
  maxIter?: number
  learningRate?: number
  maxLeafNodes?: number
  l2Regularization?: number
  actor?: string
}

export interface RuleCondition {
  field: string
  operator: '>' | '>=' | '<' | '<=' | '==' | '!=' | 'in'
  value: number | string | string[]
}

export interface StructuredRule {
  rule_id: string
  rule_name: string
  description: string
  attack_type: string
  severity: Severity
  attack_stage: string
  mitre_technique_ids: string[]
  conditions: RuleCondition[]
  evidence_ids: string[]
  generated_by: 'DeepSeek V4 Pro' | string
  version: number
  parent_rule_id: string | null
}

export interface RuleValidation {
  qualityScore: number
  syntax: number
  attackHitAbility: number
  lowFalsePositive: number
  coverage: number
  nonRedundancy: number
  evidenceConsistency: number
  hitRate: number
  falsePositiveRate: number
  precision: number
  recall: number
  f1: number
  attackCoverage: number
  redundancy: number
  perturbationRobustness: number
  replayAttackFlows: number
  replayNormalFlows: number
  schemaChecks: Array<{ label: string; passed: boolean; note: string }>
}

export interface RuleDetail {
  record: RuleRecord
  structured: StructuredRule
  validation: RuleValidation
  sourceAlertId: string
  previousVersion: StructuredRule | null
  diffReason: string
  expectedCoverageChange: string
  falsePositiveRisk: string
}

export interface AuditEvent {
  id: string
  createdAt: string
  actor: string
  action: string
  objectType: string
  objectId: string
  outcome: string
  requestId: string | null
  note: string | null
}

export type SensorState = 'online' | 'degraded' | 'offline' | 'maintenance'

export interface SensorRecord {
  id: string
  name: string
  location: string | null
  version: string | null
  state: SensorState
  healthReason: string
  lastSeenAt: string | null
  flowCount: number
  alertCount: number
  criticalAlerts: number
  acceptedEvents: number
  rejectedEvents: number
  ingestSource: string
  lastError: string | null
  createdAt: string
  updatedAt: string
}

export interface SensorSummary {
  total: number
  online: number
  degraded: number
  offline: number
  maintenance: number
  flows: number
  alerts: number
  rejectedEvents: number
}

export interface SensorsResponse {
  items: SensorRecord[]
  summary: SensorSummary
}

export interface OverviewMetrics {
  pendingAlerts: number
  highRiskAlerts: number
  unassignedAlerts: number
  flows: number
  anomalousFlows: number
  candidateRules: number
  deployedRules: number
  sensors: SensorSummary
}
