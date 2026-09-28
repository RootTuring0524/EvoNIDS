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
  // The FastAPI contract emits an explicit null while a rule awaits replay validation.
  qualityScore?: number | null
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
  displayModel: string
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
  // Online ingestion-agent telemetry reported by recent heartbeats. Optional so
  // older/mock registry payloads (which predate the backend extension) stay valid.
  agentVersion?: string | null
  lastHeartbeatAt?: string | null
  clockSkewSeconds?: number | null
  spoolDepth?: number
  droppedEvents?: number
  expectedIntervalSeconds?: number
  capabilities?: string[]
  createdAt: string
  updatedAt: string
}

/**
 * A single sensor telemetry metric. `measured: false` is an explicit "not
 * measured" signal (no data in the window) and MUST NOT be rendered as zero.
 */
export interface SensorMetric {
  value: number | null
  measured: boolean
  unit: string
  note: string | null
}

export interface SensorDataQuality {
  sensorId: string
  state: SensorState
  healthReason: string
  windowSeconds: number
  batches: number
  eventsAccepted: number
  eventsRejected: number
  eventsDuplicate: number
  rejectRate: SensorMetric
  duplicateRate: SensorMetric
  ingestLatencyP50Ms: SensorMetric
  ingestLatencyP95Ms: SensorMetric
  clockSkewSeconds: SensorMetric
  gapCount: SensorMetric
  estimatedMissingSeconds: SensorMetric
  spoolDepth: number
  droppedEvents: number
  expectedIntervalSeconds: number
  lastBatchAt: string | null
  lastEventAt: string | null
  lastHeartbeatAt: string | null
}

export interface SensorHealthResponse {
  items: SensorDataQuality[]
}

export type IngestionBatchStatus = 'accepted' | 'partial' | 'rejected'

export interface IngestionBatch {
  id: string
  sensorId: string
  batchId: string
  receivedAt: string
  contentSha256: string
  encoding: string
  payloadBytes: number
  eventCount: number
  acceptedCount: number
  duplicateCount: number
  rejectedCount: number
  createdFlows: number
  createdAlerts: number
  firstEventAt: string | null
  lastEventAt: string | null
  clockSkewSeconds: number | null
  status: IngestionBatchStatus
}

export interface IngestionBatchesResponse {
  items: IngestionBatch[]
  total: number
  page: number
  pageSize: number
}

export type DetectionMode = 'disabled' | 'shadow' | 'enabled'
export type DetectionChannel = 'suricata' | 'baseline' | 'autoencoder'
export type SignalDecision = 'alert' | 'benign' | 'abstain'
export type AssessmentDecision = 'malicious' | 'suspicious' | 'benign' | 'abstain'

export interface DetectionChannelStatus {
  available: boolean
  modelId: string | null
  version: string | null
  contractMatches: boolean
  reason: string | null
}

export interface DetectionStatus {
  mode: DetectionMode
  featureVersion: string
  channels: Record<string, DetectionChannelStatus>
  alerting: boolean
  notes: string[]
}

/**
 * Channel-specific scoring detail carried inside every detection signal.
 * Baseline emits prediction/topK, autoencoder emits reconstructionError and
 * friends; missingFields/windowSeconds/contextFeatures are always present.
 */
export interface DetectionSignalDetail {
  missingFields: string[]
  windowSeconds: number
  contextFeatures: Record<string, number>
  prediction?: string
  topK?: Array<{ label: string; probability: number }>
  reconstructionError?: number
  errorThreshold?: number
  exceedsThreshold?: boolean
  deviatingFeatures?: Array<{ field: string; observed: number; baseline: number; deviation: number }>
  calibration?: string
  featureContract?: string
}

export interface DetectionSignal {
  id: string
  createdAt: string
  flowId: string | null
  alertId: string | null
  sensorId: string
  channel: DetectionChannel
  channelVersion: string
  modelId: string | null
  rawScore: number
  calibratedScore: number
  threshold: number
  decision: SignalDecision
  uncertainty: number
  featureVersion: string
  featureSource: string
  imputedFeatures: string[]
  latencyMs: number
  degraded: boolean
  degradedReason: string | null
  detail: DetectionSignalDetail
}

export interface RiskAssessmentInput {
  signalId: string | null
  channel: DetectionChannel
  channelVersion: string
  modelId: string | null
  rawScore: number
  calibratedScore: number
  decision: SignalDecision
  imputedFeatures: string[]
  degradedReason: string | null
}

export interface RiskAssessment {
  id: string
  createdAt: string
  flowId: string | null
  alertId: string | null
  sensorId: string
  signalIds: string[]
  inputs: RiskAssessmentInput[]
  weights: Record<string, number>
  finalScore: number
  uncertainty: number
  decision: AssessmentDecision
  explanation: string
  degradedReasons: string[]
  mode: string
}

export interface DetectionSignalsResponse {
  items: DetectionSignal[]
  total: number
  page: number
  pageSize: number
}

export interface DetectionFlowDetail {
  flowId: string
  signals: DetectionSignal[]
  assessments: RiskAssessment[]
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

export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low'
export type CaseStatus = 'open' | 'investigating' | 'contained' | 'closed' | 'archived'

export interface CaseRecord {
  id: string
  title: string
  summary: string
  severity: CaseSeverity
  status: CaseStatus
  assignee: string | null
  createdBy: string
  alertCount: number
  highestRiskScore: number
  createdAt: string
  updatedAt: string
}

export interface CaseTimelineEventItem {
  id: string
  eventType: string
  actor: string
  note: string | null
  createdAt: string
}

export interface CaseDetailData {
  case: CaseRecord
  alerts: Alert[]
  timeline: CaseTimelineEventItem[]
}

export interface CaseSuggestionItem {
  caseId: string
  caseTitle: string
  caseStatus: CaseStatus
  sharedIps: string[]
  matchingAlertIds: string[]
  updatedAt: string
}

export interface EntityRecord {
  id: string
  entityType: string
  value: string
  firstSeenAt: string
  lastSeenAt: string
  eventCount: number
  sensorIds: string[]
  createdAt: string
}

export interface EntityRelationItem {
  id: string
  relationType: string
  otherEntityId: string
  otherEntityValue: string
  eventCount: number
  firstSeenAt: string
  lastSeenAt: string
}

export interface EntityDetailData extends EntityRecord {
  relations: EntityRelationItem[]
}

export interface EvidenceRecord {
  id: string
  sourceType: string
  sensorId: string
  eventType: string
  externalId: string
  observedAt: string
  receivedAt: string
  contentSha256: string
  integrity: string
  dataMissing: string
  parserVersion: string
  redacted: boolean
  sourceRefType: string | null
  sourceRefId: string | null
  artifactSizeBytes: number
  createdAt: string
}

export interface EvidenceDetailData extends EvidenceRecord {
  fields: Record<string, unknown>
  artifactText: string | null
}

// ---- Phase 4: AI investigations -------------------------------------------
// Mirrors the FastAPI contracts for investigation runs, per-claim evidence
// citations, tool executions and analyst feedback. Every value rendered in the
// console comes from these reads; nothing is fabricated client-side.

export type InvestigationRunState =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'insufficient_evidence'
  | 'degraded'
  | 'failed'
  | 'cancelled'

export type InvestigationClaimType = 'observation' | 'inference' | 'recommendation' | 'rejected'
export type FeedbackVerdict = 'agree' | 'disagree' | 'unsure'

export interface InvestigationRunRecord {
  id: string
  alertId: string
  caseId: string | null
  requestedBy: string
  state: InvestigationRunState
  mode: string
  provider: string
  modelId: string
  promptTemplateVersion: string
  toolRegistryVersion: string
  knowledgeVersion: string
  maxToolCalls: number
  budgetUsd: number | null
  inputEvidenceIds: string[]
  /** Hybrid-RAG retrieval snapshot as reported by the backend (opaque object). */
  retrieval: Record<string, unknown>
  summary: string | null
  uncertainty: number | null
  promptTokens: number
  completionTokens: number
  costEstimateUsd: number | null
  latencyMs: number | null
  attempts: number
  degradedReasons: string[]
  errorMessage: string | null
  startedAt: string | null
  completedAt: string | null
  createdAt: string
  updatedAt: string
}

export interface InvestigationClaimRead {
  id: string
  runId: string
  claimIndex: number
  claimType: InvestigationClaimType
  statement: string
  evidenceIds: string[]
  confidence: number
  uncertainty: number
  mitreTechniques: string[]
  verified: boolean
  rejectionReason: string | null
  createdAt: string
}

export type ToolExecutionState = 'completed' | 'rejected' | 'failed'

export interface ToolExecutionRead {
  id: string
  runId: string
  toolName: string
  toolVersion: string
  arguments: Record<string, unknown>
  resultSummary: string | null
  state: ToolExecutionState
  durationMs: number
  error: string | null
  createdAt: string
}

export interface FeedbackRead {
  id: string
  objectType: string
  objectId: string
  verdict: FeedbackVerdict
  label: string | null
  comment: string | null
  actor: string
  createdAt: string
}

export interface InvestigationsListResponse {
  items: InvestigationRunRecord[]
  total: number
  page: number
  pageSize: number
}

export interface InvestigationDetailResponse {
  run: InvestigationRunRecord
  claims: InvestigationClaimRead[]
  tools: ToolExecutionRead[]
  feedback: FeedbackRead[]
}

export interface InvestigationCreateRequest {
  alertId: string
  caseId?: string
  maxToolCalls?: number
  budgetUsd?: number
}

export interface FeedbackCreateRequest {
  objectType: string
  objectId: string
  verdict: FeedbackVerdict
  label?: string
  comment?: string
}

// ---- Phase 4: LLM gateway --------------------------------------------------
export type LlmCircuitState = 'open' | 'closed'

export interface LlmStatusBudget {
  day: string
  spentUsd: number
  dailyBudgetUsd: number
  runBudgetUsd: number
  remainingUsd: number
}

export interface LlmGatewayStatus {
  provider: string
  model: string
  available: boolean
  circuit: { state: LlmCircuitState; consecutiveFailures: number; resetInSeconds: number | null }
  concurrencyLimit: number
  timeoutSeconds: number
  maxAttempts: number
  budget: LlmStatusBudget
  stats: Record<string, number>
  pricingKnown: boolean
}

export interface LlmProbeResult {
  available: boolean
  models: string[]
  configuredModelExists: boolean
  error: string | null
}

// ---- Phase 5: rule governance ----------------------------------------------
export interface SandboxCapability {
  suricataAvailable: boolean
  binary: string | null
  executorVersion: string
  note: string | null
}

export interface RuleIRVersionRecord {
  id: string
  ruleId: string
  version: number
  sid: number | null
  rev: number | null
  irDigest: string
  irDocument: Record<string, unknown>
  suricataText: string | null
  state: string
  createdBy: string
  createdAt: string
}

export interface RuleSandboxMetrics {
  normalFlows: number
  maliciousFlows: number
  truePositives: number
  falsePositives: number
  falseNegatives: number
  recall: number
  precision: number
  f1: number
  falsePositiveRate: number
  falsePositivesPerMillion: number
  replaySeconds: number
  peakRssKb: number
  /** Per-metric measurement flag: a metric with measured=false is 未测量, never 0. */
  measured: Record<string, boolean>
}

export type RuleSandboxRunStatus =
  | 'blocked'
  | 'partial'
  | 'validated'
  | 'validation_failed'
  | 'failed'

export interface RuleSandboxCheck {
  label: string
  passed: boolean
  note: string
}

export interface RuleSandboxRunRecord {
  id: string
  ruleId: string
  ruleVersionId: string
  status: RuleSandboxRunStatus
  suricataAvailable: boolean
  suricataVersion: string | null
  syntaxPassed: boolean
  executorVersion: string
  normalPcap: string | null
  maliciousPcap: string | null
  metrics: RuleSandboxMetrics
  checks: RuleSandboxCheck[]
  passed: boolean
  blockedReason: string | null
  detail: string | null
  createdAt: string
}

export type RuleDeploymentState = 'canary' | 'deployed' | 'rolled_back'

export interface RuleDeploymentRecord {
  id: string
  ruleId: string
  ruleVersionId: string
  sensorGroupId: string
  state: RuleDeploymentState
  deployedBy: string
  deployedAt: string
  promotedAt: string | null
  rolledBackAt: string | null
  rollbackReason: string | null
  monitoring: Record<string, unknown>
  previousVersionId: string | null
  createdAt: string
}

export interface RuleDeploymentsResponse {
  items: RuleDeploymentRecord[]
}

export type SensorGroupStage = 'canary' | 'production'

export interface SensorGroupRecord {
  id: string
  name: string
  description: string | null
  sensorIds: string[]
  stage: SensorGroupStage
  createdAt: string
  updatedAt: string
}

export interface RuleDeploymentCreateRequest {
  ruleVersionId: string
  sensorGroupId: string
  state: 'canary' | 'deployed'
  note?: string
}
