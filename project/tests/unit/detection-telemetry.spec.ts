import { describe, expect, it } from 'vitest'

import {
  detectionFlowDetailSchema,
  detectionSignalSchema,
  detectionSignalsResponseSchema,
  detectionStatusSchema,
  ingestionBatchesResponseSchema,
  ingestionBatchSchema,
  riskAssessmentSchema,
  sensorDataQualitySchema,
  sensorHealthResponseSchema,
  sensorMetricSchema,
  sensorSchema,
} from '../../shared/schemas/security'
import { UNMEASURED_TEXT, formatSensorMetric, sensorMetricUnitLabel } from '../../app/utils/formatSensorMetric'

const measuredMetric = { value: 0.042, measured: true, unit: 'ratio', note: null }
const unmeasuredMetric = { value: null, measured: false, unit: 'ms', note: '窗口内没有可用于计算的批次' }

const sampleQuality = {
  sensorId: 'lab-core-01',
  state: 'online',
  healthReason: '心跳正常',
  windowSeconds: 3600,
  batches: 3,
  eventsAccepted: 148_000,
  eventsRejected: 12,
  eventsDuplicate: 200,
  rejectRate: measuredMetric,
  duplicateRate: { value: 0.00135, measured: true, unit: 'ratio', note: null },
  ingestLatencyP50Ms: { value: 12.4, measured: true, unit: 'ms', note: null },
  ingestLatencyP95Ms: unmeasuredMetric,
  clockSkewSeconds: { value: 0.42, measured: true, unit: 'seconds', note: '正值表示探针时钟快于服务端' },
  gapCount: { value: 1, measured: true, unit: 'gaps', note: null },
  estimatedMissingSeconds: { value: null, measured: false, unit: 'seconds', note: '窗口内无事件时间可用于估算' },
  spoolDepth: 0,
  droppedEvents: 0,
  expectedIntervalSeconds: 60,
  lastBatchAt: '2026-09-09T08:00:00Z',
  lastEventAt: '2026-09-09T07:59:59Z',
  lastHeartbeatAt: '2026-09-09T08:00:00Z',
}

const sampleBatch = {
  id: 'BAT-0001',
  sensorId: 'lab-core-01',
  batchId: 'eve-2026-09-09T07:59:00Z',
  receivedAt: '2026-09-09T08:00:01Z',
  contentSha256: 'a'.repeat(64),
  encoding: 'ndjson',
  payloadBytes: 4096,
  eventCount: 100,
  acceptedCount: 92,
  duplicateCount: 5,
  rejectedCount: 3,
  createdFlows: 92,
  createdAlerts: 1,
  firstEventAt: '2026-09-09T07:59:00Z',
  lastEventAt: '2026-09-09T07:59:59Z',
  clockSkewSeconds: 0.1,
  status: 'partial',
}

const sampleSignal = {
  id: 'SIG-ABC123',
  createdAt: '2026-09-09T08:00:01Z',
  flowId: 'FLOW-0001',
  alertId: null,
  sensorId: 'lab-core-01',
  channel: 'baseline',
  channelVersion: 'hgb 2026.09',
  modelId: 'mdl-base-1',
  rawScore: 0.91,
  calibratedScore: 0.84,
  threshold: 0.7,
  decision: 'alert',
  uncertainty: 0.08,
  featureVersion: 'flow-v1',
  featureSource: 'online',
  imputedFeatures: ['forward_bytes', 'syn_ratio'],
  latencyMs: 12.3,
  degraded: false,
  degradedReason: null,
  detail: {
    missingFields: ['tcp_options'],
    windowSeconds: 60,
    contextFeatures: { bytes_out: 2048 },
    prediction: 'DoS',
    topK: [{ label: 'DoS', probability: 0.84 }],
    calibration: 'artifact',
  },
}

const sampleAssessment = {
  id: 'RISK-ABC123',
  createdAt: '2026-09-09T08:00:01Z',
  flowId: 'FLOW-0001',
  alertId: null,
  sensorId: 'lab-core-01',
  signalIds: ['SIG-ABC123'],
  inputs: [
    {
      signalId: 'SIG-ABC123',
      channel: 'baseline',
      channelVersion: 'hgb 2026.09',
      modelId: 'mdl-base-1',
      rawScore: 0.91,
      calibratedScore: 0.84,
      decision: 'alert',
      imputedFeatures: ['forward_bytes'],
      degradedReason: null,
    },
    {
      signalId: null,
      channel: 'suricata',
      channelVersion: 'deployed_rules',
      modelId: null,
      rawScore: 0.9,
      calibratedScore: 0.9,
      decision: 'alert',
      imputedFeatures: [],
      degradedReason: null,
    },
  ],
  weights: { baseline: 0.8, autoencoder: 0.2 },
  finalScore: 87.2,
  uncertainty: 0.12,
  decision: 'suspicious',
  explanation: '双通道证据一致，结合规则风险给出可疑结论。',
  degradedReasons: [],
  mode: 'shadow',
}

describe('sensor health & data-quality schemas', () => {
  it('parses a measured SensorMetric', () => {
    const parsed = sensorMetricSchema.parse(measuredMetric)
    expect(parsed.value).toBe(0.042)
    expect(parsed.measured).toBe(true)
  })

  it('keeps measured:false with a null value (never a fabricated zero)', () => {
    const parsed = sensorMetricSchema.parse(unmeasuredMetric)
    expect(parsed.measured).toBe(false)
    expect(parsed.value).toBeNull()
  })

  it('rejects a metric whose measured flag is missing or non-boolean', () => {
    expect(() => sensorMetricSchema.parse({ value: 1, unit: 'ms', note: null })).toThrow()
    expect(() => sensorMetricSchema.parse({ ...unmeasuredMetric, measured: 'yes' })).toThrow()
  })

  it('parses a full sensor data-quality payload', () => {
    const quality = sensorDataQualitySchema.parse(sampleQuality)
    expect(quality.sensorId).toBe('lab-core-01')
    expect(quality.ingestLatencyP95Ms.measured).toBe(false)
    expect(quality.estimatedMissingSeconds.value).toBeNull()
  })

  it('parses the health response envelope and rejects malformed counters', () => {
    const response = sensorHealthResponseSchema.parse({ items: [sampleQuality] })
    expect(response.items).toHaveLength(1)
    expect(() => sensorHealthResponseSchema.parse({ items: [{ ...sampleQuality, eventsAccepted: 'many' }] })).toThrow()
  })
})

describe('ingestion batch ledger schemas', () => {
  it('parses a partial batch record', () => {
    const parsed = ingestionBatchSchema.parse(sampleBatch)
    expect(parsed.status).toBe('partial')
    expect(parsed.clockSkewSeconds).toBe(0.1)
  })

  it('parses a paginated batches response', () => {
    const response = ingestionBatchesResponseSchema.parse({ items: [sampleBatch], total: 1, page: 1, pageSize: 25 })
    expect(response.total).toBe(1)
  })

  it('rejects an unknown batch status and a missing batch id', () => {
    expect(() => ingestionBatchSchema.parse({ ...sampleBatch, status: 'quarantined' })).toThrow()
    expect(() => ingestionBatchSchema.parse({ ...sampleBatch, id: undefined })).toThrow()
  })
})

describe('detection status & signal schemas', () => {
  it('parses detection status in shadow mode with channel contract state', () => {
    const parsed = detectionStatusSchema.parse({
      mode: 'shadow',
      featureVersion: 'flow-v1',
      channels: {
        baseline: { available: true, modelId: 'mdl-base-1', version: '2026.09', contractMatches: true, reason: null },
        autoencoder: { available: false, modelId: null, version: null, contractMatches: false, reason: 'artifact_unavailable' },
      },
      alerting: false,
      notes: ['影子模式下仅评分与留存证据'],
    })
    expect(parsed.mode).toBe('shadow')
    expect(parsed.alerting).toBe(false)
    expect(parsed.channels.baseline.contractMatches).toBe(true)
  })

  it('rejects an unknown detection mode', () => {
    expect(() => detectionStatusSchema.parse({
      mode: 'aggressive', featureVersion: '', channels: {}, alerting: true, notes: [],
    })).toThrow()
  })

  it('parses a baseline detection signal with channel detail', () => {
    const parsed = detectionSignalSchema.parse(sampleSignal)
    expect(parsed.detail.prediction).toBe('DoS')
    expect(parsed.detail.topK?.[0].label).toBe('DoS')
    expect(parsed.imputedFeatures).toContain('syn_ratio')
  })

  it('rejects an invalid signal decision and missing flow fields', () => {
    expect(() => detectionSignalSchema.parse({ ...sampleSignal, decision: 'ban' })).toThrow()
    expect(() => detectionSignalSchema.parse({ ...sampleSignal, id: undefined })).toThrow()
  })

  it('parses a paginated signals response', () => {
    const response = detectionSignalsResponseSchema.parse({ items: [sampleSignal], total: 1, page: 1, pageSize: 50 })
    expect(response.items[0].channel).toBe('baseline')
  })
})

describe('risk assessment & flow detail schemas', () => {
  it('parses a shadow-mode risk assessment with rule input', () => {
    const parsed = riskAssessmentSchema.parse(sampleAssessment)
    expect(parsed.mode).toBe('shadow')
    expect(parsed.weights.baseline).toBe(0.8)
    expect(parsed.inputs[1].channel).toBe('suricata')
    expect(parsed.inputs[1].signalId).toBeNull()
  })

  it('parses a flow detail response containing signals and assessments', () => {
    const parsed = detectionFlowDetailSchema.parse({
      flowId: 'FLOW-0001',
      signals: [sampleSignal],
      assessments: [sampleAssessment],
    })
    expect(parsed.flowId).toBe('FLOW-0001')
    expect(parsed.assessments[0].decision).toBe('suspicious')
  })

  it('rejects an invalid assessment decision', () => {
    expect(() => riskAssessmentSchema.parse({ ...sampleAssessment, decision: 'maybe' })).toThrow()
  })
})

describe('extended sensor registry schema', () => {
  const baseSensor = {
    id: 'lab-core-01', name: '核心网实验探针', location: null, version: 'Suricata 7.0.8',
    state: 'online', healthReason: '正常', lastSeenAt: '2026-09-09T08:00:00Z',
    flowCount: 100, alertCount: 2, criticalAlerts: 0, acceptedEvents: 10_000, rejectedEvents: 0,
    ingestSource: 'eve-stream', lastError: null, createdAt: '2026-09-09T00:00:00Z', updatedAt: '2026-09-09T08:00:00Z',
  }

  it('accepts the new online-telemetry fields', () => {
    const parsed = sensorSchema.parse({
      ...baseSensor,
      agentVersion: 'evonids-agent-1.2.0',
      lastHeartbeatAt: '2026-09-09T07:59:00Z',
      clockSkewSeconds: 0.2,
      spoolDepth: 12,
      droppedEvents: 3,
      expectedIntervalSeconds: 60,
      capabilities: ['eve-stream', 'batch-ledger'],
    })
    expect(parsed.agentVersion).toBe('evonids-agent-1.2.0')
    expect(parsed.spoolDepth).toBe(12)
  })

  it('rejects malformed telemetry (negative spool depth)', () => {
    expect(() => sensorSchema.parse({ ...baseSensor, spoolDepth: -1 })).toThrow()
  })
})

describe('SensorMetric rendering helper (measured:false → 未测量)', () => {
  it('renders a measured:false metric as 未测量, never as 0', () => {
    const view = formatSensorMetric(unmeasuredMetric)
    expect(view.measured).toBe(false)
    expect(view.text).toBe('未测量')
    expect(view.text).toBe(UNMEASURED_TEXT)
    expect(view.text).not.toBe('0')
  })

  it('renders a measured ratio converted to a percentage with % unit', () => {
    const view = formatSensorMetric({ value: 0.25, measured: true, unit: 'ratio', note: null })
    expect(view.measured).toBe(true)
    expect(view.text).toBe('25')
    expect(view.unit).toBe('%')
  })

  it('renders measured latency and counters verbatim with localised units', () => {
    expect(formatSensorMetric({ value: 12.3456, measured: true, unit: 'ms', note: null }).text).toBe('12.35')
    expect(sensorMetricUnitLabel('ms')).toBe('毫秒')
    expect(formatSensorMetric({ value: 3, measured: true, unit: 'gaps', note: null }).text).toBe('3')
    expect(sensorMetricUnitLabel('gaps')).toBe('次')
  })

  it('keeps the backend note for tooltips and falls back to the raw unit', () => {
    const view = formatSensorMetric(unmeasuredMetric)
    expect(view.note).toBe('窗口内没有可用于计算的批次')
    expect(sensorMetricUnitLabel('weird-unit')).toBe('weird-unit')
  })
})
