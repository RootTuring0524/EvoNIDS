import { describe, expect, it } from 'vitest'

import {
  irCompileRequestSchema,
  ruleDeploymentCreateRequestSchema,
  ruleDeploymentRollbackRequestSchema,
  ruleDeploymentSchema,
  ruleDeploymentsResponseSchema,
  ruleIRVersionSchema,
  ruleSandboxMetricsSchema,
  ruleSandboxRunSchema,
  sandboxCapabilitySchema,
  sandboxRunRequestSchema,
  sensorGroupCreateRequestSchema,
  sensorGroupSchema,
} from '../../shared/schemas/security'
import { evidenceDetailPath, evidenceLinkTargets } from '../../app/utils/evidenceLinks'
import { formatSandboxMetric, UNMEASURED_SANDBOX_TEXT } from '../../app/utils/formatSandboxMetric'

const createdAt = '2026-09-10T09:00:00Z'

const sampleVersion = {
  id: 'IRV-0001',
  ruleId: 'EVO-2026-0716-14',
  version: 2,
  sid: 1000002,
  rev: 1,
  irDigest: 'sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  irDocument: { rule_id: 'EVO-2026-0716-14', conditions: [{ field: 'dst_port', operator: '==', value: 445 }] },
  suricataText: 'alert tcp any any -> any 445 (msg:"EvoNIDS lateral movement"; sid:1000002; rev:1;)',
  state: 'compiled',
  createdBy: 'analyst-l1',
  createdAt,
}

const sampleMetrics = {
  normalFlows: 1200,
  maliciousFlows: 300,
  truePositives: 295,
  falsePositives: 1,
  falseNegatives: 5,
  recall: 0.9833,
  precision: 0.9966,
  f1: 0.99,
  falsePositiveRate: 0.0008,
  falsePositivesPerMillion: 0,
  replaySeconds: 3.2,
  peakRssKb: 184320,
  measured: {
    normalFlows: true,
    maliciousFlows: true,
    truePositives: true,
    falsePositives: true,
    falseNegatives: true,
    recall: true,
    precision: true,
    f1: true,
    falsePositiveRate: true,
    falsePositivesPerMillion: false,
    replaySeconds: true,
    peakRssKb: true,
  },
}

const sampleRun = {
  id: 'SANDBOX-0001',
  ruleId: 'EVO-2026-0716-14',
  ruleVersionId: 'IRV-0001',
  status: 'validated',
  suricataAvailable: true,
  suricataVersion: '7.0.8',
  syntaxPassed: true,
  executorVersion: 'exec-v2',
  normalPcap: '/corpus/normal.pcap',
  maliciousPcap: '/corpus/malicious.pcap',
  metrics: sampleMetrics,
  checks: [
    { label: 'Suricata 语法检查', passed: true, note: 'syntax ok' },
    { label: '恶意流量命中', passed: true, note: '295/300' },
  ],
  passed: true,
  blockedReason: null,
  detail: null,
  createdAt,
}

const sampleDeployment = {
  id: 'DEP-0001',
  ruleId: 'EVO-2026-0716-14',
  ruleVersionId: 'IRV-0001',
  sensorGroupId: 'GRP-CANARY-01',
  state: 'canary',
  deployedBy: 'admin',
  deployedAt: createdAt,
  promotedAt: null,
  rolledBackAt: null,
  rollbackReason: null,
  monitoring: { since: createdAt },
  previousVersionId: null,
  createdAt,
}

const sampleGroup = {
  id: 'GRP-CANARY-01',
  name: '金丝雀组',
  description: '观察用',
  sensorIds: ['lab-core-01'],
  stage: 'canary',
  createdAt,
  updatedAt: createdAt,
}

describe('rule-governance read schemas', () => {
  it('parses a compiled IR version', () => {
    const parsed = ruleIRVersionSchema.parse(sampleVersion)
    expect(parsed.version).toBe(2)
    expect(parsed.sid).toBe(1000002)
    expect(parsed.suricataText).toContain('sid:1000002')
  })

  it('rejects a compiled version with missing digest', () => {
    expect(() => ruleIRVersionSchema.parse({ ...sampleVersion, irDigest: undefined })).toThrow()
  })

  it('parses sandbox metrics and keeps measured:false explicit (never a 0)', () => {
    const parsed = ruleSandboxMetricsSchema.parse(sampleMetrics)
    expect(parsed.measured.falsePositivesPerMillion).toBe(false)
    expect(parsed.falsePositivesPerMillion).toBe(0)
    expect(parsed.measured.recall).toBe(true)
  })

  it('parses a validated sandbox run and rejects unknown statuses', () => {
    const parsed = ruleSandboxRunSchema.parse(sampleRun)
    expect(parsed.status).toBe('validated')
    expect(parsed.passed).toBe(true)
    expect(() => ruleSandboxRunSchema.parse({ ...sampleRun, status: 'queued' })).toThrow()
  })

  it('parses a blocked sandbox run (no Suricata available)', () => {
    const blocked = ruleSandboxRunSchema.parse({
      ...sampleRun,
      status: 'blocked',
      suricataAvailable: false,
      suricataVersion: null,
      syntaxPassed: false,
      normalPcap: null,
      maliciousPcap: null,
      metrics: { ...sampleMetrics, measured: { ...sampleMetrics.measured, recall: false, precision: false, f1: false, falsePositiveRate: false } },
      passed: false,
      blockedReason: '本机未安装 Suricata：未执行真实验证',
      detail: null,
    })
    expect(blocked.status).toBe('blocked')
    expect(blocked.blockedReason).toContain('Suricata')
  })

  it('parses sandbox-capability including an honest unavailable state', () => {
    const cap = sandboxCapabilitySchema.parse({ suricataAvailable: false, binary: null, executorVersion: '', note: '演示模式' })
    expect(cap.suricataAvailable).toBe(false)
  })

  it('parses deployments, the deployments envelope and sensor groups', () => {
    const parsed = ruleDeploymentSchema.parse(sampleDeployment)
    expect(parsed.state).toBe('canary')
    const envelope = ruleDeploymentsResponseSchema.parse({ items: [sampleDeployment] })
    expect(envelope.items).toHaveLength(1)
    const group = sensorGroupSchema.parse(sampleGroup)
    expect(group.stage).toBe('canary')
    expect(() => ruleDeploymentSchema.parse({ ...sampleDeployment, state: 'paused' })).toThrow()
    expect(() => sensorGroupSchema.parse({ ...sampleGroup, stage: 'staging' })).toThrow()
  })
})

describe('rule-governance request schemas', () => {
  it('accepts an IR object with an optional sid and rejects non-object IR', () => {
    const compiled = irCompileRequestSchema.parse({ ir: { rule_id: 'EVO-2026-0716-14' }, sid: 1000003 })
    expect(compiled.sid).toBe(1000003)
    expect(irCompileRequestSchema.safeParse({ ir: { rule_id: 'EVO-2026-0716-14' } }).success).toBe(true)
    expect(() => irCompileRequestSchema.parse({ ir: 'not-an-object' })).toThrow()
    expect(() => irCompileRequestSchema.parse({ ir: { a: 1 }, sid: 0 })).toThrow()
  })

  it('accepts optional sandbox knobs and rejects out-of-range floors', () => {
    const request = sandboxRunRequestSchema.parse({ normalPcap: true, maliciousPcap: true, recallFloor: 0.9 })
    expect(request.recallFloor).toBe(0.9)
    expect(() => sandboxRunRequestSchema.parse({ recallFloor: 1.2 })).toThrow()
  })

  it('validates deployment create / rollback bodies', () => {
    const deploy = ruleDeploymentCreateRequestSchema.parse({
      ruleVersionId: 'IRV-0001', sensorGroupId: 'GRP-CANARY-01', state: 'canary',
    })
    expect(deploy.state).toBe('canary')
    expect(() => ruleDeploymentCreateRequestSchema.parse({ ruleVersionId: 'IRV-0001', sensorGroupId: 'GRP-CANARY-01', state: 'live' })).toThrow()
    const rollback = ruleDeploymentRollbackRequestSchema.parse({ reason: '金丝雀观察期出现误报' })
    expect(rollback.reason.length).toBeGreaterThanOrEqual(10)
    expect(() => ruleDeploymentRollbackRequestSchema.parse({ reason: '太短' })).toThrow()
  })

  it('validates sensor group creation', () => {
    const created = sensorGroupCreateRequestSchema.parse({ name: '生产组', stage: 'production', sensorIds: ['lab-core-02'] })
    expect(created.stage).toBe('production')
    expect(() => sensorGroupCreateRequestSchema.parse({ name: '', stage: 'production' })).toThrow()
  })
})

describe('sandbox metric rendering helper (measured:false → 未测量)', () => {
  it('renders measured:false as 未测量 even when the API payload carries 0', () => {
    const view = formatSandboxMetric(0, false)
    expect(view.measured).toBe(false)
    expect(view.text).toBe(UNMEASURED_SANDBOX_TEXT)
    expect(view.text).toBe('未测量')
    expect(view.text).not.toBe('0')
  })

  it('renders measured:false with a null value as 未测量', () => {
    const view = formatSandboxMetric(null, false)
    expect(view.measured).toBe(false)
    expect(view.text).toBe('未测量')
  })

  it('renders measured integer and fractional values verbatim', () => {
    const counters = formatSandboxMetric(295, true)
    expect(counters.measured).toBe(true)
    expect(counters.text).toBe('295')
    const ratio = formatSandboxMetric(0.9833, true)
    expect(ratio.text).toBe('0.9833')
  })

  it('renders a measured zero as 0 (only measured zeros show as zero)', () => {
    const view = formatSandboxMetric(0, true)
    expect(view.measured).toBe(true)
    expect(view.text).toBe('0')
  })

  it('never renders a value when the measured flag is missing', () => {
    const view = formatSandboxMetric(42, undefined)
    expect(view.measured).toBe(false)
    expect(view.text).toBe('未测量')
  })
})

describe('claim evidence link mapping', () => {
  it('maps every evidence id to an /evidence/<id> deep link', () => {
    const targets = evidenceLinkTargets(['EVID-0001', 'EVID-0002'])
    expect(targets).toHaveLength(2)
    expect(targets[0]).toEqual({ id: 'EVID-0001', to: '/evidence/EVID-0001' })
    expect(targets[1].to).toBe(evidenceDetailPath('EVID-0002'))
  })

  it('returns an empty list for an empty or blank-only evidence list', () => {
    expect(evidenceLinkTargets([])).toEqual([])
    expect(evidenceLinkTargets([''])).toEqual([])
  })
})
