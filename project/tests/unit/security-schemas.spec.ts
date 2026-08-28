import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import AgentStep from '../../app/components/AgentStep.vue'
import {
  agentAnalysisSchema,
  alertDetailSchema,
  datasetsResponseSchema,
  detectionCategorySchema,
  flowsResponseSchema,
  modelsResponseSchema,
  overviewMetricsSchema,
  readinessResponseSchema,
  ragResponseSchema,
  ruleDetailSchema,
  sensorsResponseSchema,
  trainingMetricsSchema,
  trainingRunsResponseSchema,
} from '../../shared/schemas/security'
import { parseDeepSeekAgentResponse, selectTrustedRagEvidence } from '../../server/services/deepseek'
import {
  alertDetails,
  candidateRule,
  datasets,
  getAlertDetail,
  ragEvidence,
  ruleDetails,
} from '../../server/utils/domain-data'
import { alerts, flows, models, rules, sensorRegistry } from '../../server/utils/mock-data'
import { DETECTION_CATEGORIES, type AgentStepRecord } from '../../shared/types/security'

describe('EvoNIDS domain payloads', () => {
  it('keeps every listed alert detail internally consistent', () => {
    expect(Object.keys(alertDetails).sort()).toEqual(alerts.map((item) => item.id).sort())

    for (const alert of alerts) {
      const detail = alertDetailSchema.parse(alertDetails[alert.id])
      expect(detail.alert.id).toBe(alert.id)
      expect(detail.profile.transformer_prediction).toBe(detail.transformer.prediction)
      expect(detail.profile.transformer_confidence).toBe(detail.transformer.confidence)
      expect(detail.profile.autoencoder_reconstruction_error).toBe(detail.autoEncoder.reconstructionError)
      expect(detail.profile.autoencoder_anomaly_score).toBe(detail.autoEncoder.anomalyScore)
      expect(detail.profile.final_risk_score).toBe(detail.fusion.finalScore)

      const actualEvidence = detail.rag.filter((item) => item.allowed && item.usedByAgent).map((item) => item.id)
      expect(actualEvidence).toHaveLength(4)
      expect(detail.agent.evidenceIds).toEqual(actualEvidence)
      expect(new Set(actualEvidence).size).toBe(actualEvidence.length)
      expect(detail.rag.filter((item) => actualEvidence.includes(item.id)).every((item) => item.promptInjectionRisk === 'none')).toBe(true)
    }
  })

  it('validates the dual-channel port scan scenario and evidence lineage', () => {
    const detail = alertDetailSchema.parse(alertDetails['ALT-78435'])
    expect(detail.transformer.isKnownClass).toBe(false)
    expect(detail.autoEncoder.exceedsThreshold).toBe(true)
    expect(detail.fusion.lean).toBe('unknown_anomaly')
    expect(detail.profile.destination_port_count_60s).toBe(76)
    expect(detail.agent.patternDecision).toBe('rule_variant')
    expect(candidateRule.evidence_ids).toEqual(detail.agent.evidenceIds)
    expect(detail.rag.some((item) => item.sourceType === 'Snort / Suricata')).toBe(true)
    expect(detail.rag.some((item) => item.sourceType === 'CVE / CWE / CAPEC')).toBe(true)
    expect(detail.rag.some((item) => item.sourceType === '已验证规则')).toBe(true)
    expect(detail.rag.find((item) => item.id === 'EVIDENCE-131')?.usedByAgent).toBe(false)
    expect(detail.rag.find((item) => item.id === 'EVIDENCE-147')?.usedByAgent).toBe(true)
    expect(selectTrustedRagEvidence(detail.rag).map((item) => item.id)).toEqual(detail.agent.evidenceIds)
  })

  it('uses scenario-specific DDoS, C2 and SSH evidence and model outputs', () => {
    const ddos = alertDetailSchema.parse(alertDetails['ALT-78436'])
    expect(ddos.agent.patternDecision).toBe('known_match')
    expect(ddos.agent.summary).toContain('1,842')
    expect(ddos.rag.some((item) => item.sourceId === 'SIG-DDOS-4401' && item.usedByAgent)).toBe(true)

    const c2 = alertDetailSchema.parse(alertDetails['ALT-78431'])
    expect(c2.rag.some((item) => item.title.includes('TLS 周期心跳 C2') && item.usedByAgent)).toBe(true)
    expect(c2.rag.filter((item) => item.usedByAgent).some((item) => item.title.includes('端口探测'))).toBe(false)
    expect(c2.agent.summary).toContain('ALT-70318')

    const ssh = alertDetailSchema.parse(alertDetails['ALT-78428'])
    expect(ssh.profile.dst_port).toBe(22)
    expect(ssh.profile.autoencoder_reconstruction_error).toBe(0.72)
    expect(ssh.autoEncoder.reconstructionError).toBe(0.72)
    expect(ssh.transformer.abnormalFeatures.some((item) => item.field === 'authentication_failures_5m')).toBe(true)
  })

  it('uses only the locked detection taxonomy and includes complete DoS and Web Attack scenarios', () => {
    for (const alert of alerts) expect(detectionCategorySchema.parse(alert.category)).toBe(alert.category)
    expect(DETECTION_CATEGORIES).toEqual([
      'DoS', 'DDoS', 'Port Scan', 'Brute Force', 'Botnet', 'C2 Communication', 'Web Attack', 'Infiltration',
      'Abnormal Outbound Connection', 'Unknown Anomaly',
    ])
    expect(new Set(alerts.map((alert) => alert.category))).toEqual(new Set(DETECTION_CATEGORIES))

    const dos = alertDetailSchema.parse(alertDetails['ALT-78388'])
    expect(dos.alert.category).toBe('DoS')
    expect(dos.transformer.prediction).toBe('DoS')
    expect(dos.fusion.lean).toBe('dual_confirmed')
    expect(dos.agent.patternDecision).toBe('known_match')

    const web = alertDetailSchema.parse(alertDetails['ALT-78381'])
    expect(web.alert.category).toBe('Web Attack')
    expect(web.transformer.prediction).toBe('Web Attack')
    expect(web.rag.some((item) => item.sourceId === 'ATTACK-T1190' && item.usedByAgent)).toBe(true)

    const botnet = alertDetailSchema.parse(alertDetails['ALT-78376'])
    expect(botnet.alert.category).toBe('Botnet')
    expect(botnet.transformer.prediction).toBe('Botnet')
    expect(botnet.rag.some((item) => item.sourceId === 'RULE-BOTNET-0011' && item.usedByAgent)).toBe(true)
  })

  it('rejects unknown alert IDs instead of returning an unrelated scenario', () => {
    expect(() => getAlertDetail('ALT-NOT-FOUND')).toThrow('Unknown alert')
  })

  it('contains reproducible normal HTTP, HTTPS, download, DNS and database traffic', () => {
    const parsed = flowsResponseSchema.parse({ items: flows, total: flows.length })
    expect(parsed.items.some((item) => item.protocol === 'HTTP' && item.verdict === 'benign')).toBe(true)
    expect(parsed.items.some((item) => item.protocol === 'HTTPS' && item.verdict === 'benign')).toBe(true)
    expect(parsed.items.some((item) => item.activity.includes('下载') && item.verdict === 'benign')).toBe(true)
    expect(parsed.items.some((item) => item.service === 'DNS' && item.verdict === 'benign')).toBe(true)
    expect(parsed.items.some((item) => item.service === 'PostgreSQL' && item.verdict === 'benign')).toBe(true)
  })

  it('validates the configured dataset route', () => {
    const payload = datasetsResponseSchema.parse({ items: datasets })
    expect(payload.items.map((item) => item.name)).toEqual(['CICIDS2017', 'NF-CSE-CIC-IDS2018', 'UNSW-NB15'])
  })

  it('registers exactly the two detection models and the downstream DeepSeek Agent role', () => {
    const payload = modelsResponseSchema.parse({ items: models })
    expect(payload.items.map((item) => item.name)).toEqual(['Flow Transformer', 'Flow AutoEncoder', 'DeepSeek V4 Pro'])
    expect(payload.items.some((item) => item.name === 'Traffic Encoder' || item.name === 'Security RAG')).toBe(false)
    expect(payload.items.at(-1)?.role).toContain('Agent')
  })

  it('keeps queued training runs metric-free until the backend produces measurements', () => {
    const now = new Date().toISOString()
    const payload = trainingRunsResponseSchema.parse({
      items: [{
        id: 'TR-TEST-001',
        datasetId: 'DS-CIC-2017',
        datasetName: 'CICIDS2017',
        modelId: null,
        task: 'known_attack_classification_baseline',
        algorithm: 'hist_gradient_boosting',
        state: 'queued',
        requestedBy: 'test-operator',
        datasetSha256: 'a'.repeat(64),
        featureVersion: 'flow-v1',
        config: { randomSeed: 42, maxRows: 250000 },
        samplesSeen: 0,
        samplesUsed: 0,
        startedAt: null,
        completedAt: null,
        metrics: null,
        artifactState: 'missing',
        artifactSha256: null,
        errorMessage: null,
        createdAt: now,
        updatedAt: now,
      }],
    })

    expect(payload.items[0]?.state).toBe('queued')
    expect(payload.items[0]?.metrics).toBeNull()
    expect(payload.items[0]?.artifactState).toBe('missing')
  })

  it('rejects a training confusion matrix that does not align with its labels', () => {
    const invalid = trainingMetricsSchema.safeParse({
      accuracy: 0.9, macroPrecision: 0.9, macroRecall: 0.9, macroF1: 0.9, weightedF1: 0.9,
      validationMacroF1: 0.88, trainSamples: 70, validationSamples: 15, testSamples: 15,
      droppedTargetRows: 0, featureCount: 2, labels: ['BENIGN', 'DDoS'],
      classMetrics: [
        { label: 'BENIGN', support: 8, precision: 1, recall: 0.8, f1: 0.89 },
        { label: 'DDoS', support: 7, precision: 0.8, recall: 1, f1: 0.89 },
      ],
      confusionMatrix: [[8]], numericFeatures: ['duration', 'packets'], droppedFeatures: ['Flow ID'],
      trainSeconds: 1.2, testPredictMs: 3.5, throughputFps: 4200,
    })
    expect(invalid.success).toBe(false)
  })

  it('validates sensor health and overview metrics without invented production counts', () => {
    const sensors = sensorsResponseSchema.parse(sensorRegistry)
    expect(sensors.summary.total).toBe(sensors.items.length)
    expect(sensors.items.some((item) => item.state === 'degraded' && item.lastError)).toBe(true)
    expect(sensors.items.some((item) => item.state === 'maintenance')).toBe(true)

    const overview = overviewMetricsSchema.parse({
      pendingAlerts: alerts.filter((item) => ['new', 'investigating'].includes(item.status)).length,
      highRiskAlerts: alerts.filter((item) => ['critical', 'high'].includes(item.severity) && item.status !== 'closed').length,
      unassignedAlerts: alerts.filter((item) => ['new', 'investigating'].includes(item.status) && !item.owner).length,
      flows: flows.length,
      anomalousFlows: flows.filter((item) => item.verdict !== 'benign').length,
      candidateRules: rules.filter((item) => item.stage !== 'deployed').length,
      deployedRules: rules.filter((item) => item.stage === 'deployed').length,
      sensors: sensors.summary,
    })
    expect(overview.pendingAlerts).toBeGreaterThan(0)
    expect(overview.sensors.offline).toBe(1)

    const readiness = readinessResponseSchema.parse({
      status: 'attention', environment: 'mock', checkedAt: new Date().toISOString(), blockers: 0, warnings: 1,
      checks: [{ id: 'runtime-mode', label: '运行环境', status: 'warn', detail: 'Mock 模式不代表生产就绪' }],
    })
    expect(readiness.checks[0]?.status).toBe('warn')
  })

  it('validates the fixed RAG sample with counts derived from the returned evidence', () => {
    const retrieval = {
      vectorCandidates: ragEvidence.filter((item) => item.vectorScore >= 0.7).length,
      keywordSupplementCandidates: ragEvidence.filter((item) => item.vectorScore < 0.7 && item.keywordScore >= 0.5).length,
      filteredCandidates: ragEvidence.filter((item) => !item.allowed).length,
      rerankedCandidates: ragEvidence.filter((item) => item.allowed).length,
      providedToAgent: ragEvidence.filter((item) => item.allowed && item.usedByAgent).length,
    }
    const payload = ragResponseSchema.parse({
      query: '低置信度 Unknown + 60 秒多端口 SYN 探测 + 短连接', topK: 10, mode: 'fixed_mock_sample', retrieval, items: ragEvidence,
    })
    expect(payload.retrieval.vectorCandidates + payload.retrieval.keywordSupplementCandidates - payload.retrieval.filteredCandidates)
      .toBe(payload.retrieval.rerankedCandidates)
    expect(payload.retrieval.providedToAgent).toBe(4)
  })

  it('validates the structured rule, replay metrics and four evidence IDs', () => {
    const detail = ruleDetailSchema.parse(ruleDetails['EVO-2026-0716-14'])
    expect(detail.structured.generated_by).toBe('DeepSeek V4 Pro')
    expect(detail.validation.qualityScore).toBeGreaterThanOrEqual(90)
    expect(detail.previousVersion).not.toBeNull()
    expect(detail.structured.evidence_ids).toHaveLength(4)
    expect(detail.validation.schemaChecks.at(-1)?.note).toContain('4 条实际采用证据')
  })

  it('validates both the DeepSeek envelope and its JSON AgentAnalysis content', () => {
    const expected = agentAnalysisSchema.parse(alertDetails['ALT-78431']!.agent)
    const parsed = parseDeepSeekAgentResponse({ choices: [{ message: { content: JSON.stringify(expected) } }] })
    expect(parsed).toEqual(expected)
    expect(() => parseDeepSeekAgentResponse({ choices: [] })).toThrow()
    expect(() => parseDeepSeekAgentResponse({ choices: [{ message: { content: '{"displayModel":"wrong"}' } }] })).toThrow()
  })
})

describe('AgentStep', () => {
  const base: AgentStepRecord = { id: 'S1', label: '检索证据', state: 'completed', tool: 'hybrid_rag_search', durationMs: 186, result: '完成' }

  for (const state of ['completed', 'active', 'pending', 'failed'] as const) {
    it(`renders the ${state} state independently`, () => {
      const wrapper = mount(AgentStep, { props: { step: { ...base, state }, index: 0 } })
      expect(wrapper.get('[data-state]').attributes('data-state')).toBe(state)
      expect(wrapper.text()).toContain(({ completed: '已完成', active: '执行中', pending: '等待中', failed: '失败' })[state])
    })
  }

  it('updates the same node from active to completed', async () => {
    const wrapper = mount(AgentStep, { props: { step: { ...base, state: 'active' }, index: 0 } })
    expect(wrapper.get('[data-state]').attributes('data-state')).toBe('active')
    await wrapper.setProps({ step: { ...base, state: 'completed' } })
    expect(wrapper.get('[data-state]').attributes('data-state')).toBe('completed')
    expect(wrapper.text()).toContain('已完成')
  })
})
