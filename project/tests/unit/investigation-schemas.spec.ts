import { describe, expect, it } from 'vitest'

import {
  feedbackCreateRequestSchema,
  feedbackReadSchema,
  investigationClaimSchema,
  investigationCreateRequestSchema,
  investigationDetailResponseSchema,
  investigationRunSchema,
  investigationsListResponseSchema,
  llmProbeResultSchema,
  llmStatusSchema,
  toolExecutionSchema,
} from '../../shared/schemas/security'

const createdAt = '2026-09-10T08:00:00Z'

const sampleRun = {
  id: 'INV-RUN-0001',
  alertId: 'ALT-78435',
  caseId: 'CASE-00A1B2C3D4E5',
  requestedBy: 'analyst-l1',
  state: 'succeeded',
  mode: 'auto',
  provider: 'deepseek',
  modelId: 'deepseek-chat-v4',
  promptTemplateVersion: 'prompt-v3',
  toolRegistryVersion: 'tools-2026.09',
  knowledgeVersion: 'kb-2026.09',
  maxToolCalls: 5,
  budgetUsd: 0.5,
  inputEvidenceIds: ['EVID-0001', 'EVID-0002'],
  retrieval: { mode: 'hybrid', topK: 4, vectorCandidates: 120, reranked: { provided: 4 } },
  summary: '该主机行为符合横向移动的早期特征。',
  uncertainty: 0.12,
  promptTokens: 1832,
  completionTokens: 420,
  costEstimateUsd: 0.0081,
  latencyMs: 6400,
  attempts: 1,
  degradedReasons: [],
  errorMessage: null,
  startedAt: createdAt,
  completedAt: createdAt,
  createdAt,
  updatedAt: createdAt,
}

const sampleClaim = {
  id: 'CLAIM-0001',
  runId: 'INV-RUN-0001',
  claimIndex: 0,
  claimType: 'observation',
  statement: '源 IP 尝试访问内网多个 445 端口。',
  evidenceIds: ['EVID-0001'],
  confidence: 0.9,
  uncertainty: 0.1,
  mitreTechniques: ['T1021'],
  verified: true,
  rejectionReason: null,
  createdAt,
}

const sampleTool = {
  id: 'TOOL-0001',
  runId: 'INV-RUN-0001',
  toolName: 'evidence_lookup',
  toolVersion: '1.2.0',
  arguments: { evidenceId: 'EVID-0001' },
  resultSummary: '找到 1 条匹配事件。',
  state: 'completed',
  durationMs: 82,
  error: null,
  createdAt,
}

const sampleFeedback = {
  id: 'FB-0001',
  objectType: 'investigation_run',
  objectId: 'INV-RUN-0001',
  verdict: 'agree',
  label: '高置信',
  comment: '结论与流量回放一致。',
  actor: 'analyst-l1',
  createdAt,
}

describe('investigation run & claim schemas', () => {
  it('parses a succeeded investigation run with a retrieval snapshot', () => {
    const parsed = investigationRunSchema.parse(sampleRun)
    expect(parsed.state).toBe('succeeded')
    expect(parsed.retrieval.mode).toBe('hybrid')
    expect(parsed.degradedReasons).toEqual([])
    expect(parsed.budgetUsd).toBe(0.5)
  })

  it('parses degraded and insufficient_evidence states as distinct values', () => {
    const degraded = investigationRunSchema.parse({ ...sampleRun, state: 'degraded', degradedReasons: ['provider_rate_limited'] })
    expect(degraded.state).toBe('degraded')
    const insufficient = investigationRunSchema.parse({ ...sampleRun, state: 'insufficient_evidence' })
    expect(insufficient.state).toBe('insufficient_evidence')
  })

  it('rejects an unknown run state and an out-of-range tool-call budget', () => {
    expect(() => investigationRunSchema.parse({ ...sampleRun, state: 'thinking' })).toThrow()
    expect(() => investigationRunSchema.parse({ ...sampleRun, maxToolCalls: 9 })).toThrow()
  })

  it('parses a claim with evidence citations and a rejected claim with reason', () => {
    const claim = investigationClaimSchema.parse(sampleClaim)
    expect(claim.evidenceIds).toContain('EVID-0001')
    expect(claim.verified).toBe(true)
    const rejected = investigationClaimSchema.parse({
      ...sampleClaim,
      claimType: 'rejected',
      rejectionReason: '证据链断裂：命中流与告警流不一致',
    })
    expect(rejected.claimType).toBe('rejected')
    expect(rejected.rejectionReason).toContain('证据链断裂')
  })

  it('rejects claims with an unknown claim type', () => {
    expect(() => investigationClaimSchema.parse({ ...sampleClaim, claimType: 'guess' })).toThrow()
  })

  it('parses the run detail envelope with claims, tools and feedback', () => {
    const detail = investigationDetailResponseSchema.parse({
      run: sampleRun,
      claims: [sampleClaim],
      tools: [sampleTool],
      feedback: [sampleFeedback],
    })
    expect(detail.run.id).toBe('INV-RUN-0001')
    expect(detail.claims).toHaveLength(1)
    expect(detail.tools[0].state).toBe('completed')
    expect(detail.feedback[0].verdict).toBe('agree')
  })

  it('rejects an envelope with a malformed tool record', () => {
    expect(() => investigationDetailResponseSchema.parse({
      run: sampleRun, claims: [], tools: [{ ...sampleTool, state: 'queued' }], feedback: [],
    })).toThrow()
  })

  it('parses the paginated list envelope', () => {
    const list = investigationsListResponseSchema.parse({ items: [sampleRun], total: 1, page: 1, pageSize: 25 })
    expect(list.items[0].id).toBe('INV-RUN-0001')
  })

  it('parses and validates the create request and feedback request', () => {
    const create = investigationCreateRequestSchema.parse({ alertId: 'ALT-78435', maxToolCalls: 4, budgetUsd: 0.25 })
    expect(create.maxToolCalls).toBe(4)
    expect(investigationCreateRequestSchema.safeParse({ alertId: 'ALT-78435' }).success).toBe(true)
    // Reject invalid tool-call bounds.
    expect(() => investigationCreateRequestSchema.parse({ alertId: 'ALT-78435', maxToolCalls: 0 })).toThrow()
    expect(() => investigationCreateRequestSchema.parse({ alertId: 'ALT-78435', budgetUsd: -1 })).toThrow()
  })

  it('accepts the run-level feedback request shape and parses the created record', () => {
    const request = feedbackCreateRequestSchema.parse({
      objectType: 'investigation_run',
      objectId: 'INV-RUN-0001',
      verdict: 'disagree',
      label: '证据不足',
      comment: '结论与告警上下文不一致。',
    })
    expect(request.verdict).toBe('disagree')
    const read = feedbackReadSchema.parse(sampleFeedback)
    expect(read.objectId).toBe('INV-RUN-0001')
    expect(() => feedbackCreateRequestSchema.parse({ objectId: 'INV-RUN-0001', verdict: 'maybe' })).toThrow()
  })

  it('parses tool execution read records', () => {
    const tool = toolExecutionSchema.parse(sampleTool)
    expect(tool.durationMs).toBe(82)
    expect(() => toolExecutionSchema.parse({ ...sampleTool, state: 'expired' })).toThrow()
  })
})

describe('LLM gateway schemas', () => {
  const sampleStatus = {
    provider: 'deepseek',
    model: 'deepseek-chat-v4',
    available: true,
    circuit: { state: 'closed', consecutiveFailures: 0, resetInSeconds: null },
    concurrencyLimit: 4,
    timeoutSeconds: 60,
    maxAttempts: 2,
    budget: { day: '2026-09-10', spentUsd: 0.42, dailyBudgetUsd: 5, runBudgetUsd: 0.5, remainingUsd: 4.58 },
    stats: { requests: 12, completions: 12, failures: 0 },
    pricingKnown: true,
  }

  it('parses a healthy gateway status and an open-circuit status', () => {
    const parsed = llmStatusSchema.parse(sampleStatus)
    expect(parsed.circuit.state).toBe('closed')
    expect(parsed.pricingKnown).toBe(true)
    const open = llmStatusSchema.parse({
      ...sampleStatus,
      available: false,
      circuit: { state: 'open', consecutiveFailures: 5, resetInSeconds: 45 },
    })
    expect(open.circuit.state).toBe('open')
    expect(open.circuit.resetInSeconds).toBe(45)
  })

  it('rejects an unknown circuit state', () => {
    expect(() => llmStatusSchema.parse({ ...sampleStatus, circuit: { state: 'half', consecutiveFailures: 0, resetInSeconds: null } })).toThrow()
  })

  it('parses a probe result and keeps the backend error verbatim', () => {
    const ok = llmProbeResultSchema.parse({ available: true, models: ['deepseek-chat-v4'], configuredModelExists: true, error: null })
    expect(ok.models).toContain('deepseek-chat-v4')
    const down = llmProbeResultSchema.parse({ available: false, models: [], configuredModelExists: false, error: '上游 401' })
    expect(down.error).toBe('上游 401')
  })
})
