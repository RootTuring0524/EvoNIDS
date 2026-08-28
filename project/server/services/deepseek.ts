import { z } from 'zod'
import type { AgentAnalysis, AnomalyProfile, RagEvidence } from '../../shared/types/security'
import { RULE_CONDITION_FIELDS, agentAnalysisSchema, agentProposedRuleSchema, deepSeekChatCompletionSchema } from '../../shared/schemas/security'

interface DeepSeekServerConfig {
  apiBase: string
  apiKey: string
  model: string
}

export function parseDeepSeekAgentResponse(payload: unknown): AgentAnalysis {
  const envelope = deepSeekChatCompletionSchema.parse(payload)
  const content = envelope.choices[0]!.message.content
  const json = JSON.parse(extractJsonObject(content)) as unknown
  return agentAnalysisSchema.parse(json)
}

const deepSeekFindingSchema = z.object({
  hypothesis: z.string().trim().min(1).max(1200),
  patternDecision: z.enum(['new_pattern', 'rule_variant', 'known_match', 'benign']),
  summary: z.string().trim().min(1).max(1600),
  recommendation: z.string().trim().min(1).max(1600),
  evidenceIds: z.array(z.string().min(1)).min(1).max(8),
  proposedRule: agentProposedRuleSchema.optional(),
})

function extractJsonObject(content: string) {
  const trimmed = content.trim()
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim()
  const first = trimmed.indexOf('{')
  const last = trimmed.lastIndexOf('}')
  if (first < 0 || last <= first) throw new Error('Agent response does not contain a JSON object')
  return trimmed.slice(first, last + 1)
}

export function parseDeepSeekFindingResponse(payload: unknown) {
  const envelope = deepSeekChatCompletionSchema.parse(payload)
  const content = envelope.choices[0]!.message.content
  return deepSeekFindingSchema.parse(JSON.parse(extractJsonObject(content)) as unknown)
}

export function buildAgentRuleId(runId: string) {
  const suffix = runId.replace(/^AGENT-RUN-/, '').slice(-8)
  return `RUL-AG-${suffix || Date.now().toString(36).toUpperCase()}`
}

export function selectTrustedRagEvidence(evidence: RagEvidence[]) {
  return evidence
    .filter((item) => item.allowed && item.usedByAgent && item.promptInjectionRisk === 'none')
    .map(({ id, title, sourceType, sourceId, trust, excerpt, updatedAt, purpose, relevance }) => ({
      id, title, sourceType, sourceId, trust, excerpt, updatedAt, purpose, relevance,
    }))
}

export async function analyzeProfileWithDeepSeek(
  profile: AnomalyProfile,
  evidence: RagEvidence[],
  config: DeepSeekServerConfig,
) {
  if (!config.apiBase || !config.apiKey || !config.model) {
    throw createError({ statusCode: 503, statusMessage: 'DeepSeek server configuration is incomplete' })
  }

  const trustedEvidence = selectTrustedRagEvidence(evidence)

  if (trustedEvidence.length === 0) {
    throw createError({ statusCode: 422, statusMessage: 'No trusted RAG evidence is available for analysis' })
  }

  const started = performance.now()
  try {
    const payload = await $fetch(`${config.apiBase.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      timeout: 30_000,
      headers: { Authorization: `Bearer ${config.apiKey}` },
      body: {
        model: config.model,
        temperature: 0.1,
        max_tokens: 1600,
        messages: [
          {
            role: 'system',
            content: [
              'You are the EvoNIDS security rule-evolution agent displayed as DeepSeek V4 Pro.',
              'Use only the validated anomaly profile and trusted RAG evidence supplied by the server.',
              'Return only one JSON object with exactly these fields: hypothesis, patternDecision, summary, recommendation, evidenceIds, proposedRule.',
              'patternDecision must be one of new_pattern, rule_variant, known_match, benign.',
              'evidenceIds must be a non-empty subset of the supplied trusted evidence IDs.',
              'When patternDecision is new_pattern or rule_variant, proposedRule is REQUIRED; otherwise omit it.',
              'proposedRule must contain ruleName, description, attackType, severity, attackStage, mitreTechniqueIds, conditions, rationale.',
              'severity must be one of critical, high, medium, low, info.',
              'conditions must contain 1 to 6 objects with field, operator and value.',
              `field must be one of: ${Object.keys(RULE_CONDITION_FIELDS).join(', ')}.`,
              'operator must be one of >, >=, <, <=, ==, !=, in.',
              'Condition values must be grounded in the supplied anomaly profile flow statistics; never invent fields or fabricate thresholds without referencing the observed values.',
              'rationale must explain why these conditions separate the suspected attack from benign traffic and must cite the linked evidence.',
              'A proposed rule is only a candidate: it still requires replay validation and human approval before deployment.',
              'Do not include Markdown, hidden reasoning, run metadata or workflow steps.',
            ].join(' '),
          },
          {
            role: 'user',
            content: JSON.stringify({ profile, trustedEvidence }),
          },
        ],
      },
    })

    const finding = parseDeepSeekFindingResponse(payload)
    const trustedIds = new Set(trustedEvidence.map((item) => item.id))
    const analysisIds = new Set(finding.evidenceIds)
    if (
      analysisIds.size !== finding.evidenceIds.length
      || finding.evidenceIds.some((id) => !trustedIds.has(id))
    ) {
      throw new Error('Agent returned evidence outside the trusted context')
    }

    const durationMs = Math.max(1, Math.round(performance.now() - started))
    const analysis = agentAnalysisSchema.parse({
      displayModel: 'DeepSeek V4 Pro',
      runId: `AGENT-RUN-${Date.now().toString(36).toUpperCase()}`,
      state: 'completed',
      ...finding,
      steps: [
        {
          id: 'profile-validation',
          label: '校验异常画像',
          state: 'completed',
          tool: 'server_profile_validation',
          durationMs: 1,
          result: '客户端画像与服务端告警上下文一致',
        },
        {
          id: 'trusted-evidence',
          label: '筛选可信证据',
          state: 'completed',
          tool: 'trusted_rag_filter',
          durationMs: 1,
          result: `允许 ${trustedEvidence.length} 条证据进入模型上下文`,
        },
        {
          id: 'deepseek-analysis',
          label: '生成结构化研判',
          state: 'completed',
          tool: 'deepseek_chat_completions',
          durationMs,
          result: '响应已通过 JSON 契约与证据 ID 白名单校验',
        },
      ],
    })
    return { analysis, proposal: finding.proposedRule }
  } catch {
    // Upstream bodies, headers and credentials are deliberately not logged or reflected.
    throw createError({ statusCode: 502, statusMessage: 'DeepSeek upstream response failed validation' })
  }
}
