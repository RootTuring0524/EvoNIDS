import { z } from 'zod'
import {
  agentAnalysisResponseSchema,
  agentAnalysisSchema,
  alertDetailSchema,
  anomalyProfileSchema,
  structuredRuleSchema,
} from '../../../shared/schemas/security'
import type { AgentProposedRule } from '../../../shared/schemas/security'
import type { AgentAnalysis } from '../../../shared/types/security'
import { getAlertDetail } from '../../utils/domain-data'
import { analyzeProfileWithDeepSeek, buildAgentRuleId } from '../../services/deepseek'
import { fetchBackend, usesMockApi } from '../../utils/backend'

const requestSchema = z.object({
  alertId: z.string().min(1),
  profile: anomalyProfileSchema,
})

function attachRuleProposal(analysis: AgentAnalysis, proposal: AgentProposedRule, alertId: string) {
  const structured = structuredRuleSchema.parse({
    rule_id: buildAgentRuleId(analysis.runId),
    rule_name: proposal.ruleName,
    description: proposal.description,
    attack_type: proposal.attackType,
    severity: proposal.severity,
    attack_stage: proposal.attackStage,
    mitre_technique_ids: proposal.mitreTechniqueIds,
    conditions: proposal.conditions,
    evidence_ids: analysis.evidenceIds,
    generated_by: analysis.displayModel,
    version: 1,
    parent_rule_id: null,
  })
  return {
    ...analysis,
    steps: [
      ...analysis.steps,
      {
        id: 'rule-proposal',
        label: '生成候选规则提案',
        state: 'completed',
        tool: 'submit_candidate',
        durationMs: 1,
        result: `已生成结构化候选 ${structured.rule_id}，等待回放验证与人工确认`,
      },
    ],
    proposedRule: {
      structured,
      sourceAlertId: alertId,
      rationale: proposal.rationale || analysis.summary,
    },
  }
}

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig(event)
  const parsed = requestSchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: 'Invalid Agent analysis request' })
  }

  let detail
  if (usesMockApi(event)) {
    try {
      detail = getAlertDetail(parsed.data.alertId)
    } catch {
      throw createError({ statusCode: 404, statusMessage: 'Alert context not found' })
    }
  } else {
    const payload = await fetchBackend(
      event,
      `/alerts/${encodeURIComponent(parsed.data.alertId)}`,
    )
    detail = alertDetailSchema.parse(payload)
  }

  const canonicalProfile = anomalyProfileSchema.parse(detail.profile)
  if (JSON.stringify(canonicalProfile) !== JSON.stringify(parsed.data.profile)) {
    throw createError({ statusCode: 409, statusMessage: 'Alert and anomaly profile do not match' })
  }

  if (usesMockApi(event)) {
    return agentAnalysisResponseSchema.parse(detail.agent)
  }

  const { analysis, proposal } = await analyzeProfileWithDeepSeek(canonicalProfile, detail.rag, config.deepseek)
  const withProposal = proposal
    ? attachRuleProposal(analysis, proposal, parsed.data.alertId)
    : analysis
  const validated = agentAnalysisResponseSchema.parse(withProposal)

  // Persist only the analysis contract; rule proposals stay in the response until an analyst saves them.
  await fetchBackend(event, `/alerts/${encodeURIComponent(parsed.data.alertId)}/agent-runs`, {
    method: 'POST',
    body: agentAnalysisSchema.parse(validated),
    admin: true,
  })
  return validated
})
