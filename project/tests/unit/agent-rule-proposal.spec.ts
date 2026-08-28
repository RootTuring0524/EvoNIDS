import { describe, expect, it } from 'vitest'
import {
  agentAnalysisResponseSchema,
  agentProposedRuleSchema,
  ruleDetailSchema,
} from '../../shared/schemas/security'
import { buildAgentRuleId, parseDeepSeekFindingResponse } from '../../server/services/deepseek'
import { getAlertDetail } from '../../server/utils/domain-data'

const validProposal = {
  ruleName: 'SSH Credential Spraying Window',
  description: 'Flags source hosts attempting SSH sessions across many destinations within a 60 second window.',
  attackType: 'Brute Force',
  severity: 'high',
  attackStage: 'Credential Access',
  mitreTechniqueIds: ['T1110'],
  conditions: [
    { field: 'dst_port', operator: '==', value: 22 },
    { field: 'destination_ip_count_60s', operator: '>=', value: 40 },
    { field: 'flow_duration', operator: '<', value: 3.5 },
  ],
  rationale: 'Multi-destination SSH attempts inside one window match the credential spraying pattern cited by the linked evidence.',
} as const

function chatEnvelope(content: unknown) {
  return { choices: [{ message: { content: JSON.stringify(content) } }] }
}

const baseFinding = {
  hypothesis: 'The source host is spraying SSH credentials across the routed segment.',
  patternDecision: 'new_pattern',
  summary: 'Windowed destination counts and short flows align with credential spraying.',
  recommendation: 'Create a candidate rule and replay it against labeled flows before approval.',
  evidenceIds: ['EV-KNOWLEDGE-01'],
}

describe('agent rule proposals', () => {
  it('accepts a grounded proposal and rejects fields outside the feature schema', () => {
    expect(() => agentProposedRuleSchema.parse(validProposal)).not.toThrow()

    expect(() =>
      agentProposedRuleSchema.parse({
        ...validProposal,
        conditions: [{ field: 'attacker_reputation', operator: '>', value: 0.5 }],
      }),
    ).toThrow(/feature schema/)

    expect(() =>
      agentProposedRuleSchema.parse({
        ...validProposal,
        mitreTechniqueIds: ['NOT-MITRE'],
      }),
    ).toThrow()
  })

  it('enforces value typing per field kind', () => {
    expect(() =>
      agentProposedRuleSchema.parse({
        ...validProposal,
        conditions: [{ field: 'dst_port', operator: '==', value: 'ssh' }],
      }),
    ).toThrow(/numeric value/)

    expect(() =>
      agentProposedRuleSchema.parse({
        ...validProposal,
        conditions: [{ field: 'protocol', operator: '==', value: ['tcp'] }],
      }),
    ).toThrow(/only operator in accepts a list/)

    expect(() =>
      agentProposedRuleSchema.parse({
        ...validProposal,
        conditions: [{ field: 'protocol', operator: 'in', value: [] }],
      }),
    ).toThrow(/non-empty string list/)

    expect(() =>
      agentProposedRuleSchema.parse({
        ...validProposal,
        conditions: [{ field: 'protocol', operator: 'in', value: ['tcp', 'udp'] }],
      }),
    ).not.toThrow()
  })

  it('parses a DeepSeek finding that carries a proposal and rejects malformed proposals', () => {
    const parsed = parseDeepSeekFindingResponse(chatEnvelope({ ...baseFinding, proposedRule: validProposal }))
    expect(parsed.proposedRule?.conditions).toHaveLength(3)
    expect(parsed.proposedRule?.severity).toBe('high')

    expect(() =>
      parseDeepSeekFindingResponse(
        chatEnvelope({
          ...baseFinding,
          proposedRule: { ...validProposal, conditions: [{ field: 'raw_payload', operator: 'contains', value: 'x' }] },
        }),
      ),
    ).toThrow()
  })

  it('keeps the analysis response contract optional-proposal safe', () => {
    const detail = getAlertDetail('ALT-78428')
    const withoutProposal = agentAnalysisResponseSchema.parse(detail.agent)
    expect(withoutProposal.proposedRule).toBeUndefined()

    const structured = {
      rule_id: 'RUL-AG-TEST0001',
      rule_name: validProposal.ruleName,
      description: validProposal.description,
      attack_type: validProposal.attackType,
      severity: validProposal.severity,
      attack_stage: validProposal.attackStage,
      mitre_technique_ids: [...validProposal.mitreTechniqueIds],
      conditions: validProposal.conditions.map((condition) => ({ ...condition })),
      evidence_ids: baseFinding.evidenceIds,
      generated_by: 'DeepSeek V4 Pro',
      version: 1,
      parent_rule_id: null,
    }
    const withProposal = agentAnalysisResponseSchema.parse({
      ...detail.agent,
      proposedRule: { structured, sourceAlertId: 'ALT-78428', rationale: validProposal.rationale },
    })
    expect(withProposal.proposedRule?.structured.rule_id).toBe('RUL-AG-TEST0001')
    expect(ruleDetailSchema.safeParse).toBeTypeOf('function')
  })

  it('derives deterministic agent rule ids from run ids', () => {
    expect(buildAgentRuleId('AGENT-RUN-M1AB2C3')).toBe('RUL-AG-M1AB2C3')
    expect(buildAgentRuleId('AGENT-RUN-LONGRUNID99')).toBe('RUL-AG-GRUNID99')
    expect(buildAgentRuleId('AGENT-RUN-M1AB2C3')).toBe(buildAgentRuleId('AGENT-RUN-M1AB2C3'))
    expect(buildAgentRuleId('AGENT-RUN-M1AB2C3')).not.toBe(buildAgentRuleId('AGENT-RUN-M1AB2C4'))
  })
})
