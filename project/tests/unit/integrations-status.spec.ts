import { describe, expect, it } from 'vitest'
import { agentAnalysisSchema, integrationsStatusSchema } from '../../shared/schemas/security'
import { resolveDisplayModel } from '../../server/services/deepseek'
import { getAlertDetail } from '../../server/utils/domain-data'

const configuredStatus = {
  displayName: 'DeepSeek V4 Pro',
  useMockApi: false,
  configured: true,
  apiBaseState: 'configured',
  modelIdState: 'configured',
  apiKeyState: 'configured',
  deepseek: {
    configured: true,
    model: 'deepseek-chat',
    baseUrlHost: 'api.deepseek.example',
    displayModel: 'DeepSeek · deepseek-chat',
  },
} as const

describe('resolveDisplayModel', () => {
  it('derives the display model from the configured model id', () => {
    expect(resolveDisplayModel({ model: 'deepseek-chat' })).toBe('DeepSeek · deepseek-chat')
    expect(resolveDisplayModel({ model: 'deepseek-reasoner' })).toBe('DeepSeek · deepseek-reasoner')
  })

  it('falls back to the default product name when no model is configured', () => {
    expect(resolveDisplayModel({ model: '' })).toBe('DeepSeek V4 Pro')
  })
})

describe('agentAnalysisSchema displayModel', () => {
  it('still accepts the locked mock label and a full mock agent payload', () => {
    expect(agentAnalysisSchema.parse(getAlertDetail('ALT-78431').agent).displayModel).toBe('DeepSeek V4 Pro')
  })

  it('accepts config-derived display names and rejects empty or overlong ones', () => {
    expect(agentAnalysisSchema.shape.displayModel.parse('DeepSeek · deepseek-chat')).toBe('DeepSeek · deepseek-chat')
    expect(agentAnalysisSchema.shape.displayModel.parse('  DeepSeek · deepseek-chat  ')).toBe('DeepSeek · deepseek-chat')
    expect(agentAnalysisSchema.shape.displayModel.safeParse('').success).toBe(false)
    expect(agentAnalysisSchema.shape.displayModel.safeParse('x'.repeat(81)).success).toBe(false)
  })
})

describe('integrationsStatusSchema', () => {
  it('parses the extended payload and keeps the legacy integration fields', () => {
    const parsed = integrationsStatusSchema.parse(configuredStatus)
    expect(parsed.displayName).toBe('DeepSeek V4 Pro')
    expect(parsed.configured).toBe(true)
    expect(parsed.apiBaseState).toBe('configured')
    expect(parsed.deepseek.model).toBe('deepseek-chat')
    expect(parsed.deepseek.baseUrlHost).toBe('api.deepseek.example')
    expect(parsed.deepseek.displayModel).toBe('DeepSeek · deepseek-chat')
  })

  it('parses the unconfigured payload with empty model and host', () => {
    const parsed = integrationsStatusSchema.parse({
      ...configuredStatus,
      configured: false,
      apiBaseState: 'missing',
      modelIdState: 'missing',
      apiKeyState: 'missing',
      deepseek: { configured: false, model: '', baseUrlHost: '', displayModel: 'DeepSeek V4 Pro' },
    })
    expect(parsed.deepseek.configured).toBe(false)
    expect(parsed.deepseek.model).toBe('')
    expect(parsed.deepseek.baseUrlHost).toBe('')
    expect(parsed.deepseek.displayModel).toBe('DeepSeek V4 Pro')
  })

  it('rejects a missing deepseek block or an empty display model', () => {
    const { deepseek: _omitted, ...withoutDeepseek } = configuredStatus
    expect(integrationsStatusSchema.safeParse(withoutDeepseek).success).toBe(false)
    expect(
      integrationsStatusSchema.safeParse({ ...configuredStatus, deepseek: { ...configuredStatus.deepseek, displayModel: '' } }).success,
    ).toBe(false)
  })
})
