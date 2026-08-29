import { integrationsStatusSchema } from '../../../shared/schemas/security'
import { resolveDisplayModel } from '../../services/deepseek'

export default defineEventHandler((event) => {
  const config = useRuntimeConfig(event)
  let apiBaseState: 'configured' | 'missing' | 'invalid' = 'missing'
  let baseUrlHost = ''
  if (config.deepseek.apiBase) {
    try {
      // Only the host is reflected to the browser; path, query and credentials never leave the server.
      baseUrlHost = new URL(config.deepseek.apiBase).host
      apiBaseState = 'configured'
    } catch {
      apiBaseState = 'invalid'
    }
  }
  const configured = Boolean(apiBaseState === 'configured' && config.deepseek.apiKey && config.deepseek.model)
  return integrationsStatusSchema.parse({
    displayName: 'DeepSeek V4 Pro',
    useMockApi: config.public.useMockApi,
    configured,
    apiBaseState,
    modelIdState: config.deepseek.model ? 'configured' : 'missing',
    apiKeyState: config.deepseek.apiKey ? 'configured' : 'missing',
    deepseek: {
      configured,
      model: config.deepseek.model,
      baseUrlHost,
      displayModel: resolveDisplayModel(config.deepseek),
    },
  })
})
