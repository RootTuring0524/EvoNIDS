export default defineEventHandler((event) => {
  const config = useRuntimeConfig(event)
  let apiBaseState: 'configured' | 'missing' | 'invalid' = 'missing'
  if (config.deepseek.apiBase) {
    try {
      new URL(config.deepseek.apiBase)
      apiBaseState = 'configured'
    } catch {
      apiBaseState = 'invalid'
    }
  }
  return {
    displayName: 'DeepSeek V4 Pro',
    useMockApi: config.public.useMockApi,
    configured: Boolean(apiBaseState === 'configured' && config.deepseek.apiKey && config.deepseek.model),
    apiBaseState,
    modelIdState: config.deepseek.model ? 'configured' : 'missing',
    apiKeyState: config.deepseek.apiKey ? 'configured' : 'missing',
  }
})
