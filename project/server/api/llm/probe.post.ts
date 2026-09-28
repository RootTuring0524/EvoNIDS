import { fetchBackend, usesMockApi } from '../../utils/backend'

// POST /api/llm/probe — run a real model probe on the LLM gateway (admin-only
// upstream). The probe never runs in mock mode: the BFF reports that no probe
// was executed instead of inventing a result.
export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    return fetchBackend(event, '/llm/probe', { method: 'POST', admin: true })
  }
  return {
    available: false,
    models: [],
    configuredModelExists: false,
    error: '演示模式：未连接真实后端，未执行模型探测。',
  }
})
