import { fetchBackend, usesMockApi } from '../../utils/backend'

// GET /api/llm/status — LLM gateway status. The backend reports it admin-only
// (401 otherwise), so the BFF attaches the server-side admin token. In mock
// mode no real status exists: the BFF returns an explicit zeroed payload and
// the settings page overlays a demo notice instead of treating it as real data.
export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    return fetchBackend(event, '/llm/status', { admin: true })
  }
  return {
    provider: '',
    model: '',
    available: false,
    circuit: { state: 'closed', consecutiveFailures: 0, resetInSeconds: null },
    concurrencyLimit: 0,
    timeoutSeconds: 0,
    maxAttempts: 0,
    budget: { day: '', spentUsd: 0, dailyBudgetUsd: 0, runBudgetUsd: 0, remainingUsd: 0 },
    stats: {},
    pricingKnown: false,
  }
})
