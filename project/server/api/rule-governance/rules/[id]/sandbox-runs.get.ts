import { fetchBackend, usesMockApi } from '../../../../utils/backend'

// GET /api/rule-governance/rules/:id/sandbox-runs — sandbox validation history
// for one rule. Mock mode returns an empty list (runs only exist in the backend).
export default defineEventHandler(async (event) => {
  const ruleId = getRouterParam(event, 'id') || ''
  if (!ruleId) throw createError({ statusCode: 400, statusMessage: '缺少规则 ID' })
  const raw = getQuery(event)
  const query: Record<string, string> = {}
  if (typeof raw.limit === 'string' && raw.limit) query.limit = raw.limit
  if (!usesMockApi(event)) {
    return fetchBackend(event, `/rule-governance/rules/${encodeURIComponent(ruleId)}/sandbox-runs`, { query })
  }
  return []
})
