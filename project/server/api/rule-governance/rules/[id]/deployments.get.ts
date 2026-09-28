import { fetchBackend, usesMockApi } from '../../../../utils/backend'

// GET /api/rule-governance/rules/:id/deployments — deployment history for one
// rule. Mock mode returns an empty envelope.
export default defineEventHandler(async (event) => {
  const ruleId = getRouterParam(event, 'id') || ''
  if (!ruleId) throw createError({ statusCode: 400, statusMessage: '缺少规则 ID' })
  if (!usesMockApi(event)) {
    return fetchBackend(event, `/rule-governance/rules/${encodeURIComponent(ruleId)}/deployments`)
  }
  return { items: [] }
})
