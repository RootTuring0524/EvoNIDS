import { getRuleDetail } from '../../utils/rule-state'
import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id') || ''
  if (!usesMockApi(event)) return fetchBackend(event, `/rules/${encodeURIComponent(id)}`)
  return getRuleDetail(id)
})
