import { fetchBackend, usesMockApi } from '../../utils/backend'

// GET /api/investigations — forward the paginated list of AI investigation
// runs for one alert. Mock mode never fabricates runs: it returns an empty
// envelope and the client shows a demo notice instead.
export default defineEventHandler(async (event) => {
  const raw = getQuery(event)
  const query: Record<string, string> = {}
  for (const key of ['alertId', 'state', 'page', 'pageSize'] as const) {
    const value = raw[key]
    if (typeof value === 'string' && value) query[key] = value
  }
  if (!usesMockApi(event)) return fetchBackend(event, '/investigations', { query })
  return { items: [], total: 0, page: 1, pageSize: 25 }
})
