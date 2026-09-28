import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    return { items: [], total: 0, page: 1, pageSize: 25 }
  }
  return fetchBackend(event, '/evidence', { query: getQuery(event) })
})
