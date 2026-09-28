import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    // Entities only exist in real mode (discovered from accepted events).
    return { items: [], total: 0, page: 1, pageSize: 25 }
  }
  return fetchBackend(event, '/entities', { query: getQuery(event) })
})
