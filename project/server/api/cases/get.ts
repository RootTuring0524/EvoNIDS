import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    // Cases only exist in real mode; the mock console reports an honest empty state.
    return { items: [], total: 0, page: 1, pageSize: 25 }
  }
  return fetchBackend(event, '/cases', { query: getQuery(event) })
})
