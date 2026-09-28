import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    return { items: [] }
  }
  return fetchBackend(event, '/cases/suggestions', { query: getQuery(event) })
})
