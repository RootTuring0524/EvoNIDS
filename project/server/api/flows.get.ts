import { flows } from '../utils/mock-data'
import { flowsResponseSchema } from '../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    const payload = await fetchBackend<unknown>(event, '/flows', { query: getQuery(event) })
    return flowsResponseSchema.parse(payload)
  }
  return { items: flows, total: 1482902 }
})
