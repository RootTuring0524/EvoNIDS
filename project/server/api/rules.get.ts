import { listRules } from '../utils/rule-state'
import { rulesResponseSchema } from '../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    const payload = await fetchBackend<unknown>(event, '/rules', { query: getQuery(event) })
    return rulesResponseSchema.parse(payload)
  }
  const items = listRules()
  return { items, total: items.length }
})
