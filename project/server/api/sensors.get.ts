import { sensorsResponseSchema } from '../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../utils/backend'
import { sensorRegistry } from '../utils/mock-data'

export default defineEventHandler(async (event) => {
  const query = getQuery(event)
  if (!usesMockApi(event)) {
    const payload = await fetchBackend<unknown>(event, '/sensors', { query })
    return sensorsResponseSchema.parse(payload)
  }
  const search = typeof query.search === 'string' ? query.search.toLowerCase() : ''
  const state = typeof query.state === 'string' ? query.state : 'all'
  return {
    ...sensorRegistry,
    items: sensorRegistry.items.filter((item) =>
      (state === 'all' || item.state === state) &&
      (!search || `${item.id} ${item.name} ${item.location ?? ''}`.toLowerCase().includes(search)),
    ),
  }
})
