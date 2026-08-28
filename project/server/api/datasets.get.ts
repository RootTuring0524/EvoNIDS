import { datasets } from '../utils/domain-data'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler((event) => {
  if (!usesMockApi(event)) return fetchBackend(event, '/datasets')
  return { items: datasets }
})
