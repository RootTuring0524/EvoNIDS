import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler((event) => {
  if (usesMockApi(event)) return { items: [] }
  return fetchBackend(event, '/training/runs')
})
