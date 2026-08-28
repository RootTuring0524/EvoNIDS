import { models } from '../utils/mock-data'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) return fetchBackend(event, '/models')
  return { items: models }
})
