import { getAlertDetail } from '../../utils/domain-data'
import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id') || ''
  if (!usesMockApi(event)) return fetchBackend(event, `/alerts/${encodeURIComponent(id)}`)
  try {
    return getAlertDetail(id)
  } catch {
    throw createError({ statusCode: 404, statusMessage: 'Alert detail not found' })
  }
})
