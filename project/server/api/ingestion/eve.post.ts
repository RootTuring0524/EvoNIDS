import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({
      statusCode: 409,
      statusMessage: 'EVE ingestion is only available when the real backend is enabled',
    })
  }
  const body = await readRawBody(event, 'utf8')
  if (!body?.trim()) {
    throw createError({ statusCode: 400, statusMessage: 'An EVE NDJSON payload is required' })
  }
  const config = useRuntimeConfig(event)
  return fetchBackend(event, '/ingestion/eve', {
    method: 'POST',
    query: { sensorId: getQuery(event).sensorId || 'lab-core-01' },
    body,
    headers: config.backend.sensorToken ? { 'x-evonids-sensor-token': config.backend.sensorToken } : {},
  })
})
