import { trainingRunCreateSchema } from '~~/shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({
      statusCode: 409,
      statusMessage: 'Real training is disabled while NUXT_PUBLIC_USE_MOCK_API=true',
    })
  }
  const payload = await readValidatedBody(event, (body) => trainingRunCreateSchema.parse(body))
  return fetchBackend(event, '/training/runs', { method: 'POST', body: payload, admin: true })
})
