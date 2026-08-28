import { datasetRegistrationSchema } from '../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: 'Mock mode cannot register real datasets' })
  }
  const parsed = datasetRegistrationSchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Invalid dataset registration',
      data: { issues: parsed.error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })) },
    })
  }
  return fetchBackend(event, '/datasets', {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
