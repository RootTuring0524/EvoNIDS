import { z } from 'zod'
import { structuredRuleSchema } from '../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../utils/backend'

const candidateSchema = z.object({
  structured: structuredRuleSchema,
  sourceAlertId: z.string().optional(),
  rationale: z.string().max(2000).optional(),
  author: z.string().trim().min(1).max(120).optional(),
  source: z.enum(['agent', 'analyst']).optional(),
})

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({
      statusCode: 409,
      statusMessage: 'Persistent candidate creation requires the real backend',
    })
  }
  const parsed = candidateSchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: parsed.error.issues[0]?.message || 'Invalid candidate rule',
    })
  }
  return fetchBackend(event, '/rules', { method: 'POST', body: parsed.data, admin: true })
})
