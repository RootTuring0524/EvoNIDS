import { repairRule } from '../../../utils/rule-state'
import { fetchBackend, usesMockApi } from '../../../utils/backend'
import { z } from 'zod'

const bodySchema = z.object({ actor: z.string().trim().min(1).max(80).optional(), reason: z.string().trim().min(10).max(500) })

export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id') || ''
  const parsed = bodySchema.safeParse((await readBody(event)) || {})
  if (!parsed.success) throw createError({ statusCode: 400, statusMessage: parsed.error.issues[0]?.message || 'Invalid repair request' })
  if (!usesMockApi(event)) {
    return fetchBackend(event, `/rules/${encodeURIComponent(id)}/repair`, {
      method: 'POST',
      body: parsed.data,
      admin: true,
    })
  }
  return repairRule(id, parsed.data)
})
