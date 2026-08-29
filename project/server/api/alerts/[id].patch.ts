import { z } from 'zod'
import { getAlertDetail, setAlertOverride } from '../../utils/domain-data'
import { fetchBackend, usesMockApi } from '../../utils/backend'

const bodySchema = z.object({
  status: z.enum(['new', 'investigating', 'contained', 'closed']).optional(),
  owner: z.string().trim().max(120).nullable().optional(),
  note: z.string().trim().max(500).optional(),
  actor: z.string().trim().min(1).max(120).optional(),
})

export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id') || ''
  const parsed = bodySchema.safeParse((await readBody(event)) || {})
  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: parsed.error.issues[0]?.message || 'Invalid alert update',
    })
  }
  if (!usesMockApi(event)) {
    return fetchBackend(event, `/alerts/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: parsed.data,
      admin: true,
    })
  }
  const detail = structuredClone(getAlertDetail(id))
  if (parsed.data.owner !== undefined) detail.alert.owner = parsed.data.owner
  if (parsed.data.status) detail.alert.status = parsed.data.status
  if (parsed.data.owner && detail.alert.status === 'new') detail.alert.status = 'investigating'
  setAlertOverride(id, { owner: detail.alert.owner, status: detail.alert.status })
  return detail
})
