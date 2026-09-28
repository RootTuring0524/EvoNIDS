import { z } from 'zod'

import { fetchBackend, usesMockApi } from '../../utils/backend'

const bodySchema = z.object({
  summary: z.string().max(4000).optional(),
  assignee: z.string().max(120).nullable().optional(),
  status: z.enum(['open', 'investigating', 'contained', 'closed', 'archived']).optional(),
  note: z.string().max(2000).optional(),
})

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '更新案件需要真实后端（mock 模式不可用）' })
  }
  const context = getRouterParam(event, 'id')
  if (!context) {
    throw createError({ statusCode: 400, statusMessage: '缺少案件 ID' })
  }
  const parsed = bodySchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: '更新参数不合法' })
  }
  return fetchBackend(event, `/cases/${encodeURIComponent(context)}`, {
    method: 'PATCH',
    body: parsed.data,
    admin: true,
  })
})
