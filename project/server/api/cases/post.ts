import { z } from 'zod'

import { fetchBackend, usesMockApi } from '../../utils/backend'

const bodySchema = z.object({
  title: z.string().min(3).max(255),
  summary: z.string().max(4000).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
})

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '创建案件需要真实后端（mock 模式不可用）' })
  }
  const parsed = bodySchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: '案件参数不合法' })
  }
  return fetchBackend(event, '/cases', { method: 'POST', body: parsed.data, admin: true })
})
