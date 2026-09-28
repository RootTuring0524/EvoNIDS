import { z } from 'zod'

import { fetchBackend, usesMockApi } from '../../../utils/backend'

const bodySchema = z.object({ alertId: z.string().min(1).max(96) })

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '关联告警需要真实后端（mock 模式不可用）' })
  }
  const context = getRouterParam(event, 'id')
  if (!context) {
    throw createError({ statusCode: 400, statusMessage: '缺少案件 ID' })
  }
  const parsed = bodySchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: '缺少 alertId' })
  }
  return fetchBackend(event, `/cases/${encodeURIComponent(context)}/alerts`, {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
