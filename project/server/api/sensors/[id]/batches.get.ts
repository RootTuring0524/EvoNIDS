import { z } from 'zod'

import { ingestionBatchesResponseSchema } from '../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../utils/backend'

const batchesQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(500).default(50),
})

export default defineEventHandler(async (event) => {
  const sensorId = getRouterParam(event, 'id') || ''
  if (!sensorId || sensorId.length > 80) {
    throw createError({ statusCode: 400, statusMessage: '探针 ID 无效' })
  }
  const parsed = batchesQuerySchema.safeParse(getQuery(event))
  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: '分页参数无效：page 至少为 1，pageSize 需在 1–500 之间',
    })
  }
  const { page, pageSize } = parsed.data
  if (!usesMockApi(event)) {
    // 真实后端对未知探针返回 404，这里原样透传，绝不把 404 变成空列表。
    const payload = await fetchBackend<unknown>(event, `/sensors/${encodeURIComponent(sensorId)}/batches`, {
      query: { page, pageSize },
    })
    return ingestionBatchesResponseSchema.parse(payload)
  }
  // 演示模式不伪造批次台账：返回显式空数据。
  return { items: [], total: 0, page, pageSize }
})
