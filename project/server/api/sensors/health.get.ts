import { z } from 'zod'

import { sensorHealthResponseSchema } from '../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../utils/backend'

const healthQuerySchema = z.object({
  sensorId: z.string().trim().max(80).optional(),
  windowSeconds: z.coerce.number().int().min(60).max(604800).default(3600),
})

export default defineEventHandler(async (event) => {
  const parsed = healthQuerySchema.safeParse(getQuery(event))
  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: '窗口参数无效：windowSeconds 需在 60–604800 秒之间',
    })
  }
  const { sensorId, windowSeconds } = parsed.data
  if (!usesMockApi(event)) {
    const payload = await fetchBackend<unknown>(event, '/sensors/health', {
      query: { ...(sensorId ? { sensorId } : {}), windowSeconds },
    })
    return sensorHealthResponseSchema.parse(payload)
  }
  // 演示模式绝不伪造质量台账：返回显式空数据，页面按「未测量/暂无数据」渲染。
  return { items: [] }
})
