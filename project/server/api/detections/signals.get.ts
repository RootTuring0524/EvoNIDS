import { z } from 'zod'

import { detectionChannelSchema, detectionSignalsResponseSchema, signalDecisionSchema } from '../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../utils/backend'

const signalsQuerySchema = z.object({
  flowId: z.string().trim().max(96).optional(),
  sensorId: z.string().trim().max(80).optional(),
  channel: detectionChannelSchema.optional(),
  decision: signalDecisionSchema.optional(),
  degraded: z.enum(['true', 'false']).transform((value) => value === 'true').optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(500).default(50),
})

export default defineEventHandler(async (event) => {
  const parsed = signalsQuerySchema.safeParse(getQuery(event))
  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: '筛选参数无效：channel/decision 取值不合法，pageSize 需在 1–500 之间',
    })
  }
  const { flowId, sensorId, channel, decision, degraded, page, pageSize } = parsed.data
  if (!usesMockApi(event)) {
    const query: Record<string, string | number> = { page, pageSize }
    if (flowId) query.flowId = flowId
    if (sensorId) query.sensorId = sensorId
    if (channel) query.channel = channel
    if (decision) query.decision = decision
    if (degraded !== undefined) query.degraded = String(degraded)
    const payload = await fetchBackend<unknown>(event, '/detections/signals', { query })
    return detectionSignalsResponseSchema.parse(payload)
  }
  // 演示模式不伪造检测信号：返回显式空数据。
  return { items: [], total: 0, page, pageSize }
})
