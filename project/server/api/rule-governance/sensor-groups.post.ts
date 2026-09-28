import { sensorGroupCreateRequestSchema } from '../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../utils/backend'

// POST /api/rule-governance/sensor-groups — create a sensor group.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '创建传感器组需要真实后端（mock 模式不可用）' })
  }
  const body = await readBody(event).catch(() => undefined)
  const parsed = sensorGroupCreateRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `传感器组参数无效：${parsed.error.issues[0]?.message ?? '请检查后重试'}` })
  }
  return fetchBackend(event, '/rule-governance/sensor-groups', {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
