import { sandboxRunRequestSchema } from '../../../../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../../../../utils/backend'

// POST /api/rule-governance/rules/:id/versions/:versionId/sandbox — request a
// real Suricata sandbox validation run for a compiled version.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '沙箱验证需要真实后端（mock 模式不可用）' })
  }
  const ruleId = getRouterParam(event, 'id') || ''
  const versionId = getRouterParam(event, 'versionId') || ''
  if (!ruleId) throw createError({ statusCode: 400, statusMessage: '缺少规则 ID' })
  if (!versionId) throw createError({ statusCode: 400, statusMessage: '缺少规则版本 ID' })
  const body = await readBody(event).catch(() => undefined)
  const parsed = sandboxRunRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `沙箱请求参数无效：${parsed.error.issues[0]?.message ?? '请检查后重试'}` })
  }
  return fetchBackend(
    event,
    `/rule-governance/rules/${encodeURIComponent(ruleId)}/versions/${encodeURIComponent(versionId)}/sandbox`,
    { method: 'POST', body: parsed.data, admin: true },
  )
})
