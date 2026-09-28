import { irCompileRequestSchema } from '../../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../../utils/backend'

// POST /api/rule-governance/rules/:id/versions — compile an IR document into a
// rule version (Suricata text generation). Invalid IR is rejected by the
// backend with a 422 envelope whose detail is forwarded to the console.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '编译规则 IR 需要真实后端（mock 模式不可用）' })
  }
  const ruleId = getRouterParam(event, 'id') || ''
  if (!ruleId) throw createError({ statusCode: 400, statusMessage: '缺少规则 ID' })
  const body = await readBody(event).catch(() => undefined)
  const parsed = irCompileRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `IR 编译参数无效：${parsed.error.issues[0]?.message ?? '请检查 IR JSON 后重试'}` })
  }
  return fetchBackend(event, `/rule-governance/rules/${encodeURIComponent(ruleId)}/compile`, {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
