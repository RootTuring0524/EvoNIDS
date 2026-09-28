import { ruleDeploymentCreateRequestSchema } from '../../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../../utils/backend'

// POST /api/rule-governance/rules/:id/deployments — start a canary or full
// deployment. The backend refuses with 409 + reason when the chosen version has
// no passed sandbox run; that reason is forwarded verbatim to the console.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '创建规则部署需要真实后端（mock 模式不可用）' })
  }
  const ruleId = getRouterParam(event, 'id') || ''
  if (!ruleId) throw createError({ statusCode: 400, statusMessage: '缺少规则 ID' })
  const body = await readBody(event).catch(() => undefined)
  const parsed = ruleDeploymentCreateRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `部署参数无效：${parsed.error.issues[0]?.message ?? '请检查后重试'}` })
  }
  return fetchBackend(event, `/rule-governance/rules/${encodeURIComponent(ruleId)}/deployments`, {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
