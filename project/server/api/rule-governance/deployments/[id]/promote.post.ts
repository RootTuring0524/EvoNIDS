import { ruleDeploymentPromoteRequestSchema } from '../../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../../utils/backend'

// POST /api/rule-governance/deployments/:id/promote — promote a canary
// deployment to production. High-risk action; the client must confirm first.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '提升部署需要真实后端（mock 模式不可用）' })
  }
  const deploymentId = getRouterParam(event, 'id') || ''
  if (!deploymentId) throw createError({ statusCode: 400, statusMessage: '缺少部署 ID' })
  const body = await readBody(event).catch(() => undefined)
  const parsed = ruleDeploymentPromoteRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `提升参数无效：${parsed.error.issues[0]?.message ?? '请检查后重试'}` })
  }
  return fetchBackend(event, `/rule-governance/deployments/${encodeURIComponent(deploymentId)}/promote`, {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
