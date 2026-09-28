import { ruleDeploymentRollbackRequestSchema } from '../../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../../utils/backend'

// POST /api/rule-governance/deployments/:id/rollback — roll a deployment back.
// The reason is mandatory (>= 10 chars, enforced here and by the backend);
// rollback is high-risk and the client must confirm first.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '回滚部署需要真实后端（mock 模式不可用）' })
  }
  const deploymentId = getRouterParam(event, 'id') || ''
  if (!deploymentId) throw createError({ statusCode: 400, statusMessage: '缺少部署 ID' })
  const body = await readBody(event).catch(() => undefined)
  const parsed = ruleDeploymentRollbackRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `回滚原因必填且至少 10 个字符（${parsed.error.issues[0]?.message ?? ''}）` })
  }
  return fetchBackend(event, `/rule-governance/deployments/${encodeURIComponent(deploymentId)}/rollback`, {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
