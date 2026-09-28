import { feedbackCreateRequestSchema } from '../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../utils/backend'

// POST /api/investigations/:id/feedback — record analyst feedback on a run.
// Backend contract: feedback.objectId must equal the run id.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '提交调查反馈需要真实后端（mock 模式不可用）' })
  }
  const id = getRouterParam(event, 'id') || ''
  if (!id) throw createError({ statusCode: 400, statusMessage: '缺少调查运行 ID' })
  const body = await readBody(event).catch(() => undefined)
  const parsed = feedbackCreateRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `反馈参数无效：${parsed.error.issues[0]?.message ?? '请检查后重试'}` })
  }
  if (parsed.data.objectId !== id) {
    throw createError({ statusCode: 400, statusMessage: '反馈 objectId 必须与调查运行 ID 一致' })
  }
  return fetchBackend(event, `/investigations/${encodeURIComponent(id)}/feedback`, {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
