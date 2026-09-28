import { investigationCreateRequestSchema } from '../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../utils/backend'

// POST /api/investigations — start a new AI investigation run. The actor
// credential stays server-side (the configured backend token); the BFF never
// exposes it to the browser.
export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '启动 AI 调查需要真实后端（mock 模式不可用）' })
  }
  const body = await readBody(event).catch(() => undefined)
  const parsed = investigationCreateRequestSchema.safeParse(body ?? {})
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: `调查启动参数无效：${parsed.error.issues[0]?.message ?? '请检查后重试'}` })
  }
  return fetchBackend(event, '/investigations', {
    method: 'POST',
    body: parsed.data,
    admin: true,
  })
})
