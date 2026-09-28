import { fetchBackend, usesMockApi } from '../../utils/backend'

// GET /api/investigations/:id — run detail with claims, tool executions and
// feedback. A missing run comes back as a 404 envelope from the backend.
export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id') || ''
  if (!id) throw createError({ statusCode: 400, statusMessage: '缺少调查运行 ID' })
  if (!usesMockApi(event)) {
    return fetchBackend(event, `/investigations/${encodeURIComponent(id)}`)
  }
  throw createError({ statusCode: 404, statusMessage: '该调查运行由真实后端产生；mock 模式不提供运行详情。' })
})
