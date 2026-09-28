import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 404, statusMessage: '证据详情需要真实后端（mock 模式不可用）' })
  }
  const context = getRouterParam(event, 'id')
  if (!context) {
    throw createError({ statusCode: 400, statusMessage: '缺少证据 ID' })
  }
  return fetchBackend(event, `/evidence/${encodeURIComponent(context)}`, { admin: true })
})
