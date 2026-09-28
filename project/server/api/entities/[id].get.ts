import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 404, statusMessage: '实体详情需要真实后端（mock 模式不可用）' })
  }
  const context = getRouterParam(event, 'id')
  if (!context) {
    throw createError({ statusCode: 400, statusMessage: '缺少实体 ID' })
  }
  return fetchBackend(event, `/entities/${encodeURIComponent(context)}`)
})
