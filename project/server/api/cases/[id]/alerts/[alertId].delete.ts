import { fetchBackend, usesMockApi } from '../../../../utils/backend'

export default defineEventHandler(async (event) => {
  if (usesMockApi(event)) {
    throw createError({ statusCode: 409, statusMessage: '摘除告警需要真实后端（mock 模式不可用）' })
  }
  const caseId = getRouterParam(event, 'id')
  const alertId = getRouterParam(event, 'alertId')
  if (!caseId || !alertId) {
    throw createError({ statusCode: 400, statusMessage: '缺少案件或告警 ID' })
  }
  return fetchBackend(event, `/cases/${encodeURIComponent(caseId)}/alerts/${encodeURIComponent(alertId)}`, {
    method: 'DELETE',
    admin: true,
  })
})
