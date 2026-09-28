import { detectionFlowDetailSchema } from '../../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../../utils/backend'

export default defineEventHandler(async (event) => {
  const flowId = getRouterParam(event, 'flowId') || ''
  if (!flowId || flowId.length > 96) {
    throw createError({ statusCode: 400, statusMessage: 'flowId 无效' })
  }
  if (!usesMockApi(event)) {
    // 真实后端找不到该 Flow 的检测输出时返回 404 信封，这里原样透传。
    const payload = await fetchBackend<unknown>(event, `/detections/flows/${encodeURIComponent(flowId)}`)
    return detectionFlowDetailSchema.parse(payload)
  }
  throw createError({
    statusCode: 404,
    statusMessage: '演示模式：该 Flow 无在线模型检测记录（不生成伪造证据链）',
  })
})
