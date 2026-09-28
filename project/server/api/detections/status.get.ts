import { detectionStatusSchema } from '../../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../../utils/backend'

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    const payload = await fetchBackend<unknown>(event, '/detections/status')
    return detectionStatusSchema.parse(payload)
  }
  // 演示模式不伪造模型状态：明确标注「未启用」并说明数据仅真实后端提供。
  return {
    mode: 'disabled',
    featureVersion: '',
    channels: {
      baseline: { available: false, modelId: null, version: null, contractMatches: false, reason: null },
      autoencoder: { available: false, modelId: null, version: null, contractMatches: false, reason: null },
    },
    alerting: false,
    notes: ['演示模式：在线检测开关与模型通道状态仅由真实后端提供，此处不展示伪造状态。'],
  }
})
