import { readinessResponseSchema } from '../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    return readinessResponseSchema.parse(await fetchBackend<unknown>(event, '/readiness'))
  }
  return {
    status: 'attention', environment: 'mock', checkedAt: new Date().toISOString(), blockers: 0, warnings: 3,
    checks: [
      { id: 'database', label: '持久化数据库', status: 'warn', detail: 'Mock 模式不读取真实数据库' },
      { id: 'admin-auth', label: '管理员写操作鉴权', status: 'warn', detail: '固定演示模式不验证管理员令牌' },
      { id: 'sensor-auth', label: '探针采集鉴权', status: 'warn', detail: '切换真实模式后由服务端验证采集令牌' },
      { id: 'collection-plane', label: '采集平面', status: 'pass', detail: '固定样本包含在线、降级、离线和维护状态' },
      { id: 'model-artifacts', label: '模型制品', status: 'warn', detail: '固定模型指标仅用于界面验收' },
      { id: 'runtime-mode', label: '运行环境', status: 'warn', detail: '当前为 Mock 模式，不代表生产就绪' },
    ],
  }
})
