import { fetchBackend, usesMockApi } from '../utils/backend'

const mockItems = [
  {
    id: 'AUD-918402',
    createdAt: '2026-07-16T14:41:22+08:00',
    actor: 'Root',
    action: 'rule.deployed',
    objectType: 'rule',
    objectId: 'RULE-CAND-0042',
    outcome: 'completed',
    requestId: 'REQ-DEMO-001',
    note: '确认规则部署',
  },
  {
    id: 'AUD-918397',
    createdAt: '2026-07-16T14:35:08+08:00',
    actor: 'DeepSeek V4 Pro',
    action: 'rule.candidate',
    objectType: 'rule',
    objectId: 'RULE-CAND-0042',
    outcome: 'completed',
    requestId: 'AGENT-RUN-0716-0284',
    note: '生成候选修复规则，等待回放验证',
  },
  {
    id: 'AUD-918391',
    createdAt: '2026-07-16T14:33:11+08:00',
    actor: '检测平面',
    action: 'alert.created',
    objectType: 'alert',
    objectId: 'ALT-78435',
    outcome: 'completed',
    requestId: 'REQ-DEMO-003',
    note: '创建高危端口扫描变体告警',
  },
]

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    return fetchBackend(event, '/audit', { query: getQuery(event) })
  }
  return { items: mockItems, total: mockItems.length, page: 1, pageSize: 50 }
})
