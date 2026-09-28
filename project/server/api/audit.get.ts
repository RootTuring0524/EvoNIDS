import { caseIdSchema } from '../../shared/schemas/security'
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

/** Normalize and validate the optional caseId query parameter. */
function resolveCaseId(raw: unknown): string | undefined {
  if (raw === undefined) return undefined
  const trimmed = typeof raw === 'string' ? raw.trim() : ''
  if (!trimmed) return undefined
  const normalized = trimmed.toUpperCase()
  const parsed = caseIdSchema.safeParse(normalized)
  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: '案件编号格式无效：应为 CASE- 后跟 12 位大写十六进制字符',
    })
  }
  return parsed.data
}

export default defineEventHandler(async (event) => {
  const query = getQuery(event)
  const caseId = resolveCaseId(query.caseId)
  if (!usesMockApi(event)) {
    // Forward validated filters only; zod rejects malformed case ids before
    // they ever reach the backend so the page can explain the failure.
    return fetchBackend(event, '/audit', {
      query: { ...query, ...(caseId ? { caseId } : {}) },
    })
  }
  // Mock mode has no case records: a case filter honestly matches nothing,
  // while an absent filter keeps the previous mock behaviour.
  const items = caseId ? mockItems.filter((item) => item.objectType === 'case' && item.objectId === caseId) : mockItems
  return { items, total: items.length, page: 1, pageSize: 50 }
})
