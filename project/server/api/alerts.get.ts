import { alerts } from '../utils/mock-data'
import { alertsResponseSchema } from '../../shared/schemas/security'
import { fetchBackend, usesMockApi } from '../utils/backend'

const sortableFields = new Set([
  'severity',
  'timestamp',
  'title',
  'sourceIp',
  'destinationIp',
  'category',
  'riskScore',
  'status',
  'owner',
])

const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 } as const

function positiveInteger(value: unknown, fallback: number, maximum: number) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0 ? Math.min(parsed, maximum) : fallback
}

export default defineEventHandler(async (event) => {
  const query = getQuery(event)
  if (!usesMockApi(event)) {
    const payload = await fetchBackend<unknown>(event, '/alerts', { query })
    return alertsResponseSchema.parse(payload)
  }

  const severity = typeof query.severity === 'string' ? query.severity : 'all'
  const status = typeof query.status === 'string' ? query.status : 'all'
  const category = typeof query.category === 'string' ? query.category : 'all'
  const search = typeof query.search === 'string' ? query.search.toLowerCase() : ''
  const page = positiveInteger(query.page, 1, 100_000)
  const pageSize = positiveInteger(query.pageSize, 25, 100)
  const sortBy = typeof query.sortBy === 'string' && sortableFields.has(query.sortBy) ? query.sortBy : 'riskScore'
  const sortDirection = query.sortDir === 'asc' ? 1 : -1

  const filtered = alerts.filter((item) => {
    return (
      (severity === 'all' || item.severity === severity) &&
      (status === 'all' || item.status === status) &&
      (category === 'all' || item.category === category) &&
      (!search || `${item.id} ${item.title} ${item.sourceIp} ${item.destinationIp}`.toLowerCase().includes(search))
    )
  })

  const sorted = [...filtered].sort((left, right) => {
    if (sortBy === 'severity') {
      return (severityOrder[left.severity] - severityOrder[right.severity]) * sortDirection
    }

    const leftValue = left[sortBy as keyof typeof left]
    const rightValue = right[sortBy as keyof typeof right]
    if (typeof leftValue === 'number' && typeof rightValue === 'number') return (leftValue - rightValue) * sortDirection
    return String(leftValue ?? '').localeCompare(String(rightValue ?? ''), 'zh-CN', { numeric: true }) * sortDirection
  })

  const total = sorted.length
  const lastPage = Math.max(1, Math.ceil(total / pageSize))
  const currentPage = Math.min(page, lastPage)
  const offset = (currentPage - 1) * pageSize

  const agentDecisions: Record<string, number> = {}
  let agentCompleted = 0
  for (const item of filtered) {
    if (item.agentState !== 'completed') continue
    agentCompleted += 1
    if (item.agentDecision) agentDecisions[item.agentDecision] = (agentDecisions[item.agentDecision] ?? 0) + 1
  }

  return {
    items: sorted.slice(offset, offset + pageSize),
    total,
    page: currentPage,
    pageSize,
    agentCompleted,
    agentPending: total - agentCompleted,
    agentDecisions,
  }
})
