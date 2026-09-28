import { fetchBackend, usesMockApi } from '../../utils/backend'

// GET /api/rule-governance/sensor-groups — canary/production sensor groups.
// Mock mode returns an empty list (groups are backend state).
export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) return fetchBackend(event, '/rule-governance/sensor-groups')
  return []
})
