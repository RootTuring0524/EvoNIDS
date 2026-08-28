import { overviewMetricsSchema } from '../../shared/schemas/security'
import { alerts, flows, rules, sensorRegistry } from '../utils/mock-data'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    return overviewMetricsSchema.parse(await fetchBackend<unknown>(event, '/overview'))
  }
  return {
    pendingAlerts: alerts.filter((item) => item.status === 'new' || item.status === 'investigating').length,
    highRiskAlerts: alerts.filter((item) => (item.severity === 'critical' || item.severity === 'high') && item.status !== 'closed').length,
    unassignedAlerts: alerts.filter((item) => (item.status === 'new' || item.status === 'investigating') && !item.owner).length,
    flows: flows.length,
    anomalousFlows: flows.filter((item) => item.verdict !== 'benign').length,
    candidateRules: rules.filter((item) => ['candidate', 'validating', 'validated', 'repaired', 'confirmed'].includes(item.stage)).length,
    deployedRules: rules.filter((item) => item.stage === 'deployed').length,
    sensors: sensorRegistry.summary,
  }
})
