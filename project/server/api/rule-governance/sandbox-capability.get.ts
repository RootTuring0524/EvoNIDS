import { fetchBackend, usesMockApi } from '../../utils/backend'

// GET /api/rule-governance/sandbox-capability — whether the real backend can
// execute Suricata validation runs. In mock mode the BFF reports no measured
// capability and the rules page shows the demo notice instead.
export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    return fetchBackend(event, '/rule-governance/sandbox-capability')
  }
  return {
    suricataAvailable: false,
    binary: null,
    executorVersion: '',
    note: '演示模式：沙箱能力需由真实后端检测，本 BFF 不提供能力结果。',
  }
})
