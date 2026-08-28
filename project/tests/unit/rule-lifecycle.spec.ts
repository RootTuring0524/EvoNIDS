import { beforeEach, describe, expect, it } from 'vitest'
import { ruleDetailSchema } from '../../shared/schemas/security'
import {
  advanceValidation,
  confirmRule,
  deployRule,
  deprecateRule,
  getRuleDetail,
  getRuleTimeline,
  listRules,
  rejectValidation,
  repairRule,
  resetRuleState,
} from '../../server/utils/rule-state'

const id = 'EVO-2026-0716-14'

describe('server-side rule lifecycle state machine', () => {
  beforeEach(() => resetRuleState())

  it('requires explicit confirmation before deployment and persists deployment notes', () => {
    expect(getRuleDetail(id).record.stage).toBe('validated')
    expect(() => deployRule(id, { note: 'should fail' })).toThrow(/not allowed/i)

    const confirmed = confirmRule(id, { actor: 'Root', note: 'reviewed replay evidence' })
    expect(confirmed.record.stage).toBe('confirmed')

    const deployed = deployRule(id, { actor: 'Root', note: '灰度部署至 6 个传感器' })
    expect(() => ruleDetailSchema.parse(deployed)).not.toThrow()
    expect(deployed.record.stage).toBe('deployed')
    expect(getRuleDetail(id).record.stage).toBe('deployed')
    expect(listRules().find((rule) => rule.id === id)?.stage).toBe('deployed')
    expect(getRuleTimeline(id).items.at(-1)).toMatchObject({ stage: 'deployed', note: '灰度部署至 6 个传感器' })
  })

  it('supports rejection, repair, revalidation and version lineage', () => {
    const repaired = repairRule(id, { actor: 'Root', reason: '需要增加授权扫描器排除条件' })
    expect(repaired.record.stage).toBe('repaired')
    expect(repaired.structured.version).toBe(2)
    expect(repaired.previousVersion?.version).toBe(1)
    expect(repaired.structured.parent_rule_id).toBe(repaired.previousVersion?.rule_id)

    expect(advanceValidation(id).record.stage).toBe('validating')
    expect(rejectValidation(id, { reason: '正常流量误报率超过门槛' }).record.stage).toBe('rejected')

    const repairedAgain = repairRule(id, { reason: '加入服务网格健康检查白名单' })
    expect(repairedAgain.record.stage).toBe('repaired')
    expect(repairedAgain.structured.version).toBe(3)
    expect(advanceValidation(id).record.stage).toBe('validating')
    expect(advanceValidation(id).record.stage).toBe('validated')
  })

  it('only deprecates deployed rules', () => {
    expect(() => deprecateRule(id, { reason: 'premature' })).toThrow(/not allowed/i)
    confirmRule(id)
    deployRule(id, { note: 'production deployment' })
    const deprecated = deprecateRule(id, { actor: 'Root', reason: '由 v2 规则替代' })
    expect(deprecated.record.stage).toBe('deprecated')
    expect(getRuleTimeline(id).items.at(-1)).toMatchObject({ stage: 'deprecated', outcome: 'completed' })
  })

  it('returns a not-found error instead of falling back to another rule', () => {
    expect(() => getRuleDetail('SIG-2200451')).toThrow(/does not have an available detail record/i)
  })
})
