import type { RuleDetail, RuleRecord, RuleStage, StructuredRule } from '../../shared/types/security'
import { ruleDetails } from './domain-data'
import { rules } from './mock-data'

export interface RuleTimelineEvent {
  id: string
  stage: RuleStage
  timestamp: string
  actor: string
  summary: string
  note?: string
  outcome: 'completed' | 'failed'
}

interface RuleStateStore {
  details: Record<string, RuleDetail>
  timelines: Record<string, RuleTimelineEvent[]>
}

interface ActionContext {
  actor?: string
  note?: string
  reason?: string
}

interface RuleStateError extends Error {
  statusCode: number
  statusMessage: string
}

const STORE_KEY = '__evonidsRuleState'
const globalStore = globalThis as typeof globalThis & { [STORE_KEY]?: RuleStateStore }

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function stateError(statusCode: number, statusMessage: string): RuleStateError {
  const error = new Error(statusMessage) as RuleStateError
  error.statusCode = statusCode
  error.statusMessage = statusMessage
  return error
}

function createInitialStore(): RuleStateStore {
  const detail = clone(ruleDetails['EVO-2026-0716-14']!)
  return {
    details: { 'EVO-2026-0716-14': detail },
    timelines: {
      'EVO-2026-0716-14': [
        {
          id: 'RULE-EVENT-001',
          stage: 'candidate',
          timestamp: '2026-07-16T14:27:41+08:00',
          actor: 'DeepSeek V4 Pro',
          summary: '基于 ALT-78435 与 4 条授权证据生成候选修复规则',
          outcome: 'completed',
        },
        {
          id: 'RULE-EVENT-002',
          stage: 'validating',
          timestamp: '2026-07-16T14:29:16+08:00',
          actor: 'replay-worker-02',
          summary: '启动历史攻击流量、正常流量与阈值扰动回放',
          outcome: 'completed',
        },
        {
          id: 'RULE-EVENT-003',
          stage: 'validated',
          timestamp: '2026-07-16T14:35:08+08:00',
          actor: 'validation-gate',
          summary: '质量分 92，误报率 0.31%，达到人工确认门槛',
          outcome: 'completed',
        },
      ],
    },
  }
}

function store() {
  globalStore[STORE_KEY] ||= createInitialStore()
  return globalStore[STORE_KEY]
}

function now() {
  return new Date().toISOString()
}

function nextEventId(events: RuleTimelineEvent[]) {
  return `RULE-EVENT-${String(events.length + 1).padStart(3, '0')}`
}

function getMutableDetail(id: string) {
  const detail = store().details[id]
  if (!detail) {
    throw stateError(404, `Rule ${id} does not have an available detail record`)
  }
  return detail
}

function requireStage(id: string, allowed: RuleStage[], action: string) {
  const detail = getMutableDetail(id)
  if (!allowed.includes(detail.record.stage)) {
    throw stateError(409, `${action} is not allowed while rule ${id} is ${detail.record.stage}`)
  }
  return detail
}

function appendEvent(id: string, stage: RuleStage, actor: string, summary: string, note?: string, outcome: 'completed' | 'failed' = 'completed') {
  const events = store().timelines[id] ||= []
  events.push({ id: nextEventId(events), stage, timestamp: now(), actor, summary, note, outcome })
}

function transition(detail: RuleDetail, stage: RuleStage) {
  detail.record.stage = stage
  detail.record.updatedAt = now()
}

export function listRules(): RuleRecord[] {
  const currentDetails = store().details
  return rules.map((rule) => clone(currentDetails[rule.id]?.record ?? rule))
}

export function getRuleDetail(id: string): RuleDetail {
  return clone(getMutableDetail(id))
}

export function getRuleTimeline(id: string) {
  const detail = getMutableDetail(id)
  return {
    currentStage: detail.record.stage,
    items: clone(store().timelines[id] ?? []),
  }
}

export function advanceValidation(id: string, context: ActionContext = {}): RuleDetail {
  const detail = requireStage(id, ['candidate', 'repaired', 'validating'], 'Validation transition')
  const actor = context.actor || 'Root'

  if (detail.record.stage === 'validating') {
    transition(detail, 'validated')
    appendEvent(
      id,
      'validated',
      'validation-gate',
      `回放验证完成：命中率 ${detail.validation.hitRate}%，误报率 ${detail.validation.falsePositiveRate}%`,
      context.note,
    )
  } else {
    transition(detail, 'validating')
    appendEvent(id, 'validating', actor, '提交规则回放验证，已进入验证队列', context.note)
  }

  return clone(detail)
}

export function rejectValidation(id: string, context: ActionContext = {}): RuleDetail {
  const detail = requireStage(id, ['validating'], 'Reject')
  const reason = context.reason?.trim()
  if (!reason) throw stateError(400, 'A rejection reason is required')
  transition(detail, 'rejected')
  appendEvent(id, 'rejected', context.actor || 'Root', '验证未通过，规则已退回修复', reason, 'failed')
  return clone(detail)
}

export function confirmRule(id: string, context: ActionContext = {}): RuleDetail {
  const detail = requireStage(id, ['validated'], 'Confirm')
  transition(detail, 'confirmed')
  appendEvent(id, 'confirmed', context.actor || 'Root', '人工复核验证结果并确认规则版本', context.note)
  return clone(detail)
}

export function deployRule(id: string, context: ActionContext = {}): RuleDetail {
  const detail = requireStage(id, ['confirmed'], 'Deploy')
  const note = context.note?.trim()
  if (!note) throw stateError(400, 'A deployment note is required')
  transition(detail, 'deployed')
  appendEvent(id, 'deployed', context.actor || 'Root', '规则已同步至 6 / 6 个检测传感器', note)
  return clone(detail)
}

export function repairRule(id: string, context: ActionContext = {}): RuleDetail {
  const detail = requireStage(id, ['rejected', 'validated', 'confirmed', 'deployed', 'deprecated'], 'Repair')
  const reason = context.reason?.trim()
  if (!reason) throw stateError(400, 'A repair reason is required')

  const previous: StructuredRule = clone(detail.structured)
  detail.previousVersion = previous
  detail.structured = {
    ...clone(detail.structured),
    version: detail.structured.version + 1,
    parent_rule_id: previous.rule_id,
  }
  detail.record.revision += 1
  detail.record.rationale = reason
  detail.diffReason = reason
  transition(detail, 'repaired')
  appendEvent(
    id,
    'repaired',
    context.actor || 'Root',
    `创建修复版本 v${detail.structured.version}，等待重新验证`,
    reason,
  )
  return clone(detail)
}

export function deprecateRule(id: string, context: ActionContext = {}): RuleDetail {
  const detail = requireStage(id, ['deployed'], 'Deprecate')
  const reason = context.reason?.trim()
  if (!reason) throw stateError(400, 'A deprecation reason is required')
  transition(detail, 'deprecated')
  appendEvent(id, 'deprecated', context.actor || 'Root', '规则已从检测平面撤下并标记为废弃', reason)
  return clone(detail)
}

export function resetRuleState() {
  globalStore[STORE_KEY] = createInitialStore()
}
