import { describe, expect, it } from 'vitest'

import { caseDetailSchema, caseRecordSchema, casesResponseSchema, caseSuggestionResponseSchema } from '../../shared/schemas/security'

const sampleCase = {
  id: 'CASE-ABC123',
  title: '扫描活动调查',
  summary: '来自 192.0.2.77 的持续扫描。',
  severity: 'high',
  status: 'investigating',
  assignee: null,
  createdBy: 'env:admin',
  alertCount: 2,
  highestRiskScore: 84,
  createdAt: '2026-09-09T08:00:00Z',
  updatedAt: '2026-09-09T09:00:00Z',
}

describe('case schemas', () => {
  it('parses a valid case record', () => {
    const parsed = caseRecordSchema.parse(sampleCase)
    expect(parsed.id).toBe('CASE-ABC123')
    expect(parsed.severity).toBe('high')
  })

  it('rejects an invalid severity and negative alert count', () => {
    expect(() => caseRecordSchema.parse({ ...sampleCase, severity: 'extreme' })).toThrow()
    expect(() => caseRecordSchema.parse({ ...sampleCase, alertCount: -1 })).toThrow()
  })

  it('parses a case list response', () => {
    const response = casesResponseSchema.parse({ items: [sampleCase], total: 1, page: 1, pageSize: 25 })
    expect(response.items).toHaveLength(1)
  })

  it('parses case detail with alerts and timeline', () => {
    const detail = caseDetailSchema.parse({
      case: sampleCase,
      alerts: [],
      timeline: [
        { id: 'TLN-1', eventType: 'case.created', actor: 'env:admin', note: 'Case created', createdAt: '2026-09-09T08:00:00Z' },
      ],
    })
    expect(detail.timeline[0].eventType).toBe('case.created')
  })

  it('parses suggestions response', () => {
    const response = caseSuggestionResponseSchema.parse({
      items: [
        {
          caseId: 'CASE-ABC123',
          caseTitle: '扫描活动调查',
          caseStatus: 'open',
          sharedIps: ['192.0.2.77'],
          matchingAlertIds: ['ALT-1'],
          updatedAt: '2026-09-09T08:00:00Z',
        },
      ],
    })
    expect(response.items[0].sharedIps).toContain('192.0.2.77')
  })
})
