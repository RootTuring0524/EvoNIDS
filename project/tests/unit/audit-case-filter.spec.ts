import { describe, expect, it } from 'vitest'

import { auditEventsResponseSchema, caseIdSchema } from '../../shared/schemas/security'

describe('audit case filter schema', () => {
  it('accepts a well-formed case id', () => {
    expect(caseIdSchema.parse('CASE-ABCDEF123456')).toBe('CASE-ABCDEF123456')
    expect(caseIdSchema.parse('CASE-000000000000')).toBe('CASE-000000000000')
    expect(caseIdSchema.parse('CASE-FFFFFFFFFFFF')).toBe('CASE-FFFFFFFFFFFF')
  })

  it('rejects malformed case ids', () => {
    const invalid = [
      'CASE-ABC123', // too short
      'CASE-ABCDEF12345G', // non-hex character
      'CASE-ABCDEF1234567', // too long
      'case-abcdef123456', // lowercase
      'case-ABCDEF123456', // lowercase prefix
      'CASE_ABCDEF123456', // wrong separator
      'CASE-', // empty suffix
      '',
    ]
    for (const value of invalid) {
      expect(() => caseIdSchema.parse(value), `expected rejection of ${value}`).toThrow()
      expect(caseIdSchema.safeParse(value).success).toBe(false)
    }
  })

  it('validates the audit list response envelope that carries filtered items', () => {
    const sample = {
      items: [
        {
          id: 'AUD-1',
          createdAt: '2026-09-09T08:00:00Z',
          actor: 'env:admin',
          action: 'case.created',
          objectType: 'case',
          objectId: 'CASE-ABCDEF123456',
          outcome: 'completed',
          requestId: null,
          note: 'Case created',
        },
      ],
      total: 1,
      page: 1,
      pageSize: 50,
    }
    const parsed = auditEventsResponseSchema.parse(sample)
    expect(parsed.items[0].objectId).toBe('CASE-ABCDEF123456')
    expect(() =>
      auditEventsResponseSchema.parse({ ...sample, total: -1, pageSize: 0 }),
    ).toThrow()
  })
})
