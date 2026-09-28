import { describe, expect, it } from 'vitest'

import { entitiesResponseSchema, entityDetailSchema, evidenceDetailSchema, evidenceListResponseSchema } from '../../shared/schemas/security'

const sampleEntity = {
  id: 'ENT-ABC1',
  entityType: 'ip',
  value: '192.0.2.77',
  firstSeenAt: '2026-09-09T08:00:00Z',
  lastSeenAt: '2026-09-09T09:00:00Z',
  eventCount: 3,
  sensorIds: ['ent-core'],
  createdAt: '2026-09-09T08:00:00Z',
}

const sampleEvidence = {
  id: 'EVD-ABC1',
  sourceType: 'suricata_eve',
  sensorId: 'ent-core',
  eventType: 'alert',
  externalId: '10001:2200451',
  observedAt: '2026-09-09T08:00:00Z',
  receivedAt: '2026-09-09T08:00:01Z',
  contentSha256: 'a'.repeat(64),
  integrity: 'complete',
  dataMissing: 'none',
  parserVersion: 'evonids-eve-v1',
  redacted: false,
  sourceRefType: 'alert',
  sourceRefId: 'ALT-1',
  artifactSizeBytes: 240,
  createdAt: '2026-09-09T08:00:01Z',
}

describe('entity and evidence schemas', () => {
  it('parses entity list and detail with relations', () => {
    const list = entitiesResponseSchema.parse({ items: [sampleEntity], total: 1, page: 1, pageSize: 25 })
    expect(list.items[0].value).toBe('192.0.2.77')
    const detail = entityDetailSchema.parse({
      ...sampleEntity,
      relations: [
        {
          id: 'REL-1',
          relationType: 'communicates_with',
          otherEntityId: 'ENT-ABC2',
          otherEntityValue: '10.0.0.5',
          eventCount: 2,
          firstSeenAt: '2026-09-09T08:00:00Z',
          lastSeenAt: '2026-09-09T09:00:00Z',
        },
      ],
    })
    expect(detail.relations[0].otherEntityValue).toBe('10.0.0.5')
  })

  it('rejects non-64-char hashes on evidence', () => {
    expect(() => evidenceListResponseSchema.parse({ items: [{ ...sampleEvidence, contentSha256: 'short' }], total: 1, page: 1, pageSize: 25 })).toThrow()
  })

  it('parses evidence detail with artifact text', () => {
    const detail = evidenceDetailSchema.parse({ ...sampleEvidence, fields: { event_type: 'alert' }, artifactText: '{"event_type":"alert"}' })
    expect(detail.artifactText).toContain('alert')
    expect(detail.fields.event_type).toBe('alert')
  })
})
