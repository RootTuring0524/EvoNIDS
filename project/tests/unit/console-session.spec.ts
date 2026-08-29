import { describe, expect, it } from 'vitest'
import {
  createSessionToken,
  passwordMatches,
  sessionCookieOptions,
  verifySessionToken,
} from '../../server/utils/session'

const config = { password: 'correct-horse-battery', sessionHours: 24 }

describe('console session tokens', () => {
  it('round-trips a fresh token', () => {
    const token = createSessionToken(config)
    expect(token.startsWith('v1.')).toBe(true)
    expect(verifySessionToken(token, config)).toBe(true)
  })

  it('rejects expired, tampered and foreign-key tokens', () => {
    const expired = createSessionToken({ ...config, sessionHours: -1 })
    expect(verifySessionToken(expired, config)).toBe(false)

    const token = createSessionToken(config)
    const payload = token.slice(0, token.lastIndexOf('.'))
    expect(verifySessionToken(`${payload}.forged-signature`, config)).toBe(false)
    expect(verifySessionToken(token, { ...config, password: 'other-password' })).toBe(false)
    expect(verifySessionToken('', config)).toBe(false)
    expect(verifySessionToken(undefined, config)).toBe(false)
  })

  it('compares passwords without length-dependent timing', () => {
    expect(passwordMatches('correct-horse-battery', 'correct-horse-battery')).toBe(true)
    expect(passwordMatches('wrong', 'correct-horse-battery')).toBe(false)
    expect(passwordMatches('', 'correct-horse-battery')).toBe(false)
  })

  it('derives http-only lax cookie options from the session length', () => {
    expect(sessionCookieOptions(24)).toEqual({ httpOnly: true, sameSite: 'lax', path: '/', maxAge: 86_400 })
  })
})
