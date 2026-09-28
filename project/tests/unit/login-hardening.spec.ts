import { describe, expect, it, vi, beforeEach } from 'vitest'

import { createSlidingWindowLimiter } from '../../server/utils/rate-limit'
import { createSessionToken, verifySessionToken, sessionCookieOptions } from '../../server/utils/session'

describe('sliding window login rate limiter', () => {
  beforeEach(() => {
    vi.useRealTimers()
  })

  it('allows attempts below the limit and locks beyond it', () => {
    const limiter = createSlidingWindowLimiter(3, 60_000)
    expect(limiter.check('10.0.0.1').allowed).toBe(true)
    limiter.recordFailure('10.0.0.1')
    expect(limiter.check('10.0.0.1').allowed).toBe(true)
    limiter.recordFailure('10.0.0.1')
    expect(limiter.check('10.0.0.1').allowed).toBe(true)
    limiter.recordFailure('10.0.0.1')
    const decision = limiter.check('10.0.0.1')
    expect(decision.allowed).toBe(false)
    expect(decision.retryAfterSeconds).toBeGreaterThan(0)
  })

  it('tracks keys independently', () => {
    const limiter = createSlidingWindowLimiter(1, 60_000)
    limiter.recordFailure('ip-a')
    expect(limiter.check('ip-a').allowed).toBe(false)
    expect(limiter.check('ip-b').allowed).toBe(true)
  })

  it('releases the lock after the window elapses', () => {
    vi.useFakeTimers()
    const limiter = createSlidingWindowLimiter(2, 60_000)
    limiter.recordFailure('ip-a')
    limiter.recordFailure('ip-a')
    expect(limiter.check('ip-a').allowed).toBe(false)
    vi.advanceTimersByTime(61_000)
    expect(limiter.check('ip-a').allowed).toBe(true)
  })

  it('resets the bucket on a successful login', () => {
    const limiter = createSlidingWindowLimiter(2, 60_000)
    limiter.recordFailure('ip-a')
    limiter.recordFailure('ip-a')
    expect(limiter.check('ip-a').allowed).toBe(false)
    limiter.recordSuccess('ip-a')
    expect(limiter.check('ip-a').allowed).toBe(true)
  })
})

describe('console session cookie options', () => {
  it('adds Secure only when requested', () => {
    const plain = sessionCookieOptions(24)
    expect(plain).not.toHaveProperty('secure')
    const secure = sessionCookieOptions(24, true)
    expect(secure).toHaveProperty('secure', true)
    expect(secure.httpOnly).toBe(true)
    expect(secure.sameSite).toBe('lax')
  })

  it('session tokens verify and reject tampering', () => {
    const config = { password: 'correct-horse', sessionHours: 1 }
    const token = createSessionToken(config)
    expect(verifySessionToken(token, config)).toBe(true)
    expect(verifySessionToken(token + 'x', config)).toBe(false)
    expect(verifySessionToken('v1.999999999999.aaaa', config)).toBe(false)
  })
})
