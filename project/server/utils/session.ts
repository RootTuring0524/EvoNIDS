import { createHash, createHmac, timingSafeEqual } from 'node:crypto'

// Signed-cookie sessions for the console. The HMAC key is the configured console
// password, so sessions survive server restarts without persisting any secret on
// disk, and changing the password invalidates every outstanding session at once.
export const SESSION_COOKIE_NAME = 'evonids_session'

export interface ConsoleSessionConfig {
  password: string
  sessionHours: number
}

function sessionSignature(password: string, payload: string) {
  return createHmac('sha256', password).update(payload).digest('base64url')
}

export function createSessionToken(config: ConsoleSessionConfig): string {
  const expiry = Date.now() + config.sessionHours * 3_600_000
  const payload = `v1.${expiry}`
  return `${payload}.${sessionSignature(config.password, payload)}`
}

export function verifySessionToken(token: string | undefined | null, config: ConsoleSessionConfig): boolean {
  if (!token || !config.password) return false
  const separator = token.lastIndexOf('.')
  if (separator <= 0) return false
  const payload = token.slice(0, separator)
  const signature = token.slice(separator + 1)
  if (!payload.startsWith('v1.')) return false
  const expiry = Number(payload.slice(3))
  if (!Number.isFinite(expiry) || expiry <= Date.now()) return false
  const expected = Buffer.from(sessionSignature(config.password, payload))
  const actual = Buffer.from(signature)
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

export function passwordMatches(supplied: string, expected: string): boolean {
  // Hash both sides so the timing-safe comparison length never depends on input length.
  const left = createHash('sha256').update(supplied, 'utf8').digest()
  const right = createHash('sha256').update(expected, 'utf8').digest()
  return timingSafeEqual(left, right)
}

export function sessionCookieOptions(sessionHours: number) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: sessionHours * 3_600,
  } as const
}
