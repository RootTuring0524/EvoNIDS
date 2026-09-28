import { z } from 'zod'

import { SESSION_COOKIE_NAME, createSessionToken, passwordMatches, sessionCookieOptions } from '../../utils/session'
import { createSlidingWindowLimiter } from '../../utils/rate-limit'
import { auditConsoleEvent } from '../../utils/consoleAudit'
import type { ConsoleRuntimeConfig } from '../../utils/consoleConfig'

const bodySchema = z.object({ password: z.string().min(1).max(200) })

let limiter: ReturnType<typeof createSlidingWindowLimiter> | null = null

function loginLimiter(config: ConsoleRuntimeConfig['console']) {
  // The limiter is process-local and configured once from the runtime config.
  if (limiter === null) {
    limiter = createSlidingWindowLimiter(config.loginMaxAttempts, config.loginWindowSeconds * 1000)
  }
  return limiter
}

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig(event) as unknown as ConsoleRuntimeConfig
  if (!config.console.password) {
    throw createError({ statusCode: 409, statusMessage: '控制台未启用登录：请先配置 NUXT_CONSOLE_PASSWORD' })
  }
  const parsed = bodySchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: '请输入访问口令' })
  }

  // getRequestIP returns the remote address only (no x-forwarded-for trust), so
  // the limit cannot be evaded by spoofing a header when the console is exposed
  // directly. Behind a TLS-terminating reverse proxy this aggregates per proxy
  // IP, which still caps global brute force.
  const ip = getRequestIP(event) || 'unknown'
  const decision = loginLimiter(config.console).check(ip)
  if (!decision.allowed) {
    await auditConsoleEvent(event, 'console.login.locked', `ip=${ip}`)
    throw createError({
      statusCode: 429,
      statusMessage: `尝试次数过多，请在 ${decision.retryAfterSeconds} 秒后重试`,
    })
  }

  if (!passwordMatches(parsed.data.password, config.console.password)) {
    loginLimiter(config.console).recordFailure(ip)
    await auditConsoleEvent(event, 'console.login.failure', `ip=${ip}`)
    throw createError({ statusCode: 401, statusMessage: '访问口令不正确' })
  }

  loginLimiter(config.console).recordSuccess(ip)
  await auditConsoleEvent(event, 'console.login.success', `ip=${ip}`)

  const sessionHours = config.console.sessionHours
  setCookie(
    event,
    SESSION_COOKIE_NAME,
    createSessionToken({ password: config.console.password, sessionHours }),
    sessionCookieOptions(sessionHours, Boolean(config.console.cookieSecure)),
  )
  return { ok: true }
})
