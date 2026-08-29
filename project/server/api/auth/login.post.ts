import { z } from 'zod'
import { SESSION_COOKIE_NAME, createSessionToken, passwordMatches } from '../../utils/session'

const bodySchema = z.object({ password: z.string().min(1).max(200) })

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig(event)
  if (!config.console.password) {
    throw createError({ statusCode: 409, statusMessage: '控制台未启用登录：请先配置 NUXT_CONSOLE_PASSWORD' })
  }
  const parsed = bodySchema.safeParse(await readBody(event))
  if (!parsed.success) {
    throw createError({ statusCode: 400, statusMessage: '请输入访问口令' })
  }
  if (!passwordMatches(parsed.data.password, config.console.password)) {
    throw createError({ statusCode: 401, statusMessage: '访问口令不正确' })
  }
  const sessionHours = config.console.sessionHours
  setCookie(event, SESSION_COOKIE_NAME, createSessionToken({ password: config.console.password, sessionHours }), {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: sessionHours * 3_600,
  })
  return { ok: true }
})
