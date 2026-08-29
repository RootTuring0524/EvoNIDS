import { SESSION_COOKIE_NAME, verifySessionToken } from '../utils/session'

// Guards every BFF route when console authentication is configured. The auth
// endpoints themselves stay reachable so the login page works, and an unset
// password keeps the console open (local development / demo default).
export default defineEventHandler((event) => {
  const path = getRequestURL(event).pathname
  if (!path.startsWith('/api/') || path.startsWith('/api/auth/')) return

  const config = useRuntimeConfig(event)
  const password = config.console.password
  if (!password) return

  const token = getCookie(event, SESSION_COOKIE_NAME)
  if (verifySessionToken(token, { password, sessionHours: config.console.sessionHours })) return

  throw createError({ statusCode: 401, statusMessage: 'Console authentication required' })
})
