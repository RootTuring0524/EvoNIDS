import { SESSION_COOKIE_NAME, verifySessionToken } from '../../utils/session'

export default defineEventHandler((event) => {
  const config = useRuntimeConfig(event)
  const required = Boolean(config.console.password)
  const authenticated = required
    ? verifySessionToken(getCookie(event, SESSION_COOKIE_NAME), {
        password: config.console.password,
        sessionHours: config.console.sessionHours,
      })
    : true
  return { required, authenticated }
})
