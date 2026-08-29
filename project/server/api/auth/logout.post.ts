import { SESSION_COOKIE_NAME } from '../../utils/session'

export default defineEventHandler((event) => {
  deleteCookie(event, SESSION_COOKIE_NAME, { path: '/' })
  return { ok: true }
})
