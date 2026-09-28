import { SESSION_COOKIE_NAME } from '../../utils/session'
import { auditConsoleEvent } from '../../utils/consoleAudit'

export default defineEventHandler(async (event) => {
  deleteCookie(event, SESSION_COOKIE_NAME, { path: '/' })
  await auditConsoleEvent(event, 'console.logout', 'session cleared')
  return { ok: true }
})
