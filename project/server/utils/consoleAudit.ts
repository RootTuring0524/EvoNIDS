import type { H3Event } from 'h3'

import { fetchBackend } from './backend'

export const CONSOLE_AUDIT_ACTIONS = [
  'console.login.success',
  'console.login.failure',
  'console.login.locked',
  'console.logout',
] as const

export type ConsoleAuditAction = (typeof CONSOLE_AUDIT_ACTIONS)[number]

// Best-effort forwarding of console authentication events into the backend
// audit stream. A failure (for example when NUXT_BACKEND_ADMIN_TOKEN is not
// configured) is logged on the Nuxt server but never blocks the login flow.
export async function auditConsoleEvent(
  event: H3Event,
  action: ConsoleAuditAction,
  note?: string,
): Promise<void> {
  try {
    await fetchBackend(event, '/audit/console', {
      method: 'POST',
      body: { action, note: note ?? null },
      admin: true,
    })
  } catch (error) {
    console.error('[console-audit] failed to forward event', action, String(error))
  }
}
