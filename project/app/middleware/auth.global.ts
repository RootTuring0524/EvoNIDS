interface ConsoleAuthStatus {
  required?: boolean
  authenticated?: boolean
}

export default defineNuxtRouteMiddleware(async (to) => {
  if (to.path === '/login') return
  let status: ConsoleAuthStatus
  try {
    // useRequestFetch forwards the browser cookies during SSR, so a protected
    // console renders the login redirect instead of a wall of 401 data errors.
    // The cast skips Nuxt's typed route matcher, whose recursive route union
    // overflows the type checker on this internal endpoint (TS2321).
    const requestFetch = useRequestFetch() as (url: string) => Promise<ConsoleAuthStatus>
    status = await requestFetch('/api/auth/status')
  } catch {
    // Status probe failures must not lock the operator out of the console;
    // the server-side API guard remains the actual enforcement layer.
    return
  }
  if (!status.required || status.authenticated) return
  return navigateTo(`/login?redirect=${encodeURIComponent(to.fullPath)}`)
})
