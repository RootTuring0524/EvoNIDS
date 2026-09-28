// Shared type for the console subset of the Nuxt runtime config. Kept in a
// plain module so both the auth routes and tests agree on the shape without
// importing nuxt internals.
export interface ConsoleRuntimeConfig {
  console: {
    password: string
    sessionHours: number
    loginMaxAttempts: number
    loginWindowSeconds: number
    cookieSecure: boolean
  }
}
