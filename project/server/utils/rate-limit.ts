// In-memory sliding-window rate limiter for console login attempts.
//
// Pure logic (no h3/Nuxt imports) so it is unit-testable in isolation. Buckets
// are keyed per caller-supplied key (the client IP). Deliberately process-local:
// the console runs as a single Nuxt server instance in the supported
// deployments; multi-instance deployments must move this behind a shared store.

export interface RateLimitDecision {
  allowed: boolean
  retryAfterSeconds: number
  attempts: number
}

interface Bucket {
  attempts: number[]
  lockedUntil: number | null
}

export function createSlidingWindowLimiter(maxAttempts: number, windowMs: number) {
  const buckets = new Map<string, Bucket>()
  const now = () => Date.now()

  const prune = (bucket: Bucket, at: number) => {
    const cutoff = at - windowMs
    bucket.attempts = bucket.attempts.filter((timestamp) => timestamp > cutoff)
  }

  return {
    check(key: string): RateLimitDecision {
      const at = now()
      let bucket = buckets.get(key)
      if (bucket === undefined) {
        bucket = { attempts: [], lockedUntil: null }
        buckets.set(key, bucket)
      }
      prune(bucket, at)
      if (bucket.lockedUntil !== null) {
        if (at < bucket.lockedUntil) {
          return {
            allowed: false,
            retryAfterSeconds: Math.ceil((bucket.lockedUntil - at) / 1000),
            attempts: bucket.attempts.length,
          }
        }
        bucket.lockedUntil = null
      }
      return {
        allowed: bucket.attempts.length < maxAttempts,
        retryAfterSeconds: 0,
        attempts: bucket.attempts.length,
      }
    },
    recordFailure(key: string): void {
      const at = now()
      let bucket = buckets.get(key)
      if (bucket === undefined) {
        bucket = { attempts: [], lockedUntil: null }
        buckets.set(key, bucket)
      }
      prune(bucket, at)
      bucket.attempts.push(at)
      if (bucket.attempts.length >= maxAttempts) {
        bucket.lockedUntil = at + windowMs
      }
    },
    recordSuccess(key: string): void {
      buckets.delete(key)
    },
    clear(): void {
      buckets.clear()
    },
  }
}
