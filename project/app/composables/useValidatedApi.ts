import type { ZodType } from 'zod'

export async function validatedFetch<T>(path: string, schema: ZodType<T>, options?: Record<string, unknown>) {
  const config = useRuntimeConfig()
  const payload = await $fetch(`${config.public.apiBase}${path}`, options)
  return schema.parse(payload)
}
