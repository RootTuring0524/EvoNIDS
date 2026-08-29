import type { ZodType } from 'zod'

export async function validatedFetch<T>(path: string, schema: ZodType<T>, options?: Record<string, unknown>) {
  const config = useRuntimeConfig()
  // useRequestFetch forwards the incoming request cookies during SSR so
  // authenticated console sessions survive server-side data fetching.
  const requestFetch = useRequestFetch()
  const payload = await requestFetch(`${config.public.apiBase}${path}`, options)
  return schema.parse(payload)
}
