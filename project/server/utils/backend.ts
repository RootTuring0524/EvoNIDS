import type { H3Event } from 'h3'
import { ofetch, type FetchOptions } from 'ofetch'

interface BackendFetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  query?: FetchOptions['query']
  body?: FetchOptions['body']
  headers?: Record<string, string>
  admin?: boolean
}

function backendUrl(base: string, path: string) {
  const normalizedBase = base.replace(/\/+$/, '')
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  return `${normalizedBase}${normalizedPath}`
}

export function usesMockApi(event: H3Event) {
  return useRuntimeConfig(event).public.useMockApi
}

export async function fetchBackend<T>(
  event: H3Event,
  path: string,
  options: BackendFetchOptions = {},
): Promise<T> {
  const config = useRuntimeConfig(event)
  const requestId = getHeader(event, 'x-request-id') || crypto.randomUUID()
  if (options.admin && !config.backend.adminToken) {
    throw createError({
      statusCode: 503,
      statusMessage: 'Administrative writes require NUXT_BACKEND_ADMIN_TOKEN on the Nuxt server',
      data: { requestId },
    })
  }

  try {
    return await ofetch<T>(backendUrl(config.backend.apiBase, path), {
      method: options.method || 'GET',
      query: options.query,
      body: options.body,
      headers: {
        'x-request-id': requestId,
        accept: 'application/json',
        ...(options.admin ? { 'x-evonids-admin-token': config.backend.adminToken } : {}),
        ...options.headers,
      },
      retry: 0,
      timeout: 10_000,
    })
  } catch (error) {
    const statusCode =
      typeof error === 'object' && error && 'statusCode' in error && typeof error.statusCode === 'number'
        ? error.statusCode
        : 502
    const safeStatus = statusCode >= 400 && statusCode < 500 ? statusCode : 502
    throw createError({
      statusCode: safeStatus,
      statusMessage:
        safeStatus === 502
          ? 'EvoNIDS backend is unavailable'
          : 'The EvoNIDS backend rejected the request',
      data: { requestId },
    })
  }
}
