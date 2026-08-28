import { z } from 'zod'

const modelsEnvelopeSchema = z.object({
  data: z.array(z.object({ id: z.string().min(1) })),
})

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig(event)
  const useMockApi = Boolean(config.public.useMockApi)
  if (useMockApi) {
    return {
      status: 'mock' as const,
      latencyMs: 0,
      checkedAt: new Date().toISOString(),
      message: '当前为显式 Mock 模式，未连接或探测任何外部模型服务。',
    }
  }
  if (!config.deepseek.apiBase || !config.deepseek.apiKey || !config.deepseek.model) {
    return {
      status: 'missing' as const,
      latencyMs: 0,
      checkedAt: new Date().toISOString(),
      message: '真实模式缺少 API Base、API Key 或 Model ID。',
    }
  }

  const started = performance.now()
  try {
    const base = config.deepseek.apiBase.replace(/\/+$/, '')
    const response = await $fetch(`${base}/models`, {
      method: 'GET',
      headers: { authorization: `Bearer ${config.deepseek.apiKey}`, accept: 'application/json' },
      timeout: 8_000,
      retry: 0,
    })
    const parsed = modelsEnvelopeSchema.safeParse(response)
    const latencyMs = Math.round(performance.now() - started)
    if (!parsed.success) {
      return {
        status: 'unavailable' as const,
        latencyMs,
        checkedAt: new Date().toISOString(),
        message: '上游已响应，但模型列表不符合预期契约。',
      }
    }
    const available = parsed.data.data.some((model) => model.id === config.deepseek.model)
    return {
      status: available ? 'ready' as const : 'model_missing' as const,
      latencyMs,
      checkedAt: new Date().toISOString(),
      message: available
        ? '已通过上游 /models 接口验证凭据与目标模型可用。'
        : '凭据有效，但配置的 Model ID 不在上游可用模型列表中。',
    }
  } catch {
    return {
      status: 'unavailable' as const,
      latencyMs: Math.round(performance.now() - started),
      checkedAt: new Date().toISOString(),
      message: '无法在 8 秒内完成上游模型列表验证；未暴露认证信息或上游响应体。',
    }
  }
})
