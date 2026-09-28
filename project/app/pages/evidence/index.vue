<script setup lang="ts">
import { keepPreviousData, useQuery } from '@tanstack/vue-query'
import { DatabaseZap, Search, FileJson2 } from '~/utils/icons'
import { evidenceDetailSchema, evidenceListResponseSchema, type EvidenceListApiResponse } from '~~/shared/schemas/security'
import type { EvidenceRecord } from '~~/shared/types/security'

const search = ref('')
const debouncedHash = refDebounced(search, 300)
const sensorId = ref('')
const page = ref(1)
const pageSize = ref(25)
const selected = ref<EvidenceRecord | null>(null)
const detailOpen = ref(false)
const detailData = ref<any>(null)
const detailError = ref('')
const detailLoading = ref(false)

const evidenceQuery = useQuery({
  queryKey: computed(() => ['evidence', debouncedHash.value, sensorId.value, page.value, pageSize.value]),
  queryFn: () => validatedFetch<EvidenceListApiResponse>('/evidence', evidenceListResponseSchema, {
    query: {
      contentSha256: debouncedHash.value,
      sensorId: sensorId.value,
      page: page.value,
      pageSize: pageSize.value,
    },
  }),
  placeholderData: keepPreviousData,
})

const rows = computed(() => evidenceQuery.data.value?.items ?? [])
const total = computed(() => evidenceQuery.data.value?.total ?? 0)
const demoHint = computed(() => useRuntimeConfig().public.useMockApi ? '演示模式：证据为空（证据由真实摄取生成）' : '')

async function openDetail(row: EvidenceRecord) {
  selected.value = row
  detailOpen.value = true
  detailData.value = null
  detailError.value = ''
  detailLoading.value = true
  try {
    detailData.value = await validatedFetch('/evidence/' + encodeURIComponent(row.id), evidenceDetailSchema)
  } catch (error: any) {
    detailError.value = error?.data?.statusMessage || String(error)
  } finally {
    detailLoading.value = false
  }
}

function refLink(row: EvidenceRecord) {
  return row.sourceRefType === 'alert' ? `/alerts/${row.sourceRefId}` : null
}
</script>

<template>
  <div class="p-6 space-y-5">
    <header>
      <h1 class="text-xl font-semibold flex items-center gap-2"><DatabaseZap :size="20" /> 证据检索</h1>
      <p v-if="demoHint" class="text-sm text-amber-300/80 mt-1">{{ demoHint }}</p>
      <p v-else class="text-sm opacity-60 mt-1">摄取事件原文的哈希登记与原始工件（原文需管理员）</p>
    </header>

    <div class="flex flex-wrap gap-3">
      <div class="relative min-w-72">
        <Search class="absolute left-2.5 top-2.5 opacity-50" :size="16" />
        <input v-model="search" class="w-full rounded-lg border border-current/10 bg-transparent pl-9 pr-3 py-2 text-sm outline-none" placeholder="按内容 SHA-256 检索…">
      </div>
      <input v-model="sensorId" class="rounded-lg border border-current/10 bg-transparent px-3 py-2 text-sm outline-none w-56" placeholder="传感器 ID…">
    </div>

    <div v-if="evidenceQuery.isPending.value" class="text-sm opacity-60 py-10 text-center">加载中…</div>
    <div v-else-if="evidenceQuery.isError.value" class="text-sm text-red-300 py-10 text-center">加载失败：{{ evidenceQuery.error.value?.message }}</div>
    <div v-else-if="rows.length === 0" class="text-sm opacity-60 py-10 text-center">暂无证据</div>
    <div v-else class="overflow-x-auto rounded-xl border border-current/10">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left opacity-60 border-b border-current/10">
            <th class="p-3 font-medium">ID</th>
            <th class="p-3 font-medium">类型</th>
            <th class="p-3 font-medium">事件时间</th>
            <th class="p-3 font-medium">哈希</th>
            <th class="p-3 font-medium">完整性</th>
            <th class="p-3 font-medium">原始字节</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id" class="border-b border-current/5 hover:bg-current/5 cursor-pointer" @click="openDetail(row)">
            <td class="p-3 font-mono text-xs">{{ row.id }}</td>
            <td class="p-3">{{ row.eventType }}</td>
            <td class="p-3 text-xs opacity-70">{{ new Date(row.observedAt).toLocaleString() }}</td>
            <td class="p-3 font-mono text-xs opacity-80">{{ row.contentSha256.slice(0, 16) }}…</td>
            <td class="p-3">
              <span :class="row.integrity === 'complete' ? 'text-emerald-300' : 'text-amber-300'">{{ row.integrity }}</span>
              <span v-if="row.dataMissing !== 'none'" class="text-amber-300/70"> ({{ row.dataMissing }})</span>
            </td>
            <td class="p-3 text-xs opacity-60">{{ row.artifactSizeBytes }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="total > pageSize" class="flex justify-between text-sm opacity-70 pt-2">
      <button class="disabled:opacity-40" :disabled="page <= 1" @click="page -= 1">上一页</button>
      <span>第 {{ page }} 页 / 共 {{ total }} 条</span>
      <button class="disabled:opacity-40" :disabled="page * pageSize >= total" @click="page += 1">下一页</button>
    </div>

    <div v-if="detailOpen" class="fixed inset-0 z-50 flex items-start justify-end bg-black/60 p-4" role="dialog" aria-modal="true" @click.self="detailOpen = false">
      <div class="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl border border-current/15 bg-[#0d1117] p-5 space-y-4">
        <div class="flex items-center justify-between gap-3">
          <h2 class="font-semibold flex items-center gap-2"><FileJson2 :size="18" /> {{ selected?.id }}</h2>
          <button class="opacity-60 hover:opacity-100" aria-label="关闭" @click="detailOpen = false">×</button>
        </div>
        <div v-if="detailLoading" class="text-sm opacity-60 py-6 text-center">加载原文…</div>
        <div v-else-if="detailError" class="text-sm text-red-300">无法读取原文（可能需要管理员凭据）：{{ detailError }}</div>
        <div v-else-if="detailData" class="space-y-4">
          <dl class="grid gap-2 text-sm md:grid-cols-2">
            <div><dt class="opacity-50 text-xs">传感器</dt><dd class="font-mono">{{ detailData.sensorId }}</dd></div>
            <div><dt class="opacity-50 text-xs">外部 ID</dt><dd class="font-mono">{{ detailData.externalId }}</dd></div>
            <div><dt class="opacity-50 text-xs">SHA-256</dt><dd class="font-mono text-xs break-all">{{ detailData.contentSha256 }}</dd></div>
            <div><dt class="opacity-50 text-xs">解析器</dt><dd class="font-mono">{{ detailData.parserVersion }}</dd></div>
          </dl>
          <div v-if="refLink(detailData)" class="text-sm">
            <NuxtLink :to="refLink(detailData)!" class="text-blue-300 hover:underline">→ 查看来源告警</NuxtLink>
          </div>
          <div>
            <p class="opacity-50 text-xs mb-1">原始事件文本</p>
            <pre class="rounded-lg bg-black/40 border border-current/10 p-3 text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">{{ detailData.artifactText || '（未存储原文——超过 1 MiB 或已截断）' }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
