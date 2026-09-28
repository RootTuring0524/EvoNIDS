<script setup lang="ts">
import { keepPreviousData, useQuery } from '@tanstack/vue-query'
import { Share2, Search } from '~/utils/icons'
import { entitiesResponseSchema, type EntitiesApiResponse } from '~~/shared/schemas/security'

const search = ref('')
const debouncedSearch = refDebounced(search, 260)
const page = ref(1)
const pageSize = ref(25)

const entitiesQuery = useQuery({
  queryKey: computed(() => ['entities', debouncedSearch.value, page.value, pageSize.value]),
  queryFn: () => validatedFetch<EntitiesApiResponse>('/entities', entitiesResponseSchema, {
    query: { entityType: 'ip', search: debouncedSearch.value, page: page.value, pageSize: pageSize.value },
  }),
  placeholderData: keepPreviousData,
})

const rows = computed(() => entitiesQuery.data.value?.items ?? [])
const total = computed(() => entitiesQuery.data.value?.total ?? 0)
const demoHint = computed(() => useRuntimeConfig().public.useMockApi ? '演示模式：实体为空（实体由真实事件自动发现）' : '')
</script>

<template>
  <div class="p-6 space-y-5">
    <header>
      <h1 class="text-xl font-semibold flex items-center gap-2"><Share2 :size="20" /> 实体图谱</h1>
      <p v-if="demoHint" class="text-sm text-amber-300/80 mt-1">{{ demoHint }}</p>
      <p v-else class="text-sm opacity-60 mt-1">摄取事件中自动发现的 IP 实体与通信关系</p>
    </header>

    <div class="relative max-w-md">
      <Search class="absolute left-2.5 top-2.5 opacity-50" :size="16" />
      <input v-model="search" class="w-full rounded-lg border border-current/10 bg-transparent pl-9 pr-3 py-2 text-sm outline-none" placeholder="搜索 IP…">
    </div>

    <div v-if="entitiesQuery.isPending.value" class="text-sm opacity-60 py-10 text-center">加载中…</div>
    <div v-else-if="entitiesQuery.isError.value" class="text-sm text-red-300 py-10 text-center">加载失败：{{ entitiesQuery.error.value?.message }}</div>
    <div v-else-if="rows.length === 0" class="text-sm opacity-60 py-10 text-center">暂无实体</div>
    <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      <NuxtLink v-for="row in rows" :key="row.id" :to="`/entities/${row.id}`" class="rounded-xl border border-current/10 p-4 hover:border-current/25 transition-colors block">
        <div class="font-mono text-sm">{{ row.value }}</div>
        <div class="text-xs opacity-60 mt-2">{{ row.eventCount }} 次出现 · 传感器 {{ row.sensorIds.length }} 个</div>
        <div class="text-xs opacity-50 mt-1">最近：{{ new Date(row.lastSeenAt).toLocaleString() }}</div>
      </NuxtLink>
    </div>
    <div v-if="total > pageSize" class="flex justify-between text-sm opacity-70 pt-2">
      <button class="disabled:opacity-40" :disabled="page <= 1" @click="page -= 1">上一页</button>
      <span>第 {{ page }} 页 / 共 {{ total }} 条</span>
      <button class="disabled:opacity-40" :disabled="page * pageSize >= total" @click="page += 1">下一页</button>
    </div>
  </div>
</template>
