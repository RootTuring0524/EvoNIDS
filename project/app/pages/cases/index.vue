<script setup lang="ts">
import { keepPreviousData, useQuery } from '@tanstack/vue-query'
import { FolderKanban, Plus, Search } from '~/utils/icons'
import { casesResponseSchema, type CasesApiResponse } from '~~/shared/schemas/security'
import type { CaseSeverity, CaseStatus } from '~~/shared/types/security'

const search = ref('')
const debouncedSearch = refDebounced(search, 260)
const severity = ref('all')
const status = ref('all')
const page = ref(1)
const pageSize = ref(25)
const toast = reactive({ open: false, title: '', description: '', tone: 'success' as 'success' | 'error' })
const createOpen = ref(false)
const creating = ref(false)
const createForm = reactive({ title: '', summary: '', severity: 'medium' as CaseSeverity })

const casesQuery = useQuery({
  queryKey: computed(() => ['cases', severity.value, status.value, debouncedSearch.value, page.value, pageSize.value]),
  queryFn: () => validatedFetch<CasesApiResponse>('/cases', casesResponseSchema, {
    query: {
      severity: severity.value,
      status: status.value,
      search: debouncedSearch.value,
      page: page.value,
      pageSize: pageSize.value,
    },
  }),
  placeholderData: keepPreviousData,
})

const rows = computed(() => casesQuery.data.value?.items ?? [])
const total = computed(() => casesQuery.data.value?.total ?? 0)

const statusLabels: Record<CaseStatus, string> = {
  open: '待处理', investigating: '调查中', contained: '已遏制', closed: '已关闭', archived: '已归档',
}
const severityTone: Record<CaseSeverity, string> = {
  critical: 'text-red-300 bg-red-500/10 border-red-500/30',
  high: 'text-orange-300 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
}

async function createCase() {
  if (createForm.title.trim().length < 3) {
    toast.title = '案件标题至少 3 个字符'
    toast.tone = 'error'
    toast.open = true
    return
  }
  creating.value = true
  try {
    const url: string = '/api/cases'
    await $fetch(url, {
      method: 'POST',
      body: { title: createForm.title.trim(), summary: createForm.summary.trim(), severity: createForm.severity },
    })
    createOpen.value = false
    createForm.title = ''
    createForm.summary = ''
    toast.title = '案件已创建'
    toast.tone = 'success'
    toast.open = true
    await casesQuery.refetch()
  } catch (error: any) {
    toast.title = '创建失败'
    toast.description = error?.data?.statusMessage || String(error)
    toast.tone = 'error'
    toast.open = true
  } finally {
    creating.value = false
  }
}

const demoHint = computed(() => useRuntimeConfig().public.useMockApi ? '演示模式：案件列表为空（案件仅真实后端可用）' : '')
</script>

<template>
  <div class="p-6 space-y-5">
    <header class="flex items-center justify-between gap-3">
      <div>
        <h1 class="text-xl font-semibold flex items-center gap-2"><FolderKanban :size="20" /> 案件工作台</h1>
        <p v-if="demoHint" class="text-sm text-amber-300/80 mt-1">{{ demoHint }}</p>
        <p v-else class="text-sm opacity-60 mt-1">将相关告警聚合为调查单元，跟踪处置状态与时间线</p>
      </div>
      <button class="px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm inline-flex items-center gap-2 disabled:opacity-60" :disabled="creating" @click="createOpen = true">
        <Plus :size="16" /> 新建案件
      </button>
    </header>

    <div class="flex flex-wrap items-center gap-3">
      <div class="relative min-w-56">
        <Search class="absolute left-2.5 top-2.5 opacity-50" :size="16" />
        <input v-model="search" class="w-full rounded-lg border border-current/10 bg-transparent pl-9 pr-3 py-2 text-sm outline-none" placeholder="搜索案件标题…" >
      </div>
      <select v-model="severity" class="rounded-lg border border-current/10 bg-transparent px-3 py-2 text-sm outline-none">
        <option value="all">全部等级</option>
        <option value="critical">严重</option>
        <option value="high">高危</option>
        <option value="medium">中危</option>
        <option value="low">低危</option>
      </select>
      <select v-model="status" class="rounded-lg border border-current/10 bg-transparent px-3 py-2 text-sm outline-none">
        <option value="all">全部状态</option>
        <option v-for="(label, key) in statusLabels" :key="key" :value="key">{{ label }}</option>
      </select>
    </div>

    <div v-if="casesQuery.isPending.value" class="text-sm opacity-60 py-10 text-center">加载中…</div>
    <div v-else-if="casesQuery.isError.value" class="text-sm text-red-300 py-10 text-center">加载失败：{{ casesQuery.error.value?.message }}</div>
    <div v-else-if="rows.length === 0" class="text-sm opacity-60 py-10 text-center">暂无案件。从告警研判页选择告警后在此建案。</div>
    <div v-else class="space-y-3">
      <NuxtLink v-for="row in rows" :key="row.id" :to="`/cases/${row.id}`" class="block rounded-xl border border-current/10 p-4 hover:border-current/25 transition-colors">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-xs px-2 py-0.5 rounded-full border" :class="severityTone[row.severity]">{{ row.severity }}</span>
              <span class="text-sm font-medium truncate">{{ row.title }}</span>
            </div>
            <p v-if="row.summary" class="text-sm opacity-70 mt-1 line-clamp-2">{{ row.summary }}</p>
          </div>
          <div class="text-right shrink-0">
            <div class="text-sm">{{ statusLabels[row.status] }}</div>
            <div class="text-xs opacity-60 mt-1">{{ row.alertCount }} 告警 · 风险 {{ row.highestRiskScore.toFixed(0) }}</div>
          </div>
        </div>
        <div class="text-xs opacity-50 mt-2">更新于 {{ new Date(row.updatedAt).toLocaleString() }} · {{ row.createdBy }}</div>
      </NuxtLink>
      <div class="flex justify-between text-sm opacity-70 pt-2">
        <button class="disabled:opacity-40" :disabled="page <= 1" @click="page -= 1">上一页</button>
        <span>第 {{ page }} 页 / 共 {{ total }} 条</span>
        <button class="disabled:opacity-40" :disabled="page * pageSize >= total" @click="page += 1">下一页</button>
      </div>
    </div>

    <div v-if="createOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true">
      <div class="w-full max-w-md rounded-xl border border-current/15 bg-[#0d1117] p-5 space-y-4">
        <h2 class="font-semibold">新建案件</h2>
        <div>
          <label class="text-xs opacity-70 block mb-1">标题（必填）</label>
          <input v-model="createForm.title" class="w-full rounded-lg border border-current/10 bg-transparent px-3 py-2 text-sm outline-none" maxlength="255" >
        </div>
        <div>
          <label class="text-xs opacity-70 block mb-1">摘要</label>
          <textarea v-model="createForm.summary" class="w-full rounded-lg border border-current/10 bg-transparent px-3 py-2 text-sm outline-none" rows="3" maxlength="4000"/>
        </div>
        <div>
          <label class="text-xs opacity-70 block mb-1">等级</label>
          <select v-model="createForm.severity" class="w-full rounded-lg border border-current/10 bg-transparent px-3 py-2 text-sm outline-none">
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
        </div>
        <div class="flex justify-end gap-3">
          <button class="px-3 py-2 rounded-lg border border-current/10 text-sm" @click="createOpen = false">取消</button>
          <button class="px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm disabled:opacity-60" :disabled="creating" @click="createCase">创建</button>
        </div>
      </div>
    </div>

    <div v-if="toast.open" class="fixed bottom-4 right-4 z-50 rounded-lg px-4 py-3 text-sm border" :class="toast.tone === 'error' ? 'border-red-500/40 text-red-200 bg-[#1a0d0f]' : 'border-emerald-500/40 text-emerald-200 bg-[#0a1410]'" role="status">
      <b>{{ toast.title }}</b><span v-if="toast.description">：{{ toast.description }}</span>
      <button class="ml-3 opacity-60" @click="toast.open = false">×</button>
    </div>
  </div>
</template>
