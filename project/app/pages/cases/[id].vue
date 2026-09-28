<script setup lang="ts">
import { keepPreviousData, useQuery } from '@tanstack/vue-query'
import { ArrowLeft, Link2, Unlink, RefreshCw, Sparkles } from '~/utils/icons'
import { caseDetailSchema, caseRecordSchema, caseSuggestionResponseSchema } from '~~/shared/schemas/security'
import type { Alert, CaseStatus } from '~~/shared/types/security'

const route = useRoute()
const router = useRouter()
const caseId = computed(() => String(route.params.id ?? ''))
const toast = reactive({ open: false, title: '', description: '', tone: 'success' as 'success' | 'error' })
const attachAlertId = ref('')
const suggestAlertId = ref('')
const updating = ref(false)
const detailVersion = ref(0)

const { data: detail, isPending, isError, error, refetch } = useQuery({
  queryKey: computed(() => ['case-detail', caseId.value, detailVersion.value]),
  queryFn: () => validatedFetch('/cases/' + encodeURIComponent(caseId.value), caseDetailSchema),
})

const detailData = computed(() => detail.value)

const suggestionsQuery = useQuery({
  queryKey: computed(() => ['case-suggestions', suggestAlertId.value, detailVersion.value]),
  queryFn: () => (suggestAlertId.value ? validatedFetch('/cases/suggestions', caseSuggestionResponseSchema, { query: { alertId: suggestAlertId.value } }) : Promise.resolve({ items: [] })),
  placeholderData: keepPreviousData,
})

const statusLabels: Record<CaseStatus, string> = {
  open: '待处理', investigating: '调查中', contained: '已遏制', closed: '已关闭', archived: '已归档',
}
const severityTone: Record<string, string> = {
  critical: 'text-red-300 bg-red-500/10 border-red-500/30',
  high: 'text-orange-300 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
}
const nextTransition = ref<{ status: CaseStatus; note: string }>({ status: 'open', note: '' })
const allowedTargets = computed<CaseStatus[]>(() => {
  const current = detailData.value?.case.status
  if (current === 'open') return ['investigating']
  if (current === 'investigating') return ['open', 'contained', 'closed']
  if (current === 'contained') return ['investigating', 'closed']
  if (current === 'closed') return ['investigating', 'archived']
  return []
})

function showToast(title: string, tone: 'success' | 'error', description = '') {
  toast.title = title
  toast.tone = tone
  toast.description = description
  toast.open = true
}

async function run(action: () => Promise<unknown>, okText: string) {
  updating.value = true
  try {
    await action()
    showToast(okText, 'success')
    detailVersion.value += 1
  } catch (error: any) {
    showToast('操作失败', 'error', error?.data?.statusMessage || String(error))
  } finally {
    updating.value = false
  }
}

function updateStatus() {
  const target = nextTransition.value.status
  const requiresNote = ['contained', 'closed', 'archived'].includes(target)
  if (requiresNote && nextTransition.value.note.trim().length < 10) {
    showToast('此状态变更需要至少 10 字的备注', 'error')
    return
  }
  const path: string = '/cases/' + encodeURIComponent(caseId.value)
  run(() => validatedFetch(path, caseRecordSchema, {
    method: 'PATCH',
    body: { status: target, note: nextTransition.value.note.trim() || undefined },
  }), '状态已更新')
}

function attachAlert() {
  const alertId = attachAlertId.value.trim()
  if (!alertId) return
  const path: string = `/cases/${encodeURIComponent(caseId.value)}/alerts`
  run(() => validatedFetch(path, caseRecordSchema, { method: 'POST', body: { alertId } }), '告警已加入案件')
  attachAlertId.value = ''
}

function detachAlert(alertId: string) {
  const path: string = `/cases/${encodeURIComponent(caseId.value)}/alerts/${encodeURIComponent(alertId)}`
  run(() => validatedFetch(path, caseRecordSchema, { method: 'DELETE' }), '告警已摘除')
}

function attachSuggested(alertId: string | undefined) {
  if (!alertId) return
  const path: string = `/cases/${encodeURIComponent(caseId.value)}/alerts`
  run(() => validatedFetch(path, caseRecordSchema, { method: 'POST', body: { alertId } }), '建议告警已加入')
}

function alertSeverityClass(alert: Alert) {
  return alert.severity === 'critical' || alert.severity === 'high' ? 'text-orange-300' : 'text-yellow-300'
}
</script>

<template>
  <div class="p-6 space-y-5">
    <header class="flex items-center gap-3">
      <button class="rounded-lg border border-current/10 p-2 hover:border-current/30" aria-label="返回案件列表" @click="router.push('/cases')">
        <ArrowLeft :size="16" />
      </button>
      <div>
        <h1 class="text-xl font-semibold">{{ detailData?.case.title ?? '案件详情' }}</h1>
        <p class="text-xs opacity-60 mt-0.5">{{ caseId }}</p>
      </div>
      <div v-if="detailData" class="ml-auto flex items-center gap-2">
        <span class="text-xs px-2 py-0.5 rounded-full border" :class="severityTone[detailData.case.severity]">{{ detailData.case.severity }}</span>
        <span class="text-xs px-2 py-0.5 rounded-full border border-current/20">{{ statusLabels[detailData.case.status] }}</span>
      </div>
      <button class="rounded-lg border border-current/10 p-2 hover:border-current/30" aria-label="刷新" @click="refetch()">
        <RefreshCw :size="16" />
      </button>
    </header>

    <div v-if="isPending" class="py-10 text-center text-sm opacity-60">加载中…</div>
    <div v-else-if="isError" class="py-10 text-center text-sm text-red-300">加载失败：{{ error?.message }}</div>
    <template v-else-if="detailData">
      <section class="rounded-xl border border-current/10 p-4 space-y-4">
        <div class="grid gap-4 md:grid-cols-2">
          <div>
            <p class="text-sm opacity-70 whitespace-pre-wrap">{{ detailData.case.summary || '（无摘要）' }}</p>
            <p class="text-xs opacity-50 mt-2">创建：{{ detailData.case.createdBy }} · {{ new Date(detailData.case.createdAt).toLocaleString() }} · 更新：{{ new Date(detailData.case.updatedAt).toLocaleString() }}</p>
          </div>
          <div class="space-y-3">
            <div>
              <label class="text-xs opacity-70 block mb-1">变更状态（备注在遏制/关闭/归档时必填）</label>
              <div class="flex gap-2 flex-wrap">
                <select v-model="nextTransition.status" class="rounded-lg border border-current/10 bg-transparent px-2 py-1.5 text-sm outline-none">
                  <option v-for="target in allowedTargets" :key="target" :value="target">{{ statusLabels[target] }}</option>
                </select>
                <input v-model="nextTransition.note" class="flex-1 min-w-40 rounded-lg border border-current/10 bg-transparent px-3 py-1.5 text-sm outline-none" placeholder="处置备注…" maxlength="2000">
                <button class="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm disabled:opacity-60" :disabled="updating || allowedTargets.length === 0" @click="updateStatus">更新</button>
              </div>
            </div>
            <div>
              <label class="text-xs opacity-70 block mb-1">按 alertId 关联告警</label>
              <div class="flex gap-2">
                <input v-model="attachAlertId" class="flex-1 rounded-lg border border-current/10 bg-transparent px-3 py-1.5 text-sm outline-none" placeholder="例如 ALT-XXXXXXXX" maxlength="96">
                <button class="px-3 py-1.5 rounded-lg border border-current/20 text-sm inline-flex items-center gap-1.5 disabled:opacity-60" :disabled="updating || !attachAlertId.trim()" @click="attachAlert">
                  <Link2 :size="14" /> 关联
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="rounded-xl border border-current/10 p-4 space-y-3">
        <h2 class="font-semibold flex items-center gap-2"><Sparkles :size="16" /> 关联建议（按 alertId 查询开放案件）</h2>
        <div class="flex gap-2">
          <input v-model="suggestAlertId" class="flex-1 rounded-lg border border-current/10 bg-transparent px-3 py-1.5 text-sm outline-none" placeholder="输入告警 ID 查看应归入哪些开放案件…" maxlength="96">
        </div>
        <div v-if="suggestAlertId" class="space-y-2">
          <div v-for="suggestion in suggestionsQuery.data.value?.items ?? []" :key="suggestion.caseId" class="rounded-lg border border-current/10 p-3 flex items-center justify-between gap-3">
            <div>
              <NuxtLink :to="`/cases/${suggestion.caseId}`" class="font-medium hover:underline">{{ suggestion.caseTitle }}</NuxtLink>
              <p class="text-xs opacity-60 mt-1">共享端点：{{ suggestion.sharedIps.join(', ') }} · 匹配 {{ suggestion.matchingAlertIds.length }} 条告警</p>
            </div>
            <button v-if="suggestion.caseId !== caseId" class="px-2.5 py-1 rounded-lg border border-current/20 text-xs disabled:opacity-60" :disabled="updating" @click="attachSuggested(suggestion.matchingAlertIds[0])">加入此案件</button>
            <span v-else class="text-xs opacity-50">当前案件</span>
          </div>
        </div>
      </section>

      <section class="rounded-xl border border-current/10 p-4 space-y-3">
        <h2 class="font-semibold flex items-center gap-2"><Link2 :size="16" /> 关联告警（{{ detailData.alerts.length }}）</h2>
        <div v-if="detailData.alerts.length === 0" class="text-sm opacity-60 py-4 text-center">尚未关联告警</div>
        <div v-else class="space-y-2">
          <div v-for="alert in detailData.alerts" :key="alert.id" class="rounded-lg border border-current/10 p-3 flex items-center justify-between gap-3">
            <div class="min-w-0">
              <NuxtLink :to="`/alerts/${alert.id}`" class="hover:underline">
                <span :class="alertSeverityClass(alert)">{{ alert.severity }}</span>
                <span class="ml-2 text-sm font-medium">{{ alert.title }}</span>
              </NuxtLink>
              <p class="text-xs opacity-60 mt-1">{{ alert.sourceIp }} → {{ alert.destinationIp }}:{{ alert.destinationPort }} · {{ alert.detector }}</p>
            </div>
            <button class="shrink-0 rounded-lg border border-current/20 p-1.5 opacity-70 hover:opacity-100 disabled:opacity-40" :disabled="updating" :aria-label="`摘除 ${alert.id}`" @click="detachAlert(alert.id)">
              <Unlink :size="14" />
            </button>
          </div>
        </div>
      </section>

      <section class="rounded-xl border border-current/10 p-4 space-y-3">
        <h2 class="font-semibold">时间线</h2>
        <ol v-if="detailData.timeline.length" class="space-y-2">
          <li v-for="event in detailData.timeline" :key="event.id" class="flex gap-3 text-sm">
            <span class="opacity-40 mt-0.5">▸</span>
            <div>
              <span class="opacity-80">{{ event.eventType }}</span>
              <span class="opacity-50 ml-2">· {{ event.actor }}</span>
              <p v-if="event.note" class="text-xs opacity-70 mt-0.5">{{ event.note }}</p>
              <p class="text-xs opacity-40 mt-0.5">{{ new Date(event.createdAt).toLocaleString() }}</p>
            </div>
          </li>
        </ol>
        <p v-else class="text-sm opacity-60 py-2">（空）</p>
      </section>
    </template>
  </div>
</template>
