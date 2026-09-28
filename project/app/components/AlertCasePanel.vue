<script setup lang="ts">
import { ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { FolderKanban, Link2, Plus, RefreshCw } from '~/utils/icons'
import { caseRecordSchema, caseSuggestionResponseSchema } from '~~/shared/schemas/security'

const props = defineProps<{ alertId: string; alertTitle: string }>()

const open = ref(false)
const busy = ref(false)
const message = ref('')
const tone = ref<'ok' | 'err'>('ok')
const version = ref(0)
const createOpen = ref(false)
const createTitle = ref('')
const creating = ref(false)

const { data: suggestions, refetch } = useQuery({
  queryKey: computed(() => ['alert-case-suggestions', props.alertId, version.value]),
  queryFn: () =>
    open.value
      ? validatedFetch('/cases/suggestions', caseSuggestionResponseSchema, { query: { alertId: props.alertId } })
      : Promise.resolve({ items: [] }),
})

function toast(text: string, ok = true) {
  message.value = text
  tone.value = ok ? 'ok' : 'err'
  window.setTimeout(() => { message.value = '' }, 3200)
}

async function attachToCase(caseId: string, alertId: string) {
  busy.value = true
  try {
    const path: string = `/cases/${encodeURIComponent(caseId)}/alerts`
    await validatedFetch(path, caseRecordSchema, { method: 'POST', body: { alertId } })
    toast('已加入案件 ' + caseId)
    version.value += 1
  } catch (error: any) {
    toast(error?.data?.statusMessage || String(error), false)
  } finally {
    busy.value = false
  }
}

async function createAndAttach() {
  const title = (createTitle.value || props.alertTitle).trim().slice(0, 255)
  if (title.length < 3) {
    toast('案件标题至少 3 个字符', false)
    return
  }
  creating.value = true
  try {
    const createdPath: string = '/cases'
    const created = await validatedFetch(createdPath, caseRecordSchema, {
      method: 'POST',
      body: { title, summary: `由告警 ${props.alertId} 触发创建`, severity: 'medium' },
    })
    createOpen.value = false
    createTitle.value = ''
    await attachToCase(created.id, props.alertId)
  } catch (error: any) {
    toast(error?.data?.statusMessage || String(error), false)
  } finally {
    creating.value = false
  }
}
</script>

<template>
  <section class="case-panel surface-panel">
    <div class="case-panel-head">
      <button class="case-toggle" @click="open = !open">
        <FolderKanban :size="14" /> {{ open ? '收起案件联动' : '归入案件 / 关联建议' }}
      </button>
      <button v-if="open" class="case-icon-btn" aria-label="刷新建议" @click="refetch()"><RefreshCw :size="13" /></button>
    </div>

    <div v-if="message" class="case-toast" :class="tone === 'err' ? 'err' : 'ok'" role="status">{{ message }}</div>

    <div v-if="open" class="case-panel-body">
      <button class="case-create-btn" :disabled="creating" @click="createOpen = !createOpen">
        <Plus :size="13" /> {{ createOpen ? '取消新建' : '以此告警新建案件' }}
      </button>
      <div v-if="createOpen" class="case-create-form">
        <input v-model="createTitle" class="case-input" maxlength="255" :placeholder="`案件标题（默认：${alertTitle.slice(0, 60)}…）`">
        <button class="case-primary" :disabled="creating" @click="createAndAttach">创建并关联</button>
      </div>

      <p v-if="(suggestions?.items?.length ?? 0) === 0" class="case-empty">没有命中开放案件的相关建议（将按共享源/目的端点匹配）</p>
      <div v-else class="case-suggestions">
        <div v-for="suggestion in suggestions?.items ?? []" :key="suggestion.caseId" class="case-suggestion-row">
          <NuxtLink :to="`/cases/${suggestion.caseId}`" class="case-link">
            <b>{{ suggestion.caseTitle }}</b>
            <span>{{ suggestion.caseStatus }} · 共享 {{ suggestion.sharedIps.join(', ') }}</span>
          </NuxtLink>
          <button :disabled="busy" :aria-label="`加入案件 ${suggestion.caseId}`" @click="attachToCase(suggestion.caseId, alertId)">
            <Link2 :size="13" /> 加入
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.case-panel { margin-bottom: 12px; overflow: hidden; }
.case-panel-head { display: flex; align-items: center; justify-content: space-between; min-height: 40px; padding: 0 12px; border-bottom: 1px solid var(--border-subtle); }
.case-toggle { display: inline-flex; align-items: center; gap: 6px; border: 0; background: transparent; color: var(--text-secondary); font-size: 13px; cursor: pointer; }
.case-icon-btn { display: grid; place-items: center; width: 24px; height: 24px; border: 1px solid var(--border-default); border-radius: 6px; background: transparent; color: var(--text-tertiary); cursor: pointer; }
.case-panel-body { padding: 10px 12px; display: grid; gap: 8px; }
.case-create-btn { display: inline-flex; align-items: center; gap: 5px; justify-self: start; border: 1px solid var(--border-default); border-radius: 6px; padding: 5px 9px; background: var(--surface-2); color: var(--accent-strong); font-size: 12px; cursor: pointer; }
.case-create-form { display: flex; gap: 7px; }
.case-input { flex: 1; min-width: 0; padding: 6px 9px; border: 1px solid var(--border-default); border-radius: 6px; background: var(--surface-1); color: var(--text-primary); font-size: 13px; }
.case-primary { border: 0; border-radius: 6px; padding: 6px 10px; background: var(--accent); color: white; font-size: 13px; cursor: pointer; }
.case-empty { margin: 0; color: var(--text-tertiary); font-size: 12px; }
.case-suggestions { display: grid; gap: 7px; }
.case-suggestion-row { display: flex; align-items: center; justify-content: space-between; gap: 9px; padding: 8px 10px; border: 1px solid var(--border-subtle); border-radius: 7px; background: var(--surface-1); }
.case-link { min-width: 0; color: inherit; text-decoration: none; }
.case-link b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-primary); font-size: 13px; }
.case-link span { display: block; margin-top: 2px; color: var(--text-tertiary); font-size: 12px; }
.case-suggestion-row button { display: inline-flex; align-items: center; gap: 4px; border: 1px solid var(--border-default); border-radius: 6px; padding: 4px 8px; background: var(--surface-2); color: var(--accent-strong); font-size: 12px; cursor: pointer; }
.case-suggestion-row button:disabled { opacity: .55; cursor: wait; }
.case-toast { padding: 7px 10px; border-radius: 6px; font-size: 12px; }
.case-toast.ok { background: color-mix(in srgb, var(--status-success) 10%, transparent); color: var(--status-success); }
.case-toast.err { background: color-mix(in srgb, var(--status-error) 10%, transparent); color: var(--status-error); }
</style>
