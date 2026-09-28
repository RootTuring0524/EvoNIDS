<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { ArrowLeft, RefreshCw, Share2 } from '~/utils/icons'
import { entityDetailSchema } from '~~/shared/schemas/security'

const route = useRoute()
const router = useRouter()
const entityId = computed(() => String(route.params.id ?? ''))

const { data: detailData, isPending, isError, error, refetch } = useQuery({
  queryKey: computed(() => ['entity-detail', entityId.value]),
  queryFn: () => validatedFetch('/entities/' + encodeURIComponent(entityId.value), entityDetailSchema),
})

const relations = computed(() => detailData.value?.relations ?? [])
</script>

<template>
  <div class="p-6 space-y-5">
    <header class="flex items-center gap-3">
      <button class="rounded-lg border border-current/10 p-2 hover:border-current/30" aria-label="返回实体列表" @click="router.push('/entities')">
        <ArrowLeft :size="16" />
      </button>
      <div>
        <h1 class="text-xl font-semibold flex items-center gap-2"><Share2 :size="18" /> 实体详情</h1>
        <p class="text-xs opacity-60 mt-0.5">{{ entityId }}</p>
      </div>
      <button class="ml-auto rounded-lg border border-current/10 p-2 hover:border-current/30" aria-label="刷新" @click="refetch()">
        <RefreshCw :size="16" />
      </button>
    </header>

    <div v-if="isPending" class="py-10 text-center text-sm opacity-60">加载中…</div>
    <div v-else-if="isError" class="py-10 text-center text-sm text-red-300">加载失败：{{ error?.message }}</div>
    <template v-else-if="detailData">
      <section class="rounded-xl border border-current/10 p-4 space-y-2">
        <div class="font-mono text-lg">{{ detailData.value }}</div>
        <div class="text-sm opacity-70">{{ detailData.sensorIds.length }} 个传感器 · {{ detailData.eventCount }} 次出现</div>
        <div class="text-xs opacity-50">首次：{{ new Date(detailData.firstSeenAt).toLocaleString() }} · 最近：{{ new Date(detailData.lastSeenAt).toLocaleString() }}</div>
      </section>

      <section class="rounded-xl border border-current/10 p-4 space-y-3">
        <h2 class="font-semibold">通信关系（{{ relations.length }}）</h2>
        <div v-if="relations.length === 0" class="text-sm opacity-60 py-4 text-center">尚无关系</div>
        <div v-else class="space-y-2">
          <NuxtLink v-for="relation in relations" :key="relation.id" :to="`/entities/${relation.otherEntityId}`" class="flex items-center justify-between rounded-lg border border-current/10 p-3 hover:border-current/25">
            <div>
              <div class="font-mono text-sm">{{ relation.otherEntityValue }}</div>
              <div class="text-xs opacity-60 mt-0.5">{{ relation.relationType }} · {{ relation.eventCount }} 次</div>
            </div>
            <div class="text-xs opacity-50 text-right">{{ new Date(relation.lastSeenAt).toLocaleString() }}</div>
          </NuxtLink>
        </div>
      </section>
    </template>
  </div>
</template>
