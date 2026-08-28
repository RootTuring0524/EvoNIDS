<script setup lang="ts">
import { DialogContent, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { ArrowRight, BellRing, FileCode2, Network, Search, Server } from '~/utils/icons'

defineProps<{ open: boolean }>()
const emit = defineEmits<{ 'update:open': [value: boolean] }>()
const query = ref('')
const items = [
  { type: '告警', title: 'ALT-78431 · 疑似 C2 心跳与域前置行为', meta: '10.24.16.37 → 185.225.73.44', icon: BellRing, to: '/alerts/ALT-78431' },
  { type: '地址', title: '10.24.16.37', meta: '研发构建节点 · 当前风险 96', icon: Server, to: '/traffic' },
  { type: '规则', title: 'EVO-2026-0716-14', meta: 'short_time_multi_port_scan', icon: FileCode2, to: '/rules/EVO-2026-0716-14' },
  { type: '流量', title: 'FL-901822', meta: 'TLS · 4.8 KB · anomaly 0.97', icon: Network, to: '/traffic' },
]
const visible = computed(() => items.filter((item) => !query.value || `${item.title}${item.meta}`.toLowerCase().includes(query.value.toLowerCase())))

async function navigate(to: string) {
  emit('update:open', false)
  await navigateTo(to)
}
</script>

<template>
  <DialogRoot :open="open" @update:open="emit('update:open', $event)">
    <DialogPortal>
      <DialogOverlay class="command-overlay" />
      <DialogContent class="command-dialog" aria-describedby="command-help">
        <DialogTitle class="sr-title">全局搜索</DialogTitle>
        <div class="command-input"><Search :size="17" /><input v-model="query" autofocus placeholder="输入告警 ID、IP、规则、资产名称…" aria-label="搜索内容" ><kbd>ESC</kbd></div>
        <p id="command-help" class="command-hint">搜索全域 24 小时内的安全对象</p>
        <div class="command-results">
          <button v-for="item in visible" :key="item.title" @click="navigate(item.to)">
            <component :is="item.icon" :size="17" aria-hidden="true" />
            <span><small>{{ item.type }}</small><b>{{ item.title }}</b><em>{{ item.meta }}</em></span>
            <ArrowRight :size="15" aria-hidden="true" />
          </button>
          <p v-if="visible.length === 0" class="empty-result">未找到匹配对象</p>
        </div>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>

<style>
.command-overlay { position: fixed; inset: 0; z-index: 60; background: var(--overlay); backdrop-filter: blur(2px); animation: fade-in 160ms ease; }
.command-dialog { position: fixed; z-index: 61; top: 13vh; left: 50%; width: min(620px, calc(100vw - 32px)); transform: translateX(-50%); overflow: hidden; border: 1px solid var(--border-strong); border-radius: 12px; background: var(--surface-1); box-shadow: 0 24px 80px rgba(0,0,0,.34); animation: dialog-in 220ms ease; }
.sr-title { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); }
.command-input { display: flex; align-items: center; gap: 10px; height: 52px; padding: 0 14px; border-bottom: 1px solid var(--border-default); color: var(--text-tertiary); }.command-input input { flex: 1; border: 0; background: transparent; color: var(--text-primary); font-size: 14px; }.command-input kbd { padding: 2px 5px; border: 1px solid var(--border-default); border-radius: 4px; color: var(--text-tertiary); font-size:13px; }
.command-hint { margin: 0; padding: 8px 14px; color: var(--text-tertiary); font-size:13px; letter-spacing: .04em; text-transform: uppercase; }
.command-results { padding: 0 6px 7px; }.command-results button { display: grid; grid-template-columns: 28px 1fr 20px; gap: 7px; align-items: center; width: 100%; min-height: 58px; padding: 7px 10px; border: 0; border-radius: 7px; background: transparent; color: var(--text-secondary); cursor: pointer; text-align: left; }.command-results button:hover, .command-results button:focus-visible { background: var(--surface-2); color: var(--text-primary); }.command-results span { display: grid; grid-template-columns: auto 1fr; gap: 0 8px; }.command-results small { color: var(--accent-strong); font-size:13px; }.command-results b { font-size: 13px; font-weight: 600; }.command-results em { grid-column: 2; color: var(--text-tertiary); font-size:14px; font-style: normal; }.empty-result { padding: 24px; color: var(--text-tertiary); text-align: center; }
@keyframes fade-in { from { opacity: 0; } } @keyframes dialog-in { from { opacity: 0; transform: translate(-50%, -6px); } }
</style>
