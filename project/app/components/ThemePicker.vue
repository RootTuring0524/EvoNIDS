<script setup lang="ts">
import { Monitor, Moon, Sun } from '~/utils/icons'
import type { ThemeMode } from '~/stores/ui'

const ui = useUiStore()
const labels: Record<ThemeMode, string> = { dark: '深色模式', light: '浅色模式', system: '跟随系统' }
const order: ThemeMode[] = ['dark', 'light', 'system']
const icon = computed(() => (ui.themeMode === 'dark' ? Moon : ui.themeMode === 'light' ? Sun : Monitor))
function cycle() { ui.setTheme(order[(order.indexOf(ui.themeMode) + 1) % order.length]!) }
</script>

<template>
  <button class="theme-button" :aria-label="labels[ui.themeMode]" :title="labels[ui.themeMode]" @click="cycle"><component :is="icon" :size="16" /></button>
</template>

<style scoped>
.theme-button { display: grid; width: 32px; height: 32px; place-items: center; border: 1px solid var(--border-subtle); border-radius: 7px; background: var(--surface-1); color: var(--text-secondary); cursor: pointer; }.theme-button:hover { color: var(--text-primary); border-color: var(--border-default); }
</style>
