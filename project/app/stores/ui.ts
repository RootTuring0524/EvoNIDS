import { defineStore } from 'pinia'

export type ThemeMode = 'dark' | 'light' | 'system'

export const useUiStore = defineStore('ui', () => {
  const themeMode = ref<ThemeMode>('dark')
  const resolvedTheme = ref<'dark' | 'light'>('dark')
  const scope = ref('全域网络')
  const timeRange = ref('最近 24 小时')
  const commandOpen = ref(false)
  const sidebarOpen = ref(false)
  let systemThemeQuery: MediaQueryList | undefined

  function onSystemThemeChange() {
    if (themeMode.value === 'system') applyTheme()
  }

  function applyTheme() {
    if (!import.meta.client) return
    const isDark = (systemThemeQuery || window.matchMedia('(prefers-color-scheme: dark)')).matches
    resolvedTheme.value = themeMode.value === 'system' ? (isDark ? 'dark' : 'light') : themeMode.value
    document.documentElement.dataset.theme = resolvedTheme.value
    localStorage.setItem('evonids-theme', themeMode.value)
  }

  function initialize() {
    if (!import.meta.client) return
    const saved = localStorage.getItem('evonids-theme') as ThemeMode | null
    if (saved && ['dark', 'light', 'system'].includes(saved)) themeMode.value = saved
    systemThemeQuery ||= window.matchMedia('(prefers-color-scheme: dark)')
    systemThemeQuery.removeEventListener('change', onSystemThemeChange)
    systemThemeQuery.addEventListener('change', onSystemThemeChange)
    applyTheme()
  }

  function dispose() {
    systemThemeQuery?.removeEventListener('change', onSystemThemeChange)
    systemThemeQuery = undefined
  }

  function setTheme(value: ThemeMode) {
    themeMode.value = value
    applyTheme()
  }

  return {
    themeMode,
    resolvedTheme,
    scope,
    timeRange,
    commandOpen,
    sidebarOpen,
    initialize,
    dispose,
    setTheme,
  }
})
