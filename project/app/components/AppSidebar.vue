<script setup lang="ts">
import {
  Activity,
  BellRing,
  Boxes,
  BrainCircuit,
  ChevronsLeft,
  FileClock,
  Network,
  Radar,
  Settings,
  ShieldCheck,
  ServerCog,
  Waypoints,
} from '~/utils/icons'
import { sensorsResponseSchema } from '~~/shared/schemas/security'

const route = useRoute()
const ui = useUiStore()
const { data: sensorData } = await useAsyncData('sidebar-sensor-health', () =>
  validatedFetch('/sensors', sensorsResponseSchema),
)
const sidebar = ref<HTMLElement>()
const isMobile = useMediaQuery('(max-width: 900px)')
const mounted = ref(false)
let restoreFocus: HTMLElement | null = null

const sections = [
  {
    label: '安全运营',
    items: [
      { label: '运营态势', to: '/overview', icon: Activity },
      { label: '告警研判', to: '/alerts', icon: BellRing, badge: '6' },
      { label: '流量探索', to: '/traffic', icon: Network },
      { label: '探针与数据源', to: '/sensors', icon: ServerCog },
    ],
  },
  {
    label: '检测与演进',
    items: [
      { label: '规则演进', to: '/rules', icon: Waypoints, badge: '2' },
      { label: '模型运行', to: '/models', icon: BrainCircuit },
      { label: '知识与情报', to: '/knowledge', icon: Boxes },
    ],
  },
  {
    label: '系统',
    items: [
      { label: '审计日志', to: '/audit', icon: FileClock },
      { label: '平台设置', to: '/settings', icon: Settings },
    ],
  },
]

function closeSidebar() {
  ui.sidebarOpen = false
}

function focusableElements() {
  return Array.from(sidebar.value?.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])') || [])
}

function onSidebarKeydown(event: KeyboardEvent) {
  if (!isMobile.value || !ui.sidebarOpen) return
  if (event.key === 'Escape') {
    event.preventDefault()
    closeSidebar()
    return
  }
  if (event.key !== 'Tab') return
  const items = focusableElements()
  const first = items[0]
  const last = items.at(-1)
  if (!first || !last) return
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

watch(() => ui.sidebarOpen, async (open) => {
  if (!isMobile.value) return
  if (open) {
    restoreFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    await nextTick()
    focusableElements()[0]?.focus()
  } else if (restoreFocus) {
    restoreFocus.focus()
    restoreFocus = null
  }
})

useEventListener(() => window, 'keydown', onSidebarKeydown)
onMounted(() => {
  mounted.value = true
})
</script>

<template>
  <aside
    ref="sidebar"
    :class="['sidebar', { open: ui.sidebarOpen }]"
    aria-label="主导航"
    :role="mounted && isMobile && ui.sidebarOpen ? 'dialog' : undefined"
    :aria-modal="mounted && isMobile && ui.sidebarOpen ? 'true' : undefined"
    :aria-hidden="mounted && isMobile && !ui.sidebarOpen ? 'true' : undefined"
    :inert="mounted && isMobile && !ui.sidebarOpen"
  >
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">
        <ShieldCheck :size="18" :stroke-width="1.8" />
      </div>
      <div>
        <strong>EvoNIDS</strong>
        <span>Network Defense</span>
      </div>
      <button class="mobile-close" aria-label="关闭导航" @click="closeSidebar">
        <ChevronsLeft :size="18" />
      </button>
    </div>

    <NuxtLink to="/sensors" class="system-state">
      <span :class="['state-dot', { warning: (sensorData?.summary.degraded ?? 0) + (sensorData?.summary.offline ?? 0) > 0 }]" aria-hidden="true" />
      <div><b>{{ sensorData?.summary.online === sensorData?.summary.total && sensorData?.summary.total ? '采集平面正常' : '采集平面需关注' }}</b><small>{{ sensorData?.summary.online ?? '—' }} / {{ sensorData?.summary.total ?? '—' }} 探针在线 · {{ sensorData?.summary.alerts ?? '—' }} 告警</small></div>
    </NuxtLink>

    <nav class="nav-stack">
      <section v-for="section in sections" :key="section.label" class="nav-section">
        <p>{{ section.label }}</p>
        <NuxtLink
          v-for="item in section.items"
          :key="item.to"
          :to="item.to"
          :class="['nav-link', { active: route.path === item.to }]"
          @click="closeSidebar"
        >
          <component :is="item.icon" :size="17" :stroke-width="1.8" aria-hidden="true" />
          <span>{{ item.label }}</span>
          <em v-if="item.badge">{{ item.badge }}</em>
        </NuxtLink>
      </section>
    </nav>

    <div class="sidebar-foot">
      <Radar :size="16" aria-hidden="true" />
      <div><span>策略版本</span><b class="mono">2026.07.16-r8</b></div>
    </div>
  </aside>
</template>

<style scoped>
.sidebar {
  position: sticky;
  top: 0;
  z-index: 30;
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 0 12px 12px;
  overflow-y: auto;
  background: var(--sidebar);
  border-right: 1px solid var(--border-subtle);
}
.brand { display: flex; align-items: center; gap: 10px; height: 62px; padding: 0 8px; }
.brand-mark { display: grid; width: 31px; height: 31px; place-items: center; color: var(--accent-strong); background: var(--accent-muted); border: 1px solid rgba(78, 166, 180, .28); border-radius: 9px; }
.brand strong { display: block; font-size: 15px; letter-spacing: .01em; }
.brand span { display: block; margin-top: -1px; color: var(--text-tertiary); font-size:13px; letter-spacing: .08em; text-transform: uppercase; }
.mobile-close { display: none; margin-left: auto; padding: 6px; border: 0; background: transparent; color: var(--text-secondary); }
.system-state { display: flex; gap: 9px; align-items: flex-start; margin: 2px 4px 14px; padding: 10px 11px; background: var(--surface-1); border: 1px solid var(--border-subtle); border-radius: 9px; color:inherit; text-decoration:none; }
.state-dot { flex: 0 0 auto; width: 7px; height: 7px; margin-top: 5px; background: var(--status-success); border-radius: 50%; }
.state-dot.warning { background: var(--status-warning); }
.system-state b { display: block; font-size: 12px; font-weight: 600; }
.system-state small { display: block; margin-top: 2px; color: var(--text-tertiary); font-size:13px; }
.nav-stack { display: grid; gap: 14px; }
.nav-section p { margin: 0 8px 5px; color: var(--text-tertiary); font-size:13px; font-weight: 700; letter-spacing: .07em; }
.nav-link { position: relative; display: grid; grid-template-columns: 20px 1fr auto; gap: 8px; align-items: center; min-height: 36px; padding: 0 9px; border-radius: 7px; color: var(--text-secondary); text-decoration: none; transition: color 140ms ease, background 140ms ease; }
.nav-link:hover { color: var(--text-primary); background: var(--surface-1); }
.nav-link.active { color: var(--text-primary); background: var(--accent-muted); }
.nav-link.active::before { position: absolute; left: -12px; width: 2px; height: 20px; background: var(--accent); border-radius: 0 2px 2px 0; content: ''; }
.nav-link em { min-width: 20px; padding: 1px 5px; border-radius: 999px; background: var(--surface-3); color: var(--text-secondary); font-size:13px; font-style: normal; text-align: center; }
.nav-link.active em { background: rgba(78, 166, 180, .18); color: var(--accent-strong); }
.sidebar-foot { display: flex; gap: 9px; align-items: center; margin-top: auto; padding: 11px 9px; border-top: 1px solid var(--border-subtle); color: var(--text-tertiary); }
.sidebar-foot span, .sidebar-foot b { display: block; font-size:13px; }.sidebar-foot b { color: var(--text-secondary); font-weight: 500; }
@media (max-width: 900px) {
  .sidebar { position: fixed; left: 0; width: 240px; transform: translateX(-102%); transition: transform 220ms ease; box-shadow: 12px 0 32px rgba(0,0,0,.25); }
  .sidebar.open { transform: translateX(0); }
  .mobile-close { display: inline-flex; }
}
</style>
