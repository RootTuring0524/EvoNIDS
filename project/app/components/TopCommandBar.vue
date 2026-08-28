<script setup lang="ts">
import { Bell, ChevronDown, Clock3, Menu, Search } from '~/utils/icons'

const ui = useUiStore()
const scopes = ['全域网络', '生产数据中心', '总部办公网', '华东分支']
const ranges = ['最近 1 小时', '最近 24 小时', '最近 7 天']
const notificationOpen = ref(false)
const profileOpen = ref(false)
const mounted = ref(false)
const notificationMenu = useTemplateRef<HTMLElement>('notificationMenu')
const profileMenu = useTemplateRef<HTMLElement>('profileMenu')
const now = useNow({ interval: 1_000 })
const liveTime = useDateFormat(now, 'HH:mm:ss')

onClickOutside(notificationMenu, () => { notificationOpen.value = false })
onClickOutside(profileMenu, () => { profileOpen.value = false })

function onKeydown(event: KeyboardEvent) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault()
    ui.commandOpen = true
  }
}

onMounted(() => {
  mounted.value = true
  window.addEventListener('keydown', onKeydown)
})
onBeforeUnmount(() => window.removeEventListener('keydown', onKeydown))
</script>

<template>
  <header class="command-bar">
    <button class="menu-button" aria-label="打开导航" @click="ui.sidebarOpen = true"><Menu :size="19" /></button>
    <label class="scope-select">
      <span class="sr-only">网络范围</span>
      <select v-model="ui.scope" aria-label="网络范围">
        <option v-for="item in scopes" :key="item">{{ item }}</option>
      </select>
      <ChevronDown :size="14" aria-hidden="true" />
    </label>
    <div class="divider" />
    <span class="live-time mono"><i /> 监测中 · <span v-if="mounted">{{ liveTime }}</span><span v-else>--:--:--</span> CST</span>
    <button class="search-trigger" aria-label="打开全局搜索" @click="ui.commandOpen = true">
      <Search :size="15" /><span>搜索告警、IP、规则或资产</span><kbd>Ctrl K</kbd>
    </button>
    <label class="time-select">
      <Clock3 :size="15" aria-hidden="true" />
      <select v-model="ui.timeRange" aria-label="时间范围"><option v-for="item in ranges" :key="item">{{ item }}</option></select>
      <ChevronDown :size="13" aria-hidden="true" />
    </label>
    <ThemePicker />
    <div ref="notificationMenu" class="menu-wrap">
      <button class="icon-button has-alert" aria-label="通知" aria-controls="notification-popover" :aria-expanded="notificationOpen" @click="notificationOpen=!notificationOpen;profileOpen=false"><Bell :size="17" /></button>
      <section v-if="notificationOpen" id="notification-popover" class="top-popover notification-popover" aria-label="最近通知">
        <header><b>最近通知</b><span>2 条待处理</span></header>
        <NuxtLink to="/alerts/ALT-78436" @click="notificationOpen=false"><i class="critical"/><span><b>支付网关 SYN Flood</b><small>高危告警 · 刚刚</small></span></NuxtLink>
        <NuxtLink to="/rules/EVO-2026-0716-14" @click="notificationOpen=false"><i class="warning"/><span><b>规则等待人工确认</b><small>验证质量 92 · 8 分钟前</small></span></NuxtLink>
      </section>
    </div>
    <div ref="profileMenu" class="menu-wrap">
      <button class="avatar" aria-label="打开用户菜单" aria-controls="profile-popover" :aria-expanded="profileOpen" @click="profileOpen=!profileOpen;notificationOpen=false">R</button>
      <section v-if="profileOpen" id="profile-popover" class="top-popover profile-popover" aria-label="用户菜单">
        <div><b>Root</b><small>SOC 安全分析师</small></div>
        <NuxtLink to="/settings" @click="profileOpen=false">平台设置</NuxtLink>
        <NuxtLink to="/audit" @click="profileOpen=false">我的审计记录</NuxtLink>
      </section>
    </div>
  </header>
</template>

<style scoped>
.command-bar { position: sticky; top: 0; z-index: 20; display: flex; align-items: center; gap: 10px; height: 52px; padding: 0 18px; background: color-mix(in srgb, var(--background) 92%, transparent); border-bottom: 1px solid var(--border-subtle); backdrop-filter: blur(12px); }
.menu-button { display: none; padding: 6px; border: 0; background: transparent; color: var(--text-secondary); }
.scope-select, .time-select { display: flex; align-items: center; gap: 4px; color: var(--text-secondary); white-space: nowrap; }
select { appearance: none; border: 0; background: transparent; color: inherit; cursor: pointer; }
select option { background: var(--surface-2); color: var(--text-primary); }
.scope-select select { color: var(--text-primary); font-size: 13px; font-weight: 600; }
.divider { width: 1px; height: 18px; background: var(--border-default); }
.live-time { color: var(--text-tertiary); font-size:14px; white-space: nowrap; }.live-time i { display: inline-block; width: 6px; height: 6px; margin-right: 5px; background: var(--status-success); border-radius: 50%; }
.search-trigger { display: flex; flex: 1; align-items: center; gap: 8px; max-width: 410px; min-width: 180px; height: 32px; margin-left: auto; padding: 0 8px 0 10px; border: 1px solid var(--border-default); border-radius: 7px; background: var(--surface-1); color: var(--text-tertiary); cursor: pointer; text-align: left; }
.search-trigger span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.search-trigger kbd { margin-left: auto; padding: 1px 5px; border: 1px solid var(--border-default); border-radius: 4px; background: var(--surface-2); color: var(--text-tertiary); font-size:13px; }
.time-select { position: relative; height: 32px; padding: 0 8px; border: 1px solid var(--border-subtle); border-radius: 7px; background: var(--surface-1); font-size:14px; }
.icon-button { position: relative; display: grid; width: 32px; height: 32px; place-items: center; border: 1px solid var(--border-subtle); border-radius: 7px; background: var(--surface-1); color: var(--text-secondary); cursor: pointer; }.icon-button:hover { color: var(--text-primary); border-color: var(--border-default); }.has-alert::after { position: absolute; top: 6px; right: 6px; width: 5px; height: 5px; background: var(--severity-critical); border: 1px solid var(--surface-1); border-radius: 50%; content: ''; }
.avatar { display: grid; width: 30px; height: 30px; place-items: center; border: 1px solid var(--border-default); border-radius: 7px; background: var(--surface-3); color: var(--text-primary); font-size: 12px; cursor: pointer; }
.menu-wrap{position:relative}.top-popover{position:absolute;top:39px;right:0;z-index:40;width:300px;border:1px solid var(--border-default);border-radius:9px;background:var(--surface-1);box-shadow:0 16px 40px rgba(0,0,0,.28);color:var(--text-primary)}.top-popover header{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid var(--border-subtle)}.top-popover header b{font-size:14px}.top-popover header span{color:var(--status-warning);font-size:12px}.notification-popover>a{display:grid;grid-template-columns:8px 1fr;gap:9px;align-items:center;padding:10px 12px;border-bottom:1px solid var(--border-subtle);color:inherit;text-decoration:none}.notification-popover>a:last-child{border-bottom:0}.notification-popover>a:hover,.profile-popover>a:hover{background:var(--surface-2)}.notification-popover>a>i{width:7px;height:7px;border-radius:50%;background:var(--severity-info)}.notification-popover>a>i.critical{background:var(--severity-critical)}.notification-popover>a>i.warning{background:var(--status-warning)}.notification-popover b,.notification-popover small{display:block}.notification-popover b{font-size:13px}.notification-popover small{margin-top:2px;color:var(--text-tertiary);font-size:12px}.profile-popover{width:210px;padding:6px}.profile-popover>div{padding:8px}.profile-popover>div b,.profile-popover>div small{display:block}.profile-popover>div b{font-size:14px}.profile-popover>div small{margin-top:2px;color:var(--text-tertiary);font-size:12px}.profile-popover>a{display:block;padding:8px;border-radius:6px;color:var(--text-secondary);font-size:13px;text-decoration:none}
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); }
@media (max-width: 1100px) { .live-time, .search-trigger span, .search-trigger kbd { display: none; }.search-trigger { flex: 0 0 32px; min-width: 32px; padding: 0; justify-content: center; }.time-select { width: 32px; flex: 0 0 32px; justify-content: center; padding: 0; }.time-select select { position: absolute; inset: 0; width: 100%; opacity: 0; }.time-select > svg:last-child { display: none; } }
@media (max-width: 900px) { .menu-button { display: inline-flex; }.command-bar { padding: 0 12px; } }
@media (max-width: 600px) { .command-bar { gap: 6px; }.divider { display: none; }.scope-select select { max-width: 96px; } }
</style>
