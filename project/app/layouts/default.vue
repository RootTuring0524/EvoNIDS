<script setup lang="ts">
const ui = useUiStore()
const isMock = useRuntimeConfig().public.useMockApi

onMounted(() => {
  ui.initialize()
})

onBeforeUnmount(() => {
  ui.dispose()
})
</script>

<template>
  <div class="app-shell">
    <AppSidebar />
    <button v-if="ui.sidebarOpen" class="sidebar-overlay" type="button" aria-label="关闭导航" @click="ui.sidebarOpen = false" />
    <div class="app-main">
      <TopCommandBar />
      <div v-if="isMock" class="mock-banner" role="note">
        <span>演示模式</span>
        <p>当前展示固定 Mock 数据，仅用于界面与流程评估；连接真实后端后，所有指标均来自可审计的数据库记录。</p>
      </div>
      <main id="main-content" class="page-scroll" tabindex="-1">
        <slot />
      </main>
    </div>
    <SearchCommand v-model:open="ui.commandOpen" />
  </div>
</template>

<style scoped>
.app-shell {
  display: grid;
  grid-template-columns: 224px minmax(0, 1fr);
  min-height: 100vh;
  background: var(--background);
}

.app-main {
  min-width: 0;
  min-height: 100vh;
}

.page-scroll {
  height: calc(100vh - 52px);
  overflow: auto;
}

.app-main:has(.mock-banner) .page-scroll {
  height: calc(100vh - 82px);
}

.mock-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  min-height: 30px;
  padding: 4px 16px;
  border-bottom: 1px solid color-mix(in srgb, var(--status-warning) 30%, var(--border-default));
  background: color-mix(in srgb, var(--status-warning) 8%, var(--surface-1));
  font-size: 12px;
}

.mock-banner span {
  flex: 0 0 auto;
  padding: 1px 6px;
  border: 1px solid color-mix(in srgb, var(--status-warning) 45%, var(--border-default));
  border-radius: 999px;
  color: var(--status-warning);
  font-weight: 600;
}

.mock-banner p {
  margin: 0;
  color: var(--text-tertiary);
}

@media (max-width: 700px) {
  .mock-banner p { display: none; }
}

.sidebar-overlay { display: none; }

@media (max-width: 900px) {
  .app-shell {
    grid-template-columns: 1fr;
  }
  .sidebar-overlay { position: fixed; z-index: 29; inset: 0; display: block; border: 0; background: var(--overlay); animation: sidebar-overlay-in 180ms ease; }
}

@keyframes sidebar-overlay-in { from { opacity: 0; } }
</style>
