<script setup lang="ts">
const ui = useUiStore()

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

.sidebar-overlay { display: none; }

@media (max-width: 900px) {
  .app-shell {
    grid-template-columns: 1fr;
  }
  .sidebar-overlay { position: fixed; z-index: 29; inset: 0; display: block; border: 0; background: var(--overlay); animation: sidebar-overlay-in 180ms ease; }
}

@keyframes sidebar-overlay-in { from { opacity: 0; } }
</style>
