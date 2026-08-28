<script setup lang="ts">
import { DialogClose, DialogContent, DialogDescription, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { X } from '~/utils/icons'

withDefaults(defineProps<{
  open: boolean
  title: string
  description?: string
  width?: string
}>(), {
  description: '',
  width: '380px',
})

const emit = defineEmits<{ 'update:open': [value: boolean] }>()
</script>

<template>
  <DialogRoot :open="open" @update:open="emit('update:open', $event)">
    <DialogPortal>
      <DialogOverlay class="drawer-overlay" />
      <DialogContent class="detail-drawer" :style="{ '--drawer-width': width }">
        <header>
          <div><DialogTitle class="drawer-title">{{ title }}</DialogTitle><DialogDescription class="drawer-description">{{ description }}</DialogDescription></div>
          <DialogClose class="drawer-close" aria-label="关闭抽屉"><X :size="16" aria-hidden="true" /></DialogClose>
        </header>
        <div class="drawer-body"><slot /></div>
        <footer v-if="$slots.footer"><slot name="footer" /></footer>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>

<style>
.drawer-overlay { position: fixed; inset: 0; z-index: 80; background: var(--overlay); }
.detail-drawer { position: fixed; z-index: 81; top: 0; right: 0; width: min(var(--drawer-width), calc(100vw - 24px)); height: 100vh; border-left: 1px solid var(--border-strong); background: var(--surface-1); box-shadow: -20px 0 54px rgba(0, 0, 0, .26); }
.detail-drawer > header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; min-height: 64px; padding: 13px 14px; border-bottom: 1px solid var(--border-subtle); }
.detail-drawer .drawer-title { display: block; color: var(--text-primary); font-size: 14px; font-weight: 650; }
.detail-drawer .drawer-description { margin: 3px 0 0; color: var(--text-tertiary); font-size:13px; }
.drawer-close { display: grid; width: 29px; height: 29px; place-items: center; border: 1px solid var(--border-subtle); border-radius: 7px; background: var(--surface-2); color: var(--text-tertiary); cursor: pointer; }
.drawer-close:hover { color: var(--text-primary); border-color: var(--border-default); }
.drawer-body { height: calc(100vh - 64px); overflow: auto; padding: 12px 14px; }
.detail-drawer > footer { padding: 10px 14px; border-top: 1px solid var(--border-subtle); }
.drawer-overlay[data-state='open'] { animation: drawer-overlay-in 180ms ease; }.drawer-overlay[data-state='closed'] { animation: drawer-overlay-out 180ms ease; }
.detail-drawer[data-state='open'] { animation: drawer-in 260ms ease; }.detail-drawer[data-state='closed'] { animation: drawer-out 220ms ease; }
@keyframes drawer-overlay-in { from { opacity: 0; } } @keyframes drawer-overlay-out { to { opacity: 0; } }
@keyframes drawer-in { from { transform: translateX(100%); } } @keyframes drawer-out { to { transform: translateX(100%); } }
</style>
