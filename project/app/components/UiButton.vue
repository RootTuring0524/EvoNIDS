<script setup lang="ts">
import { cva, type VariantProps } from 'class-variance-authority'
import { LoaderCircle } from '~/utils/icons'
import { cn } from '~/utils/cn'

const buttonVariants = cva('ui-button', {
  variants: {
    variant: {
      default: 'ui-button-default',
      primary: 'ui-button-primary',
      quiet: 'ui-button-quiet',
      danger: 'ui-button-danger',
    },
    size: {
      compact: 'ui-button-compact',
      default: 'ui-button-size-default',
    },
  },
  defaultVariants: { variant: 'default', size: 'default' },
})

type ButtonVariants = VariantProps<typeof buttonVariants>
withDefaults(defineProps<{
  variant?: ButtonVariants['variant']
  size?: ButtonVariants['size']
  type?: 'button' | 'submit' | 'reset'
  disabled?: boolean
  loading?: boolean
}>(), {
  variant: 'default',
  size: 'default',
  type: 'button',
  disabled: false,
  loading: false,
})
</script>

<template>
  <button
    :type="type"
    :disabled="disabled || loading"
    :aria-busy="loading || undefined"
    :class="cn(buttonVariants({ variant, size }))"
  >
    <LoaderCircle v-if="loading" class="ui-button-spinner" :size="14" aria-hidden="true" />
    <slot />
  </button>
</template>

<style scoped>
.ui-button { display: inline-flex; align-items: center; justify-content: center; gap: 5px; border: 1px solid var(--border-default); border-radius: 8px; font-size:14px; cursor: pointer; transition: color 150ms ease, background 150ms ease, border-color 150ms ease, transform 120ms ease; }
.ui-button-size-default { height: 34px; padding: 0 10px; }.ui-button-compact { height: 32px; padding: 0 9px; border-radius: 6px; font-size:13px; }
.ui-button-default { background: var(--surface-1); color: var(--text-secondary); }.ui-button-default:hover { border-color: var(--border-strong); background: var(--surface-2); color: var(--text-primary); }
.ui-button-primary { border-color: color-mix(in srgb, var(--accent) 52%, var(--border-default)); background: var(--accent-muted); color: var(--accent-strong); }.ui-button-primary:hover { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 17%, transparent); }
.ui-button-quiet { border-color: var(--border-subtle); background: transparent; color: var(--text-tertiary); }.ui-button-quiet:hover { background: var(--surface-2); color: var(--text-primary); }
.ui-button-danger { border-color: color-mix(in srgb, var(--status-error) 45%, var(--border-default)); background: color-mix(in srgb, var(--status-error) 8%, transparent); color: var(--status-error); }
.ui-button:active:not(:disabled) { transform: translateY(1px); }.ui-button[aria-pressed='true'] { border-color: var(--accent); background: var(--accent-muted); color: var(--accent-strong); }.ui-button:disabled { color: var(--text-disabled); cursor: not-allowed; opacity: .58; }
.ui-button-spinner { animation: ui-button-spin .7s linear infinite; } @keyframes ui-button-spin { to { transform: rotate(360deg); } }
</style>
