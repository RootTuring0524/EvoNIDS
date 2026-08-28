<script setup lang="ts">
import { AlertTriangle, RotateCcw, ShieldX, X } from '~/utils/icons'
import { DialogClose, DialogContent, DialogDescription, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { toTypedSchema } from '@vee-validate/zod'
import { useField, useForm } from 'vee-validate'
import { z } from 'zod'

const props = withDefaults(defineProps<{
  open: boolean
  action: 'repair' | 'reject' | 'deprecate'
  loading?: boolean
  error?: string
}>(), { loading: false, error: '' })

const emit = defineEmits<{ 'update:open': [value: boolean]; confirm: [reason: string] }>()
const lifecycleSchema = toTypedSchema(z.object({
  reason: z.string().trim().min(10, '原因至少需要 10 个字符').max(500, '原因不能超过 500 个字符'),
}))
const { handleSubmit, resetForm, meta } = useForm({ validationSchema: lifecycleSchema, initialValues: { reason: '' } })
const { value: reason, errorMessage: reasonError } = useField<string>('reason')
const submit = handleSubmit((values) => emit('confirm', values.reason))

const copy = computed(() => ({
  repair: {
    title: '创建规则修复版本',
    description: '保留当前版本作为父版本，并创建新的 Repaired 版本。',
    label: '修复原因',
    placeholder: '说明触发修复的覆盖缺口、误报来源或阈值问题…',
    confirm: '创建 Repaired 版本',
    icon: RotateCcw,
  },
  reject: {
    title: '驳回本次规则验证',
    description: '规则将进入 Rejected，必须完成修复后才能重新验证。',
    label: '驳回原因',
    placeholder: '说明未通过的验证指标或证据冲突…',
    confirm: '确认驳回',
    icon: AlertTriangle,
  },
  deprecate: {
    title: '废弃已部署规则',
    description: '规则会从检测平面撤下，但版本与审计记录继续保留。',
    label: '废弃原因',
    placeholder: '说明替代规则、业务变更或失效原因…',
    confirm: '确认废弃',
    icon: ShieldX,
  },
})[props.action])

watch(() => props.open, (open) => { if (open) resetForm({ values: { reason: '' } }) })
</script>

<template>
  <DialogRoot :open="open" @update:open="emit('update:open', $event)">
    <DialogPortal>
      <DialogOverlay class="lifecycle-overlay" />
      <DialogContent class="lifecycle-dialog">
        <header>
          <span class="dialog-icon"><component :is="copy.icon" :size="19" /></span>
          <div><DialogTitle>{{ copy.title }}</DialogTitle><DialogDescription>{{ copy.description }}</DialogDescription></div>
          <DialogClose class="close-button" aria-label="关闭" :disabled="loading"><X :size="16" /></DialogClose>
        </header>
        <form novalidate @submit="submit">
          <label><span>{{ copy.label }}</span><textarea v-model="reason" rows="4" maxlength="500" :placeholder="copy.placeholder" :disabled="loading" :aria-invalid="Boolean(reasonError)" aria-describedby="lifecycle-reason-help lifecycle-reason-error" /><small id="lifecycle-reason-help">必填，10–500 个字符；内容将写入版本 Lineage。</small><em v-if="reasonError" id="lifecycle-reason-error" role="alert">{{ reasonError }}</em></label>
          <p v-if="error" class="dialog-error" role="alert">{{ error }}</p>
          <footer>
            <DialogClose type="button" class="cancel" :disabled="loading">取消</DialogClose>
            <button type="submit" class="confirm" :class="action" :disabled="loading" :aria-busy="loading">{{ loading ? '正在提交…' : meta.valid ? copy.confirm : `校验并${copy.confirm}` }}</button>
          </footer>
        </form>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>

<style>
.lifecycle-overlay{position:fixed;inset:0;z-index:70;background:var(--overlay);backdrop-filter:blur(2px)}.lifecycle-dialog{position:fixed;z-index:71;top:50%;left:50%;width:min(520px,calc(100vw - 28px));transform:translate(-50%,-50%);overflow:hidden;border:1px solid var(--border-strong);border-radius:12px;background:var(--surface-1);box-shadow:0 26px 80px rgba(0,0,0,.35)}
.lifecycle-dialog>header{display:grid;grid-template-columns:36px 1fr 28px;gap:10px;align-items:center;padding:14px 16px;border-bottom:1px solid var(--border-subtle)}.lifecycle-dialog .dialog-icon{display:grid;width:34px;height:34px;place-items:center;border-radius:8px;background:color-mix(in srgb,var(--status-warning) 10%,transparent);color:var(--status-warning)}.lifecycle-dialog header h2{margin:0;font-size:15px}.lifecycle-dialog header p{margin:3px 0 0;color:var(--text-tertiary);font-size:12px}.lifecycle-dialog .close-button{display:grid;width:28px;height:28px;place-items:center;border:0;background:transparent;color:var(--text-tertiary);cursor:pointer}
.lifecycle-dialog form>label{display:block;padding:14px 16px}.lifecycle-dialog form>label>span{display:block;margin-bottom:6px;color:var(--text-secondary);font-size:12px}.lifecycle-dialog textarea{width:100%;padding:9px 10px;resize:vertical;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-primary);font-size:13px;line-height:1.55}.lifecycle-dialog textarea:disabled{opacity:.6}.lifecycle-dialog textarea[aria-invalid='true']{border-color:var(--status-error)}.lifecycle-dialog form>label small,.lifecycle-dialog form>label em{display:block;margin-top:4px;font-size:14px}.lifecycle-dialog form>label small{color:var(--text-tertiary)}.lifecycle-dialog form>label em{color:var(--status-error);font-style:normal}.lifecycle-dialog .dialog-error{margin:0 16px 12px;padding:8px 10px;border-left:2px solid var(--status-error);background:color-mix(in srgb,var(--status-error) 8%,transparent);color:var(--status-error);font-size:12px}
.lifecycle-dialog form>footer{display:flex;justify-content:flex-end;gap:8px;padding:11px 16px;border-top:1px solid var(--border-subtle);background:var(--surface-2)}.lifecycle-dialog footer button{height:34px;padding:0 12px;border-radius:7px;font-size:12px;cursor:pointer}.lifecycle-dialog .cancel{border:1px solid var(--border-default);background:var(--surface-1);color:var(--text-secondary)}.lifecycle-dialog .confirm{border:1px solid color-mix(in srgb,var(--accent) 55%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.lifecycle-dialog .confirm.reject,.lifecycle-dialog .confirm.deprecate{border-color:color-mix(in srgb,var(--status-error) 45%,var(--border-default));background:color-mix(in srgb,var(--status-error) 9%,transparent);color:var(--status-error)}.lifecycle-dialog footer button:disabled{cursor:not-allowed;opacity:.5}
</style>
