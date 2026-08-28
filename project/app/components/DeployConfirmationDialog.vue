<script setup lang="ts">
import { DialogClose, DialogContent, DialogDescription, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { ShieldCheck, X } from '~/utils/icons'
import { toTypedSchema } from '@vee-validate/zod'
import { useField, useForm } from 'vee-validate'
import { z } from 'zod'
import type { RuleDetail } from '~~/shared/types/security'

const props = withDefaults(defineProps<{ open: boolean; detail: RuleDetail; loading?: boolean; error?: string }>(), {
  loading: false,
  error: '',
})
const emit = defineEmits<{ 'update:open': [value: boolean]; confirm: [note: string] }>()
const defaultNote = '经回放验证通过，同意在全域检测平面灰度部署。'
const deploySchema = toTypedSchema(z.object({
  note: z.string().trim().min(12, '部署备注至少需要 12 个字符').max(500, '部署备注不能超过 500 个字符'),
}))
const { handleSubmit, resetForm, meta } = useForm({ validationSchema: deploySchema, initialValues: { note: defaultNote } })
const { value: note, errorMessage: noteError } = useField<string>('note')
const submit = handleSubmit((values) => emit('confirm', values.note))

watch(() => props.open, (open) => {
  if (open) resetForm({ values: { note: defaultNote } })
})
</script>

<template>
  <DialogRoot :open="open" @update:open="emit('update:open', $event)">
    <DialogPortal>
      <DialogOverlay class="deploy-overlay" />
      <DialogContent class="deploy-dialog">
        <div class="deploy-title">
          <div><ShieldCheck :size="19" /><span><DialogTitle>人工确认规则部署</DialogTitle><DialogDescription>Confirmed → Deployed · 服务端将再次校验当前状态</DialogDescription></span></div>
          <DialogClose class="close-button" aria-label="关闭" :disabled="loading"><X :size="16" /></DialogClose>
        </div>
        <form novalidate @submit="submit">
          <div class="deploy-warning"><b>这是影响检测平面的变更操作</b><p>DeepSeek V4 Pro 无权批准部署。当前规则必须已经由分析师确认为 Confirmed。</p></div>
          <dl class="deploy-metrics">
          <div><dt>规则 / 版本</dt><dd class="mono">{{ detail.structured.rule_id }} · v{{ detail.structured.version }}</dd></div>
          <div><dt>当前阶段</dt><dd class="confirmed">{{ detail.record.stage }}</dd></div>
          <div><dt>质量分</dt><dd class="mono good">{{ detail.validation.qualityScore }}/100</dd></div>
          <div><dt>命中率</dt><dd class="mono">{{ detail.validation.hitRate }}%</dd></div>
          <div><dt>误报率</dt><dd class="mono good">{{ detail.validation.falsePositiveRate }}%</dd></div>
          <div><dt>覆盖率</dt><dd class="mono">{{ detail.validation.attackCoverage }}%</dd></div>
          <div><dt>关联攻击</dt><dd>{{ detail.structured.attack_type }} · {{ detail.structured.mitre_technique_ids.join(', ') }}</dd></div>
          <div><dt>操作人</dt><dd>Root（L2 分析师）</dd></div>
          <div class="wide"><dt>预计影响范围</dt><dd>全域网络 · 6 个传感器 · 约 42.8k flows/s</dd></div>
          <div class="wide risk"><dt>潜在风险</dt><dd>{{ detail.falsePositiveRisk }}</dd></div>
          </dl>
          <label class="deploy-note"><span>部署备注</span><textarea v-model="note" rows="3" maxlength="500" :disabled="loading" :aria-invalid="Boolean(noteError)" aria-describedby="deploy-note-help deploy-note-error" /><small id="deploy-note-help">必填，12–500 个字符；备注会写入生命周期审计记录。</small><em v-if="noteError" id="deploy-note-error" role="alert">{{ noteError }}</em></label>
          <p v-if="error" class="deploy-error" role="alert">{{ error }}</p>
          <div class="deploy-actions">
            <DialogClose type="button" class="cancel" :disabled="loading">取消</DialogClose>
            <button type="submit" class="confirm" :disabled="loading || detail.record.stage !== 'confirmed'" :aria-busy="loading">{{ loading ? '正在同步传感器…' : meta.valid ? '确认并部署' : '校验并部署' }}</button>
          </div>
        </form>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>

<style>
.deploy-overlay{position:fixed;inset:0;z-index:70;background:var(--overlay);backdrop-filter:blur(2px)}.deploy-dialog{position:fixed;z-index:71;top:50%;left:50%;width:min(620px,calc(100vw - 28px));max-height:calc(100vh - 32px);transform:translate(-50%,-50%);overflow:auto;border:1px solid var(--border-strong);border-radius:12px;background:var(--surface-1);box-shadow:0 26px 80px rgba(0,0,0,.35)}
.deploy-title{display:flex;justify-content:space-between;align-items:center;padding:13px 16px;border-bottom:1px solid var(--border-subtle)}.deploy-title>div{display:flex;gap:10px;align-items:center}.deploy-title svg{color:var(--accent-strong)}.deploy-title span span{display:block;font-size:15px;font-weight:650}.deploy-title p{margin:3px 0 0;color:var(--text-tertiary);font-size:12px}.close-button{display:grid;width:28px;height:28px;place-items:center;border:0;background:transparent;color:var(--text-tertiary);cursor:pointer}
.deploy-warning{margin:13px 16px;padding:10px 12px;border-left:2px solid var(--status-warning);background:color-mix(in srgb,var(--status-warning) 7%,transparent)}.deploy-warning b{font-size:13px}.deploy-warning p{margin:3px 0 0;color:var(--text-tertiary);font-size:12px}.deploy-metrics{display:grid;grid-template-columns:1fr 1fr;margin:0 16px;border:1px solid var(--border-subtle)}.deploy-metrics div{display:flex;justify-content:space-between;gap:10px;min-width:0;padding:8px 10px;border-right:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)}.deploy-metrics div:nth-child(even),.deploy-metrics .wide{border-right:0}.deploy-metrics .wide{grid-column:1/-1}.deploy-metrics dt,.deploy-metrics dd{font-size:12px}.deploy-metrics dt{color:var(--text-tertiary)}.deploy-metrics dd{margin:0;color:var(--text-secondary);text-align:right}.deploy-metrics dd.good{color:var(--status-success)}.deploy-metrics dd.confirmed{color:var(--accent-strong);text-transform:capitalize}.deploy-metrics .risk dd{color:var(--status-warning)}
.deploy-note{display:block;margin:12px 16px}.deploy-note span{display:block;margin-bottom:5px;color:var(--text-tertiary);font-size:12px}.deploy-note textarea{width:100%;padding:8px 9px;resize:vertical;border:1px solid var(--border-default);border-radius:7px;background:var(--surface-2);color:var(--text-primary);font-size:13px;line-height:1.5}.deploy-note textarea[aria-invalid='true']{border-color:var(--status-error)}.deploy-note small,.deploy-note em{display:block;margin-top:4px;font-size:14px}.deploy-note small{color:var(--text-tertiary)}.deploy-note em{color:var(--status-error);font-style:normal}.deploy-error{margin:0 16px 12px;padding:8px 10px;border-left:2px solid var(--status-error);background:color-mix(in srgb,var(--status-error) 8%,transparent);color:var(--status-error);font-size:12px}.deploy-actions{display:flex;justify-content:flex-end;gap:8px;padding:11px 16px;border-top:1px solid var(--border-subtle);background:var(--surface-2)}.deploy-actions button{height:34px;padding:0 12px;border-radius:7px;font-size:12px;cursor:pointer}.deploy-actions .cancel{border:1px solid var(--border-default);background:var(--surface-1);color:var(--text-secondary)}.deploy-actions .confirm{border:1px solid color-mix(in srgb,var(--accent) 55%,var(--border-default));background:var(--accent-muted);color:var(--accent-strong)}.deploy-actions button:disabled{cursor:not-allowed;opacity:.5}
@media(max-width:580px){.deploy-metrics{grid-template-columns:1fr}.deploy-metrics div{border-right:0}.deploy-metrics .wide{grid-column:auto}}
</style>
