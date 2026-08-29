<script setup lang="ts">
import { CheckCircle2, ShieldCheck, X } from '~/utils/icons'

definePageMeta({ layout: false })

const route = useRoute()
const redirectTarget = computed(() => {
  const raw = String(route.query.redirect || '/')
  return raw.startsWith('/') && !raw.startsWith('//') ? raw : '/'
})

const password = ref('')
const submitting = ref(false)
const errorMessage = ref('')
const status = ref<{ required: boolean; authenticated: boolean } | null>(null)

onMounted(async () => {
  try {
    // Untyped signature: Nuxt's typed route matcher overflows the type checker here (TS2321).
    const statusFetch = $fetch as unknown as (url: string) => Promise<{ required: boolean; authenticated: boolean }>
    status.value = await statusFetch('/api/auth/status')
    if (status.value && !status.value.required) {
      await navigateTo('/', { replace: true })
    }
  } catch {
    // Probe failures leave the form usable; the server still validates on submit.
  }
})

async function submit() {
  if (!password.value || submitting.value) return
  submitting.value = true
  errorMessage.value = ''
  try {
    await $fetch('/api/auth/login', { method: 'POST', body: { password: password.value } })
    await navigateTo(redirectTarget.value, { replace: true })
  } catch (error) {
    const value = error as { data?: { statusMessage?: string; message?: string }; message?: string }
    errorMessage.value = value.data?.statusMessage || value.data?.message || '登录失败，请稍后重试。'
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="login-shell">
    <form class="login-card" @submit.prevent="submit">
      <div class="brand"><span><ShieldCheck :size="18" /></span><div><p>EVONIDS · NETWORK DEFENSE</p><h1>控制台登录</h1></div></div>
      <p class="hint">该控制台已启用访问口令。口令由部署者通过 <code>NUXT_CONSOLE_PASSWORD</code> 配置，会话默认保持 24 小时。</p>
      <label>
        <span>访问口令</span>
        <input v-model="password" type="password" name="password" autocomplete="current-password" placeholder="输入部署口令" required :disabled="submitting">
      </label>
      <div v-if="errorMessage" class="error" role="alert"><X :size="13" />{{ errorMessage }}<button type="button" aria-label="关闭错误提示" @click="errorMessage = ''"><X :size="12" /></button></div>
      <button class="submit" type="submit" :disabled="submitting || !password">{{ submitting ? '验证中…' : '进入控制台' }}</button>
      <div v-if="status && !status.required" class="open-note"><CheckCircle2 :size="13" />当前未启用登录保护，将直接进入控制台。</div>
      <footer>登录仅保护控制台与 BFF；检测平面的传感器与 API 令牌仍由服务端独立管理。</footer>
    </form>
  </div>
</template>

<style scoped>
.login-shell {
  display: grid;
  place-items: center;
  min-height: 100vh;
  padding: 24px;
  background:
    radial-gradient(900px 420px at 18% -8%, color-mix(in srgb, var(--accent) 14%, transparent), transparent),
    var(--background);
}

.login-card {
  display: grid;
  gap: 14px;
  width: min(420px, 100%);
  padding: 26px 26px 20px;
  border: 1px solid var(--border-default);
  border-radius: 12px;
  background: var(--surface-1);
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.35);
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}

.brand > span {
  display: grid;
  width: 38px;
  height: 38px;
  place-items: center;
  border: 1px solid color-mix(in srgb, var(--accent) 30%, var(--border-default));
  border-radius: 9px;
  background: var(--accent-muted);
  color: var(--accent-strong);
}

.brand p {
  margin: 0;
  color: var(--text-tertiary);
  font-size: 11px;
  letter-spacing: 0.08em;
}

.brand h1 {
  margin: 2px 0 0;
  font-size: 19px;
  font-weight: 650;
}

.hint {
  margin: 0;
  color: var(--text-tertiary);
  font-size: 12.5px;
  line-height: 1.55;
}

.hint code {
  color: var(--text-secondary);
  font-size: 11.5px;
}

label {
  display: grid;
  gap: 6px;
}

label span {
  color: var(--text-tertiary);
  font-size: 12.5px;
}

input {
  height: 40px;
  padding: 0 12px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--surface-2);
  color: var(--text-primary);
  font-size: 14px;
}

input:focus {
  outline: 2px solid color-mix(in srgb, var(--accent) 55%, transparent);
  outline-offset: 1px;
  border-color: transparent;
}

.error {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 10px;
  border: 1px solid color-mix(in srgb, var(--status-error) 38%, var(--border-default));
  border-radius: 8px;
  background: color-mix(in srgb, var(--status-error) 8%, var(--surface-2));
  color: var(--status-error);
  font-size: 13px;
}

.error button {
  display: grid;
  place-items: center;
  margin-left: auto;
  border: 0;
  background: transparent;
  color: var(--text-tertiary);
  cursor: pointer;
}

.submit {
  height: 40px;
  border: 0;
  border-radius: 8px;
  background: var(--accent);
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
}

.submit:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.open-note {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-tertiary);
  font-size: 12.5px;
}

footer {
  padding-top: 4px;
  border-top: 1px solid var(--border-subtle);
  color: var(--text-tertiary);
  font-size: 11.5px;
  line-height: 1.5;
}
</style>
