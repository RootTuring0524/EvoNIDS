import tailwindcss from '@tailwindcss/vite'

export default defineNuxtConfig({
  compatibilityDate: '2026-07-01',
  devtools: { enabled: false },
  modules: ['@pinia/nuxt', '@vueuse/nuxt', '@nuxt/eslint'],
  css: ['~/assets/css/main.css'],
  vite: {
    plugins: [tailwindcss()],
  },
  runtimeConfig: {
    backend: {
      apiBase: process.env.NUXT_BACKEND_API_BASE || 'http://127.0.0.1:8000/api/v1',
      sensorToken: process.env.NUXT_SENSOR_INGEST_TOKEN || '',
      adminToken: process.env.NUXT_BACKEND_ADMIN_TOKEN || '',
    },
    deepseek: {
      apiBase: process.env.NUXT_DEEPSEEK_API_BASE || '',
      apiKey: process.env.NUXT_DEEPSEEK_API_KEY || '',
      model: process.env.NUXT_DEEPSEEK_MODEL || '',
    },
    console: {
      // Set NUXT_CONSOLE_PASSWORD to require login for every console page and
      // BFF route; an empty value keeps the console open (local dev/demo default).
      password: process.env.NUXT_CONSOLE_PASSWORD || '',
      sessionHours: Number(process.env.NUXT_CONSOLE_SESSION_HOURS) || 24,
    },
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE || '/api',
      useMockApi: process.env.NUXT_PUBLIC_USE_MOCK_API !== 'false',
    },
  },
  app: {
    head: {
      htmlAttrs: { lang: 'zh-CN' },
      title: 'EvoNIDS · 智能入侵检测与规则演进平台',
      script: [
        {
          key: 'evonids-theme-init',
          tagPosition: 'head',
          innerHTML: `(function(){try{var mode=localStorage.getItem('evonids-theme')||'dark';var valid=mode==='dark'||mode==='light'||mode==='system';if(!valid)mode='dark';var resolved=mode==='system'?(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):mode;document.documentElement.dataset.theme=resolved;document.documentElement.style.colorScheme=resolved;}catch(e){document.documentElement.dataset.theme='dark';}})();`,
        },
      ],
      meta: [
        {
          name: 'description',
          content: '面向安全运营团队的网络异常检测、证据研判与规则闭环演进平台。',
        },
      ],
    },
  },
  typescript: {
    // `pnpm typecheck` runs vue-tsc explicitly; keeping it separate avoids a Windows PATH
    // issue in Nuxt's production-builder child process while preserving full CI checking.
    typeCheck: false,
  },
})
