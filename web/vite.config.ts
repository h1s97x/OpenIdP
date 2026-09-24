import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// 默认字体 CDN 基址：可在构建期用环境变量覆盖。
// 私有化 / 离线部署设为 "-"（或空）即可完全去掉外部请求，
// 与后端 CDN_BASE_URL 的语义保持一致（见 api/internal/config）。
const DEFAULT_CDN_BASE_URL = ''

// 内置字体样式表清单（相对 CDN 基址）。
const FONT_STYLESHEETS = [
  'fonts/ZhuqueFangsong/result.css',
  'fonts/JinBuTi/result.css',
  'fonts/GuanKiapTsingKhai/result.css',
]

// cdnFonts 在构建期把 index.html 里的 <!-- cdn:fonts --> 占位替换为实际的
// 字体样式表引用。
//
// 此前这三个地址硬编码在 index.html 中：私有化 / 离线部署若没手工改源码，
// 每个访客都会向第三方域发起请求（隐私泄漏，且 CDN 不可达时首屏样式阻塞）。
// 改为构建期注入后，关闭外部 CDN 只需一个环境变量。
function cdnFonts(): Plugin {
  const raw = process.env.CDN_BASE_URL ?? DEFAULT_CDN_BASE_URL
  const base = raw.trim().replace(/\/+$/, '')
  const tags =
    base === '' || base === '-'
      ? '<!-- 外部字体 CDN 已关闭（CDN_BASE_URL 为空或 -） -->'
      : [
          `    <link rel="preconnect" href="${base}" crossorigin />`,
          ...FONT_STYLESHEETS.map((p) => `    <link rel="stylesheet" href="${base}/${p}" />`),
        ].join('\n')
  return {
    name: 'openidp-cdn-fonts',
    transformIndexHtml(html) {
      return html.replace('<!-- cdn:fonts -->', tags)
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), cdnFonts()],
  server: {
    port: 5173,
    // 开发模式由 Go 统一入口（:6099）反向代理到本 dev server，
    // API 路径已由 Go 侧管理，无需在此配置 proxy 白名单。
    // 如需直接访问 Vite（绕过 Go），可自行按需恢复 proxy 配置。
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      output: {
        // 图表库（recharts + d3 依赖）体积占比最高且只在总览/管理仪表盘使用，
        // 单独分包后首屏不必下载，同时也让业务代码改动不影响该 chunk 的长期缓存。
        manualChunks: {
          charts: ['recharts'],
          react: ['react', 'react-dom', 'react-router-dom'],
          i18n: ['./src/i18n/index.tsx'],
        },
      },
    },
  },
})
