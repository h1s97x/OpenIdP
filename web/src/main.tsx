import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { I18nProvider } from './i18n'
import { fontCss, FONT_KEY } from './hooks/useAppearance'
import { fetchSiteTimezone } from './lib/timezone'
import './index.css'

// 启动时应用界面字体偏好：未存偏好时也显式下发浏览器默认字族，
// 使首帧与外观设置面板显示的值（系统默认）一致，不出现字体闪烁。
function applySavedFont() {
  let saved: string | null = null
  try { saved = localStorage.getItem(FONT_KEY) } catch { /* 忽略 */ }
  const css = saved ? fontCss(saved) : fontCss('system')
  if (css) document.documentElement.style.setProperty('--app-font', css)
}
applySavedFont()

// 首帧前确定系统时区：所有时间展示（列表、审计、导出文件名）都按它渲染，
// 与后端日志、统计日界保持同一口径。失败时静默回落到默认 UTC+8。
fetchSiteTimezone()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <I18nProvider>
        <App />
      </I18nProvider>
    </BrowserRouter>
  </React.StrictMode>
)
