// 外观偏好统一管理：主题、侧栏样式、布局、界面字体、语言。
// 统一提供外观偏好的共享状态，使设置面板的改动即时生效并持久化。
import * as React from 'react'

export const FONT_KEY = 'openidp.font'
export const SIDEBAR_KEY = 'openidp.sidebar'
export const LAYOUT_KEY = 'openidp.layout'

// 默认值集中在这里，供外观抽屉的「单项重置」比对、以及整宽重置回滚。
// 此前散落在 read() 的 fallback 字面量里，抽屉要判断「是否已改动」就只能
// 各自硬编码一份，改默认值时必然漂移。
export const DEFAULT_SIDEBAR: SidebarStyle = 'inset'
export const DEFAULT_LAYOUT: LayoutStyle = 'default'
export const DEFAULT_FONT: FontKey = 'system'

export type SidebarStyle = 'inset' | 'floating' | 'standard'
export type LayoutStyle = 'default' | 'icon' | 'offcanvas'
export type FontKey = 'system' | 'zhuque-fangsong' | 'jinbuti' | 'guankiap-tsingkhai'

export const SIDEBAR_VALUES = ['inset', 'floating', 'standard'] as const
export const LAYOUT_VALUES = ['default', 'icon', 'offcanvas'] as const
export const FONT_VALUES = ['system', 'zhuque-fangsong', 'jinbuti', 'guankiap-tsingkhai'] as const

// 浏览器默认字体族：system 档显式下发该字族，语义即「使用浏览器默认字体」。
// 不再返回空串 —— 空串会回落到 --font-sans 的首项（朱雀仿宋），
// 导致选择「系统默认」时看到的并非浏览器默认字体。
export const BROWSER_DEFAULT_FONT =
  'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif'

export function fontCss(key: string): string {
  switch (key) {
    case 'zhuque-fangsong': return '"Zhuque Fangsong (technical preview)", serif'
    case 'jinbuti': return '"DingTalk JinBuTi", serif'
    case 'guankiap-tsingkhai': return '"GuanKiapTsingKhai", serif'
    default: return BROWSER_DEFAULT_FONT
  }
}

function read<T extends string>(key: string, fallback: T, values: readonly string[]): T {
  try {
    const saved = localStorage.getItem(key)
    return (values as readonly string[]).includes(saved ?? '') ? (saved as T) : fallback
  } catch {
    return fallback
  }
}

// 模块级广播，让 AppShell / AppearanceDrawer 等组件保持同步
const listeners = new Set<() => void>()

interface AppearanceValue {
  sidebar: SidebarStyle
  setSidebar: (v: SidebarStyle) => void
  layout: LayoutStyle
  setLayout: (v: LayoutStyle) => void
  font: FontKey
  applyFont: (key: FontKey) => void
  reset: () => void
  /** 各项默认值：外观抽屉据此决定是否显示单项重置按钮 */
  defaultSidebar: SidebarStyle
  defaultLayout: LayoutStyle
  defaultFont: FontKey
}

export function useAppearance(): AppearanceValue {
  const [sidebar, setSidebarState] = React.useState<SidebarStyle>(() =>
    read(SIDEBAR_KEY, DEFAULT_SIDEBAR, SIDEBAR_VALUES))
  const [layout, setLayoutState] = React.useState<LayoutStyle>(() =>
    read(LAYOUT_KEY, DEFAULT_LAYOUT, LAYOUT_VALUES))
  const [font, setFontState] = React.useState<FontKey>(() =>
    read(FONT_KEY, DEFAULT_FONT, FONT_VALUES))

  // 订阅外部变更（例如另一个面板修改了偏好）
  React.useEffect(() => {
    const sync = () => {
      setSidebarState(read(SIDEBAR_KEY, DEFAULT_SIDEBAR, SIDEBAR_VALUES))
      setLayoutState(read(LAYOUT_KEY, DEFAULT_LAYOUT, LAYOUT_VALUES))
      setFontState(read(FONT_KEY, DEFAULT_FONT, FONT_VALUES))
    }
    listeners.add(sync)
    return () => { listeners.delete(sync) }
  }, [])

  const setSidebar = React.useCallback((v: SidebarStyle) => {
    try { localStorage.setItem(SIDEBAR_KEY, v) } catch { /* 忽略 */ }
    setSidebarState(v)
    listeners.forEach((fn) => fn())
  }, [])

  const setLayout = React.useCallback((v: LayoutStyle) => {
    try { localStorage.setItem(LAYOUT_KEY, v) } catch { /* 忽略 */ }
    setLayoutState(v)
    listeners.forEach((fn) => fn())
  }, [])

  const applyFont = React.useCallback((key: FontKey) => {
    try { localStorage.setItem(FONT_KEY, key) } catch { /* 忽略 */ }
    setFontState(key)
    document.documentElement.style.setProperty('--app-font', fontCss(key))
    listeners.forEach((fn) => fn())
  }, [])

  const reset = React.useCallback(() => {
    setSidebar(DEFAULT_SIDEBAR)
    setLayout(DEFAULT_LAYOUT)
    applyFont(DEFAULT_FONT)
  }, [setSidebar, setLayout, applyFont])

  return {
    sidebar, setSidebar, layout, setLayout, font, applyFont, reset,
    defaultSidebar: DEFAULT_SIDEBAR,
    defaultLayout: DEFAULT_LAYOUT,
    defaultFont: DEFAULT_FONT,
  }
}
