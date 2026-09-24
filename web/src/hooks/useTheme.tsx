import * as React from 'react'

type Theme = 'light' | 'dark' | 'system'

// 默认主题：与初始化逻辑里的兜底值保持同源，供外观抽屉的「单项重置」比对与回滚。
const DEFAULT_THEME: Theme = 'system'

const ThemeContext = React.createContext<{
  theme: Theme
  setTheme: (t: Theme) => void
  toggleTheme: () => void
  /** 实际生效的明暗模式（system 会解析为 light/dark） */
  resolvedTheme: 'light' | 'dark'
  /** 默认主题，外观抽屉用它决定是否显示单项重置按钮 */
  defaultTheme: Theme
  /** 仅把主题恢复为默认值（外观抽屉的整宽重置按钮会调用） */
  resetTheme: () => void
}>({
  theme: DEFAULT_THEME, setTheme: () => {}, toggleTheme: () => {},
  resolvedTheme: 'light', defaultTheme: DEFAULT_THEME, resetTheme: () => {},
})

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = React.useState<Theme>(() => {
    try {
      const saved = localStorage.getItem('theme')
      if (saved === 'light' || saved === 'dark' || saved === 'system') return saved
    } catch { /* 隐私模式/禁用存储时忽略 */ }
    return DEFAULT_THEME
  })
  // 实际生效的明暗模式：供图标等需要按“真实当前外观”展示的组件使用
  const [resolvedTheme, setResolvedTheme] = React.useState<'light' | 'dark'>(() => {
    try {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    } catch { return 'light' }
  })

  React.useEffect(() => {
    const root = document.documentElement
    const apply = (t: Theme) => {
      const isDark = t === 'dark' || (t === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)
      root.classList.toggle('dark', isDark)
      setResolvedTheme(isDark ? 'dark' : 'light')
    }
    apply(theme)
    // system 模式下监听系统主题变化，实时跟随
    if (theme === 'system') {
      const mq = window.matchMedia('(prefers-color-scheme: dark)')
      const onChange = () => apply('system')
      mq.addEventListener?.('change', onChange)
      return () => mq.removeEventListener?.('change', onChange)
    }
  }, [theme])

  const setTheme = (t: Theme) => {
    try { localStorage.setItem('theme', t) } catch { /* 忽略存储异常 */ }
    setThemeState(t)
  }

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }

  const resetTheme = () => {
    try { localStorage.removeItem('theme') } catch { /* 忽略存储异常 */ }
    setThemeState(DEFAULT_THEME)
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme, resolvedTheme, defaultTheme: DEFAULT_THEME, resetTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  return React.useContext(ThemeContext)
}
