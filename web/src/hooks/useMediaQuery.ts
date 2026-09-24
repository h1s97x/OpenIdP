import * as React from 'react'

// 响应式媒体查询 Hook：订阅指定断点并返回是否命中。
// 常用于移动端布局判断（如 < 1024px 视为移动端）。
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = React.useState<boolean>(() =>
    typeof window !== 'undefined' ? window.matchMedia(query).matches : false
  )

  React.useEffect(() => {
    const mql = window.matchMedia(query)
    const onChange = () => setMatches(mql.matches)
    onChange()
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [query])

  return matches
}

// 是否为移动端（< lg / 1024px）
export function useIsMobile(): boolean {
  return !useMediaQuery('(min-width: 1024px)')
}
