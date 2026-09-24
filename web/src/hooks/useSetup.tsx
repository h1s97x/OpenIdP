import * as React from 'react'
import { api } from '../lib/api'
import { useI18n } from '../i18n'

// 首次部署初始化状态由全 app 共享：
//  - SetupGuard 依据它决定是否把页面劫持到 /setup；
//  - SetupPage 初始化成功后调用 markInitialized()，让守卫立即放行，
//    否则守卫仍认为「未初始化」，会把刚跳出的 /setup 又拉回去，造成
//    两个路由互相重定向、页面持续闪烁。
//
// 单独成文件而不是放在 App.tsx：SetupPage 也要读取/写入该状态，
// 若从 App.tsx 导出会形成循环依赖。

interface SetupCtx {
  checked: boolean
  needsSetup: boolean
  markInitialized: () => void
}

const SetupContext = React.createContext<SetupCtx>({
  checked: false,
  needsSetup: false,
  markInitialized: () => {},
})

export function useSetup() {
  return React.useContext(SetupContext)
}

export function SetupProvider({ children }: { children: React.ReactNode }) {
  const [checked, setChecked] = React.useState(false)
  const [needsSetup, setNeedsSetup] = React.useState(false)

  React.useEffect(() => {
    let cancelled = false
    api
      .setupStatus()
      .then((s: any) => {
        if (cancelled) return
        setNeedsSetup(!s?.initialized)
      })
      .catch(() => {
        // 读取失败时不阻塞：按「已初始化」处理，避免把正常部署误锁在 /setup。
        if (!cancelled) setNeedsSetup(false)
      })
      .finally(() => {
        if (!cancelled) setChecked(true)
      })
    return () => { cancelled = true }
  }, [])

  const markInitialized = React.useCallback(() => {
    setNeedsSetup(false)
    setChecked(true)
  }, [])

  const value = React.useMemo<SetupCtx>(
    () => ({ checked, needsSetup, markInitialized }),
    [checked, needsSetup, markInitialized],
  )

  return <SetupContext.Provider value={value}>{children}</SetupContext.Provider>
}

// BootSplash 是应用首帧（初始化状态探测完成前）的统一占位。
// 之前这里返回 null（纯白屏），紧接着又渲染各自的 loading，两次切换即为「闪烁」的来源。
export function BootSplash() {
  const { t } = useI18n()
  return (
    <div className="flex min-h-svh items-center justify-center bg-background">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
        {t('common.loading')}
      </div>
    </div>
  )
}
