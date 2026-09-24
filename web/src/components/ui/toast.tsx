// 全局 Toast 通知系统：右下角弹窗，支持成功/错误/信息/警告四种类型。
// 通过 useToast() 在任何组件中触发。二次确认弹窗见 components/ui/confirm.tsx。
import * as React from 'react'
import { CheckCircle2, XCircle, Info, AlertTriangle, X } from 'lucide-react'
import { cn } from '../../lib/utils'
import { useI18n } from '../../i18n'

export type ToastType = 'success' | 'error' | 'info' | 'warning'

export interface Toast {
  id: number
  type: ToastType
  title: string
  description?: string
  duration?: number
}

interface ToastContextValue {
  toast: (opts: Omit<Toast, 'id'>) => void
  success: (title: string, description?: string) => void
  error: (title: string, description?: string) => void
  info: (title: string, description?: string) => void
  warning: (title: string, description?: string) => void
}

const ToastContext = React.createContext<ToastContextValue>({
  toast: () => {},
  success: () => {},
  error: () => {},
  info: () => {},
  warning: () => {},
})

let toastSeq = 0

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([])

  const dismiss = React.useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const toast = React.useCallback((opts: Omit<Toast, 'id'>) => {
    const id = ++toastSeq
    const item: Toast = { id, type: opts.type, title: opts.title, description: opts.description, duration: opts.duration ?? 4500 }
    setToasts((prev) => [...prev.slice(-4), item])
    if (item.duration && item.duration > 0) {
      window.setTimeout(() => dismiss(id), item.duration)
    }
  }, [dismiss])

  const value = React.useMemo<ToastContextValue>(() => ({
    toast,
    success: (title, description) => toast({ type: 'success', title, description }),
    error: (title, description) => toast({ type: 'error', title, description }),
    info: (title, description) => toast({ type: 'info', title, description }),
    warning: (title, description) => toast({ type: 'warning', title, description }),
  }), [toast])

  // Esc 关闭最新的一条 toast。
  // 此前每个 ToastCard 各自注册一个 document 级 keydown 监听：屏幕上 N 条 toast
  // 就有 N 个监听器，按一次 Esc 会把它们全部关掉，而不是只关当前那一条。
  // 监听器统一上提到 Provider，只挂一个。
  React.useEffect(() => {
    if (toasts.length === 0) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      setToasts((prev) => (prev.length === 0 ? prev : prev.slice(0, -1)))
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [toasts.length])

  return (
    <ToastContext.Provider value={value}>
      {children}
      {/* 右下角 Toast 容器 */}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(22rem,calc(100vw-2rem))] flex-col gap-2">
        {toasts.map((t) => (
          <ToastCard key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

function ToastCard({ toast: t, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const { t: tr } = useI18n()

  const icons: Record<ToastType, React.ReactNode> = {
    success: <CheckCircle2 className="size-5 text-success" />,
    error: <XCircle className="size-5 text-destructive" />,
    info: <Info className="size-5 text-primary" />,
    warning: <AlertTriangle className="size-5 text-warning" />,
  }

  // 错误 / 警告需要即时打断播报（alert），其余用 status 礼貌播报即可。
  const isUrgent = t.type === 'error' || t.type === 'warning'

  return (
    <div
      role={isUrgent ? 'alert' : 'status'}
      data-slot="toast"
      className={cn(
        'pointer-events-auto flex w-full items-start gap-3 rounded-xl border bg-popover p-4 text-popover-foreground shadow-lg',
        'animate-[toast-in_0.2s_ease-out]'
      )}
    >
      <span className="mt-0.5 shrink-0">{icons[t.type]}</span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold">{t.title}</div>
        {t.description && <div className="mt-1 text-xs leading-5 text-muted-foreground">{t.description}</div>}
      </div>
      <button
        onClick={onDismiss}
        aria-label={tr('common.close')}
        className="flex size-6 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
      >
        <X className="size-3.5" />
      </button>
    </div>
  )
}

export function useToast() {
  return React.useContext(ToastContext)
}
