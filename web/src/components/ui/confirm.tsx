// 二次确认弹窗：对退出登录、删除、撤销等危险操作提供确认步骤。
// 布局：居中覆盖层 + 圆角卡片 + 标题/描述 + 右下角操作区（无分割线）。
import * as React from 'react'
import { Loader2 } from 'lucide-react'
import { Button } from './button'
import { useI18n } from '../../i18n'

export interface ConfirmOptions {
  title: string
  description?: string
  confirmText?: string
  cancelText?: string
  variant?: 'default' | 'destructive'
  /**
   * 传了 onConfirm 时，弹窗会一直等到它 resolve 才关闭，期间显示 loading
   * 并锁死所有关闭途径（遮罩 / Esc / 关闭按钮 / 取消按钮）。
   *
   * 不传时退化为「点确认立即 resolve(true)」，调用方自己在 await 之后发请求。
   * 这种模式下「弹窗关闭」到「请求完成」之间存在窗口，按钮可重复点击，
   * 因此破坏性操作应优先传 onConfirm。
   */
  onConfirm?: () => void | Promise<void>
}

interface ConfirmContextValue {
  confirm: (opts: ConfirmOptions) => Promise<boolean>
}

const ConfirmContext = React.createContext<ConfirmContextValue>({ confirm: async () => false })

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const { t } = useI18n()
  const [state, setState] = React.useState<(ConfirmOptions & { resolving?: (v: boolean) => void }) | null>(null)
  // onConfirm 执行期间为 true：此时不允许以任何方式关闭弹窗，
  // 否则「弹窗已关、请求还在飞」，用户能再次点击按钮造成重复提交。
  const [busy, setBusy] = React.useState(false)

  const confirm = React.useCallback((opts: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      setState({ ...opts, resolving: resolve })
    })
  }, [])

  const close = React.useCallback((result: boolean) => {
    if (busy) return
    state?.resolving?.(result)
    setState(null)
  }, [state, busy])

  React.useEffect(() => {
    if (!state) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [state, close])

  // 点击确认：有 onConfirm 时等它跑完再关闭，并把它的异常向上抛给调用方，
  // 由调用方决定如何提示（通常走右上角 toast）。
  const handleConfirm = async () => {
    if (busy) return
    if (!state?.onConfirm) {
      close(true)
      return
    }
    setBusy(true)
    try {
      await state.onConfirm()
      state.resolving?.(true)
      setState(null)
    } catch {
      // 失败时保持弹窗打开，让用户能直接重试或取消；
      // resolve(false) 表示「未执行成功」，调用方据此不再继续后续流程。
      state.resolving?.(false)
      setState(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <ConfirmContext.Provider value={{ confirm }}>
      {children}
      {state && (
        <div
          data-slot="alert-dialog-overlay"
          className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]"
          onClick={() => close(false)}
          aria-busy={busy}
        >
          <div
            role="alertdialog"
            aria-modal="true"
            data-slot="alert-dialog-content"
            className="w-full max-w-md overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 pb-3">
              <h2 data-slot="alert-dialog-title" className="text-lg font-semibold leading-7">{state.title}</h2>
              {state.description && (
                <p data-slot="alert-dialog-description" className="mt-2 text-sm leading-5 text-muted-foreground">{state.description}</p>
              )}
            </div>
            <div data-slot="alert-dialog-footer" className="flex justify-end gap-3 p-6 pt-3">
              <Button variant="outline" className="h-10 px-5" onClick={() => close(false)} disabled={busy}>
                {state.cancelText ?? t('common.cancel')}
              </Button>
              <Button variant={state.variant ?? 'destructive'} className="h-10 px-5" onClick={handleConfirm} disabled={busy}>
                {busy && <Loader2 className="size-4 animate-spin" />}
                {state.confirmText ?? t('common.confirm')}
              </Button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  )
}

export function useConfirm() {
  return React.useContext(ConfirmContext)
}
