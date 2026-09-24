// 通用模态弹窗：居中覆盖层 + 卡片 + 页头 / 内容 / 页脚。
//
// 与 confirm.tsx 共用同一套视觉与交互约定（点遮罩关闭、Esc 关闭、busy 时锁死
// 关闭途径、页脚右对齐）。区别在语义与用途：
//   - 只是「确认 / 取消」→ 用 useConfirm()，它的 role=alertdialog 更准确；
//   - 需要表单、多选、说明区块等富交互 → 用本组件，内容由调用方给完整 JSX。
import * as React from 'react'
import { cn } from '../../lib/utils'

interface DialogProps {
  open: boolean
  onClose: () => void
  title: string
  description?: string
  /** 页脚动作区；调用方决定放哪些按钮 */
  footer?: React.ReactNode
  /** 处理中：锁死所有关闭途径，避免「弹窗已关、请求还在飞」导致重复提交 */
  busy?: boolean
  /** 额外宽度等样式（默认 max-w-md） */
  className?: string
  children: React.ReactNode
}

export function Dialog({ open, onClose, title, description, footer, busy, className, children }: DialogProps) {
  React.useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, busy, onClose])

  if (!open) return null
  return (
    <div
      data-slot="dialog-overlay"
      className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]"
      onClick={() => { if (!busy) onClose() }}
      aria-busy={busy}
    >
      <div
        role="dialog"
        aria-modal="true"
        data-slot="dialog-content"
        className={cn(
          'w-full max-w-md overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]',
          className,
        )}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-6 pb-3">
          <h2 data-slot="dialog-title" className="text-lg font-semibold leading-7">{title}</h2>
          {description && (
            <p data-slot="dialog-description" className="mt-2 text-sm leading-5 text-muted-foreground">{description}</p>
          )}
        </div>
        {/* 内容区限高并自行滚动：分组列表可能较长，避免把弹窗撑出视口 */}
        <div className="max-h-[60vh] overflow-y-auto px-6 pb-4">{children}</div>
        {footer && <div data-slot="dialog-footer" className="flex justify-end gap-3 p-6 pt-2">{footer}</div>}
      </div>
    </div>
  )
}
