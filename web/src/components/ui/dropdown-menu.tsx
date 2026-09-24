import * as React from 'react'
import { createPortal } from 'react-dom'
import { cn } from '../../lib/utils'

// 轻量 DropdownMenu：点击外部或按 Esc 关闭。
// 浮层通过 createPortal 挂到 body 上并使用 fixed 定位，避免被表格 / 卡片等
// 带 overflow 的祖先容器裁切（例如「设备会话」表格内的三点菜单）。
interface DropdownMenuProps {
  open?: boolean
  onOpenChange?: (v: boolean) => void
  children: React.ReactNode
  modal?: boolean
}

const VIEWPORT_GAP = 8 // 浮层与视口边缘的最小间距
const TRIGGER_GAP = 6 // 浮层与触发器之间的间距

interface DropdownMenuCtx {
  open: boolean
  setOpen: (v: boolean) => void
  triggerRef: React.MutableRefObject<HTMLElement | null>
  contentRef: React.MutableRefObject<HTMLDivElement | null>
}

const DropdownMenuContext = React.createContext<DropdownMenuCtx>({
  open: false,
  setOpen: () => {},
  triggerRef: { current: null },
  contentRef: { current: null },
})

export function DropdownMenu({ open, onOpenChange, children }: DropdownMenuProps) {
  const [inner, setInner] = React.useState(false)
  const isOpen = open ?? inner
  const setOpen = (v: boolean) => {
    setInner(v)
    onOpenChange?.(v)
  }
  const ref = React.useRef<HTMLDivElement>(null)
  const triggerRef = React.useRef<HTMLElement | null>(null)
  const contentRef = React.useRef<HTMLDivElement | null>(null)

  React.useEffect(() => {
    if (!isOpen) return
    const onDoc = (e: MouseEvent) => {
      const target = e.target as Node
      // 触发器与浮层（已挂到 body）都不算「外部点击」
      if (ref.current && ref.current.contains(target)) return
      if (contentRef.current && contentRef.current.contains(target)) return
      setOpen(false)
    }
    const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onEsc)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onEsc)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen])

  const value = React.useMemo<DropdownMenuCtx>(
    () => ({ open: isOpen, setOpen, triggerRef, contentRef }),
    // setOpen 每次渲染都是新函数，这里保持引用稳定由 useMemo 依赖控制。
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [isOpen],
  )

  return (
    <DropdownMenuContext.Provider value={value}>
      <div ref={ref} className="relative inline-block">{children}</div>
    </DropdownMenuContext.Provider>
  )
}

export function DropdownMenuTrigger({
  asChild,
  children,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { asChild?: boolean }) {
  const ctx = React.useContext(DropdownMenuContext)

  // 记录触发器节点，供浮层计算 fixed 定位。
  const setRef = React.useCallback(
    (node: HTMLElement | null) => { ctx.triggerRef.current = node },
    [ctx.triggerRef],
  )

  if (asChild && React.isValidElement(children)) {
    const child = children as React.ReactElement<any>
    return React.cloneElement(child, {
      ref: setRef,
      onClick: (e: React.MouseEvent) => {
        child.props.onClick?.(e)
        ctx.setOpen(!ctx.open)
      },
      'aria-haspopup': 'menu',
      'aria-expanded': ctx.open,
      'data-state': ctx.open ? 'open' : 'closed',
      ...props,
    })
  }
  return (
    <button
      type="button"
      ref={setRef as unknown as React.Ref<HTMLButtonElement>}
      data-slot="dropdown-menu-trigger"
      aria-haspopup="menu"
      aria-expanded={ctx.open}
      data-state={ctx.open ? 'open' : 'closed'}
      onClick={() => ctx.setOpen(!ctx.open)}
      {...props}
    >
      {children}
    </button>
  )
}

export function DropdownMenuContent({
  className,
  align = 'end',
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { align?: 'start' | 'end' | 'center' }) {
  const ctx = React.useContext(DropdownMenuContext)
  const [pos, setPos] = React.useState<{ top: number; left: number } | null>(null)

  // 依据触发器的视口坐标计算浮层位置：优先向下展开，空间不足时向上翻转，
  // 两侧越界时向内收拢，保证菜单始终完整可见。
  React.useLayoutEffect(() => {
    if (!ctx.open) {
      setPos(null)
      return
    }
    const update = () => {
      const trigger = ctx.triggerRef.current
      if (!trigger) return
      const r = trigger.getBoundingClientRect()
      const el = ctx.contentRef.current
      const w = el?.offsetWidth ?? 0
      const h = el?.offsetHeight ?? 0
      const vw = window.innerWidth
      const vh = window.innerHeight

      let left = align === 'end' ? r.right - w : align === 'center' ? r.left + r.width / 2 - w / 2 : r.left
      left = Math.max(VIEWPORT_GAP, Math.min(left, Math.max(VIEWPORT_GAP, vw - w - VIEWPORT_GAP)))

      let top = r.bottom + TRIGGER_GAP
      if (h > 0) {
        if (top + h > vh - VIEWPORT_GAP) {
          const above = r.top - TRIGGER_GAP - h
          top = above >= VIEWPORT_GAP ? above : Math.max(VIEWPORT_GAP, vh - h - VIEWPORT_GAP)
        }
      }
      setPos({ top, left })
    }
    update()
    // capture 模式监听任意祖先容器的滚动，保证浮层跟随触发器
    window.addEventListener('scroll', update, true)
    window.addEventListener('resize', update)
    return () => {
      window.removeEventListener('scroll', update, true)
      window.removeEventListener('resize', update)
    }
  }, [ctx.open, align, ctx.triggerRef, ctx.contentRef])

  if (!ctx.open) return null

  return createPortal(
    <div
      ref={(node) => { ctx.contentRef.current = node }}
      data-slot="dropdown-menu-content"
      data-state="open"
      style={{
        position: 'fixed',
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        // 首次测量完成前先隐藏，避免定位计算前出现一帧错位
        visibility: pos ? 'visible' : 'hidden',
      }}
      className={cn(
        // z-[105]：高于侧栏(40)/顶栏(50)/进度条(60)/Toast(100)，低于确认与弹窗遮罩(110)
        'z-[105] min-w-[10rem] overflow-hidden rounded-lg border bg-popover p-1 text-popover-foreground shadow-lg',
        className
      )}
      {...props}
    >
      {children}
    </div>,
    document.body,
  )
}

export function DropdownMenuItem({
  className,
  onClick,
  disabled,
  children,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const ctx = React.useContext(DropdownMenuContext)
  return (
    <button
      type="button"
      role="menuitem"
      data-slot="dropdown-menu-item"
      disabled={disabled}
      data-disabled={disabled ? true : undefined}
      onClick={(e) => {
        if (disabled) return
        onClick?.(e)
        ctx.setOpen(false)
      }}
      className={cn(
        'relative flex w-full cursor-default select-none items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&>svg]:size-4 [&>svg]:shrink-0 [&>svg]:text-muted-foreground',
        className
      )}
      {...props}
    >
      {children}
    </button>
  )
}

export function DropdownMenuSeparator({ className }: { className?: string }) {
  return <div className={cn('-mx-1 my-1 h-px bg-border', className)} />
}

export function DropdownMenuLabel({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div
      data-slot="dropdown-menu-label"
      className={cn('px-2 py-1.5 text-xs font-medium text-muted-foreground', className)}
    >
      {children}
    </div>
  )
}
