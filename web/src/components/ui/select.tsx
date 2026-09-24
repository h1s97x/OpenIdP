import * as React from 'react'
import { Check, ChevronDown } from 'lucide-react'
import { cn } from '../../lib/utils'
import { useI18n } from '../../i18n'

interface SelectProps {
  value?: string
  defaultValue?: string
  placeholder?: string
  onValueChange?: (v: string) => void
  children: React.ReactNode
  className?: string
  id?: string
  ariaLabel?: string
  /** 触发按钮左侧图标（如 Languages） */
  icon?: React.ReactNode
  size?: 'default' | 'sm'
}

export function Select({
  value,
  defaultValue,
  placeholder,
  onValueChange,
  children,
  className,
  id,
  ariaLabel,
  icon,
  size = 'default',
}: SelectProps) {
  // 未选中时的兜底文案走 i18n，避免非中文界面里残留中文。
  const { t } = useI18n()
  const [open, setOpen] = React.useState(false)
  const [inner, setInner] = React.useState(defaultValue ?? '')
  // 浮层的展开方向：下方空间不足时翻到触发器上方，避免在弹层/滚动容器底部被裁切。
  const [placement, setPlacement] = React.useState<'bottom' | 'top'>('bottom')
  const current = value ?? inner
  const ref = React.useRef<HTMLDivElement>(null)
  const listRef = React.useRef<HTMLDivElement>(null)

  React.useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onEsc)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onEsc)
    }
  }, [])

  // 计算展开方向：以「会裁剪浮层的最近祖先」的下边缘为界，
  // 下方放不下且上方更宽裕时，把浮层翻到触发器上方显示。
  const updatePlacement = React.useCallback(() => {
    const trigger = ref.current?.querySelector('[data-slot="select-trigger"]')
    if (!(trigger instanceof HTMLElement)) return
    const rect = trigger.getBoundingClientRect()
    const panelHeight = listRef.current?.offsetHeight ?? 0
    // 最近的可滚动/裁剪祖先，遍历到 body 为止
    let boundary = window.innerHeight
    let node: HTMLElement | null = trigger.parentElement
    while (node && node !== document.body) {
      const style = window.getComputedStyle(node)
      const clips = /(auto|scroll|hidden|clip)/.test(style.overflowY)
      if (clips) {
        boundary = node.getBoundingClientRect().bottom
        break
      }
      node = node.parentElement
    }
    const spaceBelow = boundary - rect.bottom
    const spaceAbove = rect.top
    const needed = panelHeight + 8
    setPlacement(spaceBelow < needed && spaceAbove > spaceBelow ? 'top' : 'bottom')
  }, [])

  // 打开后测量（首帧浮层尚未挂载，需要等 float 渲染完），并监听滚动/resize 重算。
  React.useEffect(() => {
    if (!open) return
    updatePlacement()
    const raf = requestAnimationFrame(updatePlacement)
    window.addEventListener('resize', updatePlacement)
    // capture 阶段监听滚动，覆盖任意滚动容器
    window.addEventListener('scroll', updatePlacement, true)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', updatePlacement)
      window.removeEventListener('scroll', updatePlacement, true)
    }
  }, [open, updatePlacement])

  const select = (v: string) => {
    setInner(v)
    onValueChange?.(v)
    setOpen(false)
  }

  // 显示当前选中的项文本。
  // 注意：后端未初始化的枚举字段常返回空字符串（如人机验证 provider: ""），
  // 空串不是 nullish，`??` 兜不住，会把空串当成已选值渲染出「空的」下拉框。
  // 这里统一把空字符串视为「未选择」，走 placeholder 兜底。
  let currentLabel: string | undefined
  React.Children.forEach(children, (child) => {
    if (React.isValidElement(child) && (child.props as { value?: string }).value === current) {
      currentLabel = child.props.children as string
    }
  })
  const hasValue = current !== '' && current != null
  const displayLabel = hasValue ? (currentLabel ?? current) : (placeholder ?? t('common.select'))

  return (
    <div ref={ref} className={cn('relative', className)}>
      <button
        type="button"
        role="combobox"
        aria-label={ariaLabel}
        aria-expanded={open}
        data-state={open ? 'open' : 'closed'}
        data-slot="select-trigger"
        data-size={size}
        id={id}
        onClick={() => setOpen(!open)}
        data-placeholder={hasValue ? undefined : ''}
        className={cn(
          'flex w-fit items-center justify-between gap-2 rounded-md border border-input bg-transparent px-3 text-sm whitespace-nowrap shadow-xs transition-[color,box-shadow] outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 data-[placeholder]:text-muted-foreground [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*="size-"])]:size-4 [&_svg:not([class*="text-"])]:text-muted-foreground',
          size === 'sm' ? 'h-8 py-1' : 'h-9 py-2',
          className
        )}
      >
        {icon}
        <span data-slot="select-value" className="flex items-center gap-2">{displayLabel}</span>
        <ChevronDown className="size-4 opacity-50" />
      </button>
      {open && (
        <div
          ref={listRef}
          data-slot="select-content"
          data-placement={placement}
          className={cn(
            'absolute z-50 max-h-64 min-w-[8rem] overflow-y-auto rounded-md border bg-popover p-1 text-popover-foreground shadow-md',
            placement === 'top' ? 'bottom-full mb-1' : 'top-full mt-1'
          )}
          role="listbox"
        >
          {React.Children.map(children, (child) => {
            if (React.isValidElement(child)) {
              const v = (child.props as { value?: string }).value ?? ''
              return React.cloneElement(child as React.ReactElement<any>, {
                onClick: () => select(v),
                selected: v === current,
              })
            }
            return child
          })}
        </div>
      )}
    </div>
  )
}

export function SelectItem({
  className,
  value,
  children,
  onClick,
  selected,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { value: string; selected?: boolean }) {
  return (
    <div
      role="option"
      data-slot="select-item"
      data-value={value}
      aria-selected={selected}
      data-state={selected ? 'checked' : 'unchecked'}
      onClick={onClick}
      className={cn(
        'relative flex w-full cursor-default select-none items-center gap-2 rounded-sm py-1.5 pr-2 pl-8 text-sm outline-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 hover:bg-accent hover:text-accent-foreground',
        className
      )}
      {...props}
    >
      {selected && <Check className="absolute left-2 size-4 text-primary" />}
      {children}
    </div>
  )
}
