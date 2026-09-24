// 外观设置抽屉的共享积木。
//
// 两块共享积木，供外观抽屉的各分组复用：
//   - SectionTitle      —— 分组标题 +（可选）单项重置按钮
//   - OptionTile        —— 「示意图 + 文字」的单选卡，选中时右上角打勾
import * as React from 'react'
import { CircleCheck, RotateCcw } from 'lucide-react'
import { cn } from '../../lib/utils'

export const APPEARANCE_RADIO_GRID = 'grid w-full max-w-md grid-cols-3 gap-4'

export function SectionTitle({ title, showReset, onReset }: {
  title: string
  showReset?: boolean
  onReset?: () => void
}) {
  return (
    <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
      {title}
      {showReset && onReset && (
        <button
          type="button"
          onClick={onReset}
          aria-label="Reset"
          className="flex size-4 items-center justify-center rounded-md bg-secondary text-secondary-foreground transition-colors hover:bg-secondary/80"
        >
          <RotateCcw className="size-3" aria-hidden />
        </button>
      )}
    </div>
  )
}

// OptionTile：「示意图 + 文字」的单选卡。
// 选中态：外框 ring-primary + shadow-2xl，右上角一个实心打勾徽标；
// 未选中态：图标继承 muted-foreground 的描边/填充，外框 ring-border。
export function OptionTile({ value, label, active, onSelect, children }: {
  value: string
  label: string
  active: boolean
  onSelect: (v: string) => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      data-state={active ? 'checked' : 'unchecked'}
      aria-label={`Select ${label.toLowerCase()}`}
      onClick={() => onSelect(value)}
      className="group flex flex-col items-stretch text-left outline-none"
    >
      <div
        role="img"
        aria-label={`${label} option preview`}
        className={cn(
          'relative rounded-md ring-1 transition duration-200 ease-in',
          'group-hover:ring-primary/60 group-focus-visible:ring-2',
          active ? 'ring-primary shadow-2xl' : 'ring-border'
        )}
      >
        <CircleCheck
          aria-hidden
          className={cn(
            'absolute top-0 right-0 z-10 size-6 translate-x-1/2 -translate-y-1/2 fill-primary stroke-white',
            !active && 'hidden'
          )}
        />
        {children}
      </div>
      <div className="mt-1 text-xs">{label}</div>
    </button>
  )
}

// 「盒子」示意图的统一外框：所有预览图都是 79.86 : 51.14 的扁矩形。
// 外框必须沿用同一宽高比：固定高度（如 h-12）会把 1.56:1 的图压进 2.6:1 的框里，
// svg 只能按 meet 居中留白，两侧出现大片空档，窄屏尤其明显。
export function PreviewFrame({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        'relative aspect-[79.86/51.14] w-full overflow-hidden rounded-md',
        'text-primary [&_svg]:size-full',
        // 未选中时示意图降级为中性灰，选中时回到主色，让选中项在整组中跳出来。
        'group-data-[state=unchecked]:text-muted-foreground',
        className
      )}
    >
      {children}
    </div>
  )
}
