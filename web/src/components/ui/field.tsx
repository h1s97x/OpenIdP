// 表单字段容器：Label + 控件 + 错误提示。
// disabled 用于「只读/不可修改」字段：整组置灰（group-data-[disabled] 由子控件消费）。
import * as React from 'react'
import { cn } from '../../lib/utils'
import { Label } from './input'

interface FieldProps {
  label?: React.ReactNode
  htmlFor?: string
  error?: string
  className?: string
  /** 置灰态：Label 与内部控件整体降为不可修改的视觉表现 */
  disabled?: boolean
  children: React.ReactNode
}

export function Field({ label, htmlFor, error, className, disabled, children }: FieldProps) {
  return (
    <div
      data-disabled={disabled ? true : undefined}
      data-slot="field"
      className={cn(
        'grid gap-1.5',
        error && 'text-destructive',
        disabled && 'opacity-100 data-[disabled]:opacity-100',
        className
      )}
    >
      {label && (
        <Label htmlFor={htmlFor} className={cn(error && 'text-destructive', disabled && 'text-muted-foreground')}>
          {label}
        </Label>
      )}
      <div
        data-disabled={disabled ? true : undefined}
        className={cn(
          'group/field-content flex flex-col gap-1.5',
          disabled && 'group-data-[disabled=true]/field-content:opacity-100'
        )}
      >
        {children}
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  )
}
