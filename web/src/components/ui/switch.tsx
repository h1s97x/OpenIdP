import * as React from 'react'
import { cn } from '../../lib/utils'

interface SwitchProps {
  checked?: boolean
  defaultChecked?: boolean
  onCheckedChange?: (v: boolean) => void
  className?: string
  id?: string
  disabled?: boolean
}

export function Switch({ checked, defaultChecked, onCheckedChange, className, id, disabled }: SwitchProps) {
  const [inner, setInner] = React.useState(defaultChecked ?? false)
  const isChecked = checked ?? inner
  const toggle = () => {
    const v = !isChecked
    setInner(v)
    onCheckedChange?.(v)
  }
  return (
    <button
      type="button"
      role="switch"
      id={id}
      aria-checked={isChecked}
      data-state={isChecked ? 'checked' : 'unchecked'}
      disabled={disabled}
      onClick={toggle}
      className={cn(
        'peer inline-flex h-5 w-9 shrink-0 items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50',
        isChecked ? 'bg-primary' : 'bg-input',
        className
      )}
    >
      <span
        data-slot="switch-thumb"
        className={cn(
          'pointer-events-none block h-4 w-4 rounded-full bg-background shadow-lg ring-0 transition-transform',
          isChecked ? 'translate-x-4' : 'translate-x-0'
        )}
      />
    </button>
  )
}
