// 6 位邮箱验证码 OTP 输入组件。
// 采用“透明真实输入 + 视觉格子”方案：底层一个隐形 input 承载键盘/粘贴/焦点，
// 上层用 N 个格子展示每一位字符，支持自动聚焦下一格、粘贴整串、按退格回退。
import * as React from 'react'
import { cn } from '../../lib/utils'

interface InputOTPProps {
  value: string
  onChange: (v: string) => void
  maxLength?: number
  /** length 为 maxLength 的别名，便于调用方按语义传参 */
  length?: number
  disabled?: boolean
  autoFocus?: boolean
  className?: string
  containerClassName?: string
  'aria-invalid'?: boolean
  id?: string
}

export function InputOTP({
  value,
  onChange,
  maxLength = 6,
  length: lengthProp,
  disabled = false,
  autoFocus = false,
  className,
  containerClassName,
  id,
  'aria-invalid': ariaInvalid,
}: InputOTPProps) {
  const length = Math.max(1, lengthProp ?? maxLength)
  const inputRef = React.useRef<HTMLInputElement>(null)
  const [focused, setFocused] = React.useState(false)

  const sanitize = (v: string) => v.replace(/\D/g, '').slice(0, length)

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(sanitize(e.target.value))
  }

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault()
    const text = e.clipboardData.getData('text')
    const next = sanitize(text)
    if (!next) return
    onChange(next)
    // 粘贴完整后移出焦点
    if (next.length >= length) inputRef.current?.blur()
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') {
      // 已在首位且为空则阻止默认（避免触发浏览器后退等）
      if (inputRef.current?.selectionStart === 0 && inputRef.current?.selectionEnd === 0) {
        e.preventDefault()
      }
    }
  }

  const chars = value.split('').slice(0, length)
  const activeIndex = Math.min(value.length, length - 1)

  return (
    <div className={cn('relative flex items-center gap-2', containerClassName)}>
      {/* 视觉格子 */}
      <div className="flex gap-2" aria-hidden="true">
        {Array.from({ length }, (_, i) => {
          const isActive = focused && i === activeIndex
          const hasChar = !!chars[i]
          return (
            <div
              key={i}
              data-slot="input-otp-slot"
              className={cn(
                'grid size-11 place-items-center rounded-md border text-base font-medium tabular-nums transition-all',
                hasChar ? 'border-ring/60 bg-background' : 'border-input bg-background',
                isActive && 'border-ring ring-[3px] ring-ring/40',
                disabled && 'opacity-50',
                className
              )}
            >
              {chars[i] ?? ''}
              {isActive && !hasChar && (
                <span className="pointer-events-none h-5 w-px animate-pulse bg-foreground/60" />
              )}
            </div>
          )
        })}
      </div>
      {/* 隐形真实输入 */}
      <input
        ref={inputRef}
        id={id}
        value={value}
        onChange={handleChange}
        onPaste={handlePaste}
        onKeyDown={handleKeyDown}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        disabled={disabled}
        autoFocus={autoFocus}
        autoComplete="one-time-code"
        inputMode="numeric"
        pattern="[0-9]*"
        maxLength={length}
        aria-label="邮箱验证码"
        aria-invalid={ariaInvalid}
        className="absolute inset-0 h-full w-full cursor-text opacity-0"
      />
    </div>
  )
}
