// 二次验证输入框：根据账号实际可用的方式渲染验证器码 / 邮箱验证码，
// 两种方式都可用时提供切换入口。
//
// 抽成组件的原因：更换邮箱、注销账号、删除通行密钥、解绑第三方四处都要它，
// 各自实现一遍必然出现「有的地方能切换、有的地方不能」这类不一致。
import * as React from 'react'
import { Button } from './button'
import { Input, Label } from './input'
import { useI18n } from '../../i18n'
import type { SecondFactorMethod } from '../../hooks/useSecondFactor'
import { Loader2, RefreshCw } from 'lucide-react'

interface SecondFactorFieldProps {
  /** 当前选中的方式；'none' 时组件不渲染任何内容（调用方不必再判断）。 */
  method: SecondFactorMethod | 'none'
  value: string
  onChange: (v: string) => void
  /** 两种方式都可用时展示切换入口 */
  canSwitch: boolean
  onSwitch: () => void
  /** 邮箱验证码：是否已发送过 */
  sent: boolean
  sending: boolean
  cooldown: number
  onSendCode: () => void
  disabled?: boolean
  autoFocus?: boolean
  id?: string
}

export function SecondFactorField({
  method,
  value,
  onChange,
  canSwitch,
  onSwitch,
  sent,
  sending,
  cooldown,
  onSendCode,
  disabled = false,
  autoFocus = false,
  id = 'second-factor-code',
}: SecondFactorFieldProps) {
  const { t } = useI18n()

  // 无需第二因素：后端只校验密码，这里不渲染输入框。
  // 若仍渲染一个空输入框，用户填无可填，会被永久卡在这一步。
  if (method === 'none') return null

  const isEmail = method === 'email'

  return (
    <div className="grid gap-2">
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={id}>
          {isEmail ? t('security.stepUpEmailCode') : t('security.stepUpTotpCode')}
        </Label>
        {canSwitch && (
          <button
            type="button"
            onClick={onSwitch}
            disabled={disabled}
            className="text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline disabled:pointer-events-none disabled:opacity-50"
          >
            {isEmail ? t('security.switchToMfa') : t('security.switchToEmail')}
          </button>
        )}
      </div>
      <div className="flex gap-2">
        <Input
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={t('common.codePlaceholder')}
          inputMode="numeric"
          maxLength={6}
          autoComplete="one-time-code"
          disabled={disabled}
          autoFocus={autoFocus}
          className="flex-1"
        />
        {isEmail && (
          <Button
            type="button"
            variant="outline"
            className="shrink-0"
            onClick={onSendCode}
            disabled={disabled || sending || cooldown > 0}
          >
            {sending ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <RefreshCw className="size-4" />
            )}
            {cooldown > 0
              ? `${cooldown}s`
              : sent
                ? t('security.resend')
                : t('security.sendCode')}
          </Button>
        )}
      </div>
      {isEmail ? (
        <p className="text-xs text-muted-foreground">
          {sent ? t('security.stepUpEmailSent') : t('security.stepUpEmailHint')}
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">{t('security.stepUpTotpHint')}</p>
      )}
    </div>
  )
}
