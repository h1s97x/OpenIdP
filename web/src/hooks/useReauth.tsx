import * as React from 'react'
import { Button } from '../components/ui/button'
import { Input, Label } from '../components/ui/input'
import { api, ApiError } from '../lib/api'
import { useSession } from './useSession'
import { useSecondFactor } from './useSecondFactor'
import { SecondFactorField } from '../components/ui/second-factor-field'
import { useI18n } from '../i18n'
import { X, Loader2 } from 'lucide-react'

// useReauth 提供「敏感操作前的身份重验证」能力。
//
// 解绑第三方登录、删除通行密钥等操作会被服务端要求携带 reauthToken
// （由 POST /me/reauthenticate 签发，绑定会话且用后即焚）。本 hook 统一
// 收集「密码 + 二次验证码」换取令牌，再把令牌交给调用方的 action 执行。
//
// 之所以做成 hook 而不是放在某个页面里：这些敏感操作分散在 SecurityPage
// 与 ThirdPartyCard 等多个组件中，各自实现一遍会导致交互与校验不一致。
//
// 用法：
//   const { requestReauth, dialog } = useReauth()
//   await requestReauth(async (token) => { await api.deleteXxx(id, token) })
//   // 渲染时：{dialog}
export function useReauth() {
  const { t } = useI18n()
  const { session } = useSession()
  // 纯三方登录账号没有密码，此时只需二次验证码
  const passwordSet = session?.user?.passwordSet !== false
  // 可用二次验证方式由后端统一下发：没有第二因素的账号只索要密码。
  const sf = useSecondFactor()

  const [open, setOpen] = React.useState(false)
  const [password, setPassword] = React.useState('')
  const [code, setCode] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState('')
  // 换取令牌后要执行的操作
  const then = React.useRef<((token: string) => Promise<void>) | null>(null)

  const requestReauth = React.useCallback((action: (token: string) => Promise<void>) => {
    then.current = action
    setPassword('')
    setCode('')
    setError('')
    sf.reset()
    setOpen(true)
    // 依赖 reset 而非整个 sf：sf 每次渲染都是新对象，直接依赖它等于每次都重建回调。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sf.reset])

  const submit = async () => {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const res = await api.reauthenticate(password, code.trim(), sf.method === 'none' ? undefined : sf.method)
      const token = (res as any)?.reauthToken ?? ''
      if (!token) {
        setError(t('security.reauthFailed'))
        return
      }
      setOpen(false)
      const action = then.current
      then.current = null
      if (action) await action(token)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('security.reauthFailed'))
    } finally {
      setBusy(false)
    }
  }

  const dialog = open ? (
    <div
      data-slot="alert-dialog-overlay"
      className="fixed inset-0 z-[115] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]"
      onClick={() => { if (!busy) setOpen(false) }}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="w-full max-w-md overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b px-5 py-4">
          <div>
            <h2 className="font-semibold leading-6">{t('security.reauthTitle')}</h2>
            <p className="mt-1 text-xs text-muted-foreground">{t('security.reauthDesc')}</p>
          </div>
          <button
            onClick={() => { if (!busy) setOpen(false) }}
            aria-label={t('common.close')}
            disabled={busy}
            className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50"
          >
            <X className="size-4" />
          </button>
        </div>
        <div className="space-y-4 p-5">
          {passwordSet && (
            <div className="grid gap-2">
              <Label htmlFor="reauth-password">{t('security.currentPassword')}</Label>
              <Input
                id="reauth-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => { setPassword(e.target.value); if (error) setError('') }}
                placeholder={t('security.reauthPasswordPlaceholder')}
                autoFocus
              />
            </div>
          )}
          <SecondFactorField
            id="reauth-code"
            method={sf.method}
            value={code}
            onChange={(v) => { setCode(v); if (error) setError('') }}
            canSwitch={sf.canSwitch}
            onSwitch={sf.switchMethod}
            sent={sf.sent}
            sending={sf.sending}
            cooldown={sf.cooldown}
            onSendCode={sf.requestCode}
            disabled={busy}
            autoFocus={!passwordSet}
          />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <div className="flex justify-end gap-2 border-t p-4">
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          {/* 无可用第二因素时后端只校验密码，按钮不应再等一个永远填不出来的验证码 */}
          <Button
            onClick={submit}
            disabled={busy || (passwordSet && !password) || (sf.required && !code.trim())}
          >
            {busy && <Loader2 className="size-4 animate-spin" />}
            {t('security.reauthSubmit')}
          </Button>
        </div>
      </div>
    </div>
  ) : null

  return { requestReauth, dialog }
}
