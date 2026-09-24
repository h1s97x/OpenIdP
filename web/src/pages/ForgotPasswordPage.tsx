import * as React from 'react'
import { Link } from 'react-router-dom'
import { Mail, Loader2, ShieldCheck, ArrowRight, RefreshCw } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input, Label } from '../components/ui/input'
import { AuthLayout, AuthToggles } from '../components/layout/AuthLayout'
import { useI18n } from '../i18n'
import type { PasswordResetPayload } from '../lib/api-types'
import { api, ApiError } from '../lib/api'
import { useCaptcha, TurnstileWidget, GeeTestWidget, type CaptchaPolicy, type GeeTestProof } from '../lib/captcha'
import { useToast } from '../components/ui/toast'
import { useSiteBrand } from '../hooks/useSiteBrand'

// 与 SignupPage 保持同一套邮箱规则，避免两处校验不一致。
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// 策略未取到时的兜底。此前这里硬编码 8 位，若后端配了更长的最小长度，
// 前端会放行一个必然被服务端拒绝的密码，用户看不到原因。
const DEFAULT_MIN_LENGTH = 8

type Policy = {
  passwordRequirements?: { minimumLength?: number }
  captcha?: CaptchaPolicy
}

export function ForgotPasswordPage() {
  const { t } = useI18n()
  const { toast } = useToast()
  const { logo: brandLogo } = useSiteBrand()
  const [step, setStep] = React.useState<'request' | 'confirm'>('request')
  const [email, setEmail] = React.useState('')
  const [code, setCode] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [confirm, setConfirm] = React.useState('')
  // 发码与重置是两个独立请求，分开记录 loading：
  // 此前共用一个 loading，导致发码失败也会把「重置密码」按钮锁死。
  const [sending, setSending] = React.useState(false)
  const [loading, setLoading] = React.useState(false)
  const [countdown, setCountdown] = React.useState(0)
  const [done, setDone] = React.useState(false)
  // 进入第二步的前提是验证码已发出。此前点「下一步」只是切步骤，
  // 用户不点发码也能进到 confirm，然后卡在一个从没收到码的表单上。
  const [codeSent, setCodeSent] = React.useState(false)

  const [policy, setPolicy] = React.useState<Policy | null>(null)
  const minLength = policy?.passwordRequirements?.minimumLength ?? DEFAULT_MIN_LENGTH

  // 统一错误提示：右下角 toast（满足"未登录页报错用右下角弹窗"的需求）
  const fail = React.useCallback((msg: string) => {
    if (msg) toast({ type: 'error', title: msg })
  }, [toast])

  const [captchaPolicy, setCaptchaPolicy] = React.useState<CaptchaPolicy | undefined>(undefined)
  const { runCaptcha, bindContainerRef } = useCaptcha(captchaPolicy)
  const [turnstileToken, setTurnstileToken] = React.useState('')
  const [geetestProof, setGeeTestProof] = React.useState<GeeTestProof | undefined>(undefined)

  // 加了 cancelled 保护：与 Login/Signup 一致，避免组件卸载后 setState。
  React.useEffect(() => {
    let cancelled = false
    api.loginPolicy<Policy>()
      .then((p) => {
        if (cancelled) return
        setPolicy(p)
        setCaptchaPolicy(p?.captcha)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  React.useEffect(() => {
    if (countdown <= 0) return
    const t0 = window.setInterval(() => setCountdown((c) => Math.max(c - 1, 0)), 1000)
    return () => window.clearInterval(t0)
  }, [countdown])

  const captchaPayload = async () => {
    // 仅在开启"找回密码需要人机验证"时要求验证（独立于登录/注册开关）
    if (!captchaPolicy?.requiredForPasswordReset) return {}
    if (captchaPolicy?.provider === 'turnstile') {
      if (captchaPolicy.enabled && !turnstileToken) {
        throw new ApiError(t('login.needCaptcha'), { status: 0, code: 'captcha.required' })
      }
      return { turnstile: turnstileToken || undefined }
    }
    if (captchaPolicy?.provider === 'geetest') {
      if (captchaPolicy.enabled && !geetestProof) {
        throw new ApiError(t('login.needCaptcha'), { status: 0, code: 'captcha.required' })
      }
      return { captcha: geetestProof }
    }
    return runCaptcha()
  }

  const sendCode = async (): Promise<boolean> => {
    if (!EMAIL_RE.test(email.trim())) { fail(t('signup.emailInvalid')); return false }
    if (sending) return false
    setSending(true)
    try {
      const payload = await captchaPayload()
      await api.passwordResetRequest(email.trim(), payload ?? undefined)
      setCountdown(60)
      setCodeSent(true)
      return true
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.fail'))
      return false
    } finally {
      setSending(false)
    }
  }

  // 点「下一步」即发码：发成功了才切步骤，避免用户进到没收到码的表单。
  const goConfirm = async () => {
    const ok = await sendCode()
    if (ok) setStep('confirm')
  }

  const resend = async () => {
    await sendCode()
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (password.length < minLength) {
      fail(t('signup.passwordTooShort', { min: minLength }))
      return
    }
    if (password !== confirm) { fail(t('security.passwordMismatch')); return }
    setLoading(true)
    try {
      await api.passwordResetConfirm({ email: email.trim(), code: code.trim(), newPassword: password } as PasswordResetPayload)
      setDone(true)
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.fail'))
    } finally {
      setLoading(false)
    }
  }

  if (done) {
    return (
      <AuthLayout>
        <div data-slot="card" className="flex flex-col gap-6 rounded-3xl border border-border/70 bg-card/85 py-6 text-card-foreground shadow-sm backdrop-blur-md max-md:bg-card max-md:backdrop-filter-none">
          <div data-slot="card-content" className="grid gap-3 px-6 py-6 text-center sm:px-8">
            <ShieldCheck className="mx-auto size-12 text-success" />
            <h2 className="text-2xl font-semibold">{t('forgot.done.title')}</h2>
            <p className="text-sm text-muted-foreground">{t('forgot.done.desc')}</p>
            <Link to="/sign-in"><Button className="mt-4 w-full">{t('forgot.backToLogin')}</Button></Link>
          </div>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout>
      <div data-slot="card" className="flex flex-col gap-0 rounded-3xl border border-border/70 bg-card/85 py-6 text-card-foreground shadow-sm backdrop-blur-md max-md:bg-card max-md:backdrop-filter-none">
        <div data-slot="card-header" className="flex flex-col items-start gap-2 border-b bg-card/80 px-6 py-5 sm:px-8 sm:py-6">
          {/* 移动端品牌 + 语言/主题 */}
          <div className="flex w-full items-center justify-between gap-3 lg:hidden">
            <div className="flex min-w-0 items-center gap-3">
              <div className="size-10 shrink-0 overflow-hidden rounded-md">
                <img alt="" className="size-full object-contain" src={brandLogo} />
              </div>
              <div className="min-w-0">
                <p className="truncate text-base font-semibold">{t('brand.name')}</p>
              </div>
            </div>
            <AuthToggles className="flex shrink-0 items-center gap-1" />
          </div>

          <h2 data-slot="card-title" className="font-semibold text-xl tracking-tight">{t('forgot.title')}</h2>
          <p data-slot="card-description" className="text-sm text-muted-foreground">
            {t('forgot.desc')}{' '}
            <Link to="/sign-in" className="font-medium text-foreground underline underline-offset-4">{t('forgot.backLogin')}</Link>
          </p>
        </div>

        <div data-slot="card-content" className="px-6 py-6 sm:px-8">
          {step === 'request' ? (
            <form
              onSubmit={(e) => { e.preventDefault(); goConfirm() }}
              className="grid gap-4"
            >
              <div className="grid gap-2">
                <Label>{t('forgot.email')}</Label>
                <div className="flex gap-2">
                  <Input
                    type="email"
                    name="email"
                    autoComplete="email"
                    placeholder="name@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                  <Button type="button" variant="outline" className="shrink-0" onClick={resend} disabled={sending || countdown > 0}>
                    {countdown > 0 ? `${countdown}s` : t('login.sendCode')}
                  </Button>
                </div>
              </div>
              {captchaPolicy?.enabled && captchaPolicy.provider === 'turnstile' && captchaPolicy.requiredForPasswordReset && (
                <TurnstileWidget
                  policy={captchaPolicy}
                  onToken={setTurnstileToken}
                  onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); fail(t('login.captchaFail')) }}
                />
              )}
              {captchaPolicy?.enabled && captchaPolicy.provider === 'geetest' && captchaPolicy.requiredForPasswordReset && (
                <GeeTestWidget
                  policy={captchaPolicy}
                  containerRef={bindContainerRef}
                  onSuccess={setGeeTestProof}
                  onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); fail(t('login.captchaFail')) }}
                />
              )}
              <Button type="submit" className="w-full" disabled={sending}>
                {sending ? <Loader2 className="size-4 animate-spin" /> : <ArrowRight className="size-4" />}
                {t('forgot.next')}
              </Button>
            </form>
          ) : (
            <form onSubmit={submit} className="grid gap-4">
              <div className="grid gap-2">
                <Label>{t('forgot.code')}</Label>
                <div className="flex gap-2">
                  <Input placeholder={t('common.codePlaceholder')} value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" required className="flex-1" />
                  <Button type="button" variant="outline" className="shrink-0" onClick={resend} disabled={sending || countdown > 0}>
                    {countdown > 0 ? `${countdown}s` : (codeSent ? <RefreshCw className="size-4" /> : t('login.sendCode'))}
                  </Button>
                </div>
              </div>
              <div className="grid gap-2">
                <Label>{t('forgot.newPassword')}</Label>
                <Input
                  type="password"
                  placeholder={t('signup.passwordPlaceholder', { min: minLength })}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label>{t('forgot.confirmPassword')}</Label>
                <Input type="password" placeholder={t('forgot.confirmPlaceholder')} value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? <><Loader2 className="size-4 animate-spin" /> {t('forgot.resetting')}</> : t('forgot.submit')}
              </Button>
              <Button type="button" variant="ghost" className="w-full text-muted-foreground" onClick={() => setStep('request')}>{t('forgot.back')}</Button>
            </form>
          )}
        </div>

        <div data-slot="card-footer" className="border-t px-6 py-5 sm:px-8">
          <p className="text-center text-xs text-muted-foreground">
            {t('forgot.rememberHint')}{' '}
            <Link to="/sign-in" className="font-medium text-foreground underline underline-offset-4">{t('forgot.backLogin')}</Link>
          </p>
        </div>
      </div>
    </AuthLayout>
  )
}
