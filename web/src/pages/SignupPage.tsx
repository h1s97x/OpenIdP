// 注册页：三步式注册流程。
// 步骤一「详情」：用户名 + 显示名称 + 邮箱 → 步骤二「验证」：6 位邮箱验证码 OTP
// → 步骤三「密码」：密码 + 确认密码 + 密码要求卡 → 创建账号。
import * as React from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { KeyRound, Mail, UserPlus, Loader2, Check, RefreshCw } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { PasswordInput } from '../components/ui/password-input'
import { InputOTP } from '../components/ui/input-otp'
import { Field } from '../components/ui/field'
import { AuthLayout, AuthCardMobileHeader } from '../components/layout/AuthLayout'
import { useSession } from '../hooks/useSession'
import { useI18n } from '../i18n'
import { api, ApiError } from '../lib/api'
import { useCaptcha, TurnstileWidget, GeeTestWidget, type CaptchaPolicy, type GeeTestProof, type CaptchaPayload } from '../lib/captcha'
import { useToast } from '../components/ui/toast'
import { DEFAULT_PASSWORD_REQUIREMENTS, passwordRequirementList } from '../hooks/usePasswordPolicy'

type Step = 'details' | 'verification' | 'password'

interface Policy {
  signup?: boolean
  signupEmailVerification?: boolean
  providers?: Array<{ name: string; displayName: string; logoUrl?: string; providerType?: string }>
  passwordRequirements?: {
    minimumLength: number
    requireUppercase: boolean
    requireLowercase: boolean
    requireNumber: boolean
    requireSymbol: boolean
  }
  captcha?: CaptchaPolicy
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// 用户名规则：仅允许半角字母与数字，长度 3-32，区分大小写。
const USERNAME_RE = /^[A-Za-z0-9]{3,32}$/

export function SignupPage() {
  const { session, signup } = useSession()
  const { t } = useI18n()
  const { success: toastSuccess, error: toastError } = useToast()
  const navigate = useNavigate()

  // 注册策略（来自 /login-policy）
  const [policy, setPolicy] = React.useState<Policy | null>(null)
  const [policyLoaded, setPolicyLoaded] = React.useState(false)
  // 策略拉取失败：与「已加载且 signup=false」区分开，以便给出可重试的提示。
  const [policyError, setPolicyError] = React.useState(false)

  // 表单字段
  const [username, setUsername] = React.useState('')
  const [displayName, setDisplayName] = React.useState('')
  const [email, setEmail] = React.useState('')
  const [emailCode, setEmailCode] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [confirmPassword, setConfirmPassword] = React.useState('')

  // 流程状态
  const [step, setStep] = React.useState<Step>('details')
  const [sending, setSending] = React.useState(false)
  const [submitting, setSubmitting] = React.useState(false)
  const [countdown, setCountdown] = React.useState(0)
  const [errors, setErrors] = React.useState<Record<string, string>>({})

  // 人机验证
  const [captchaPolicy, setCaptchaPolicy] = React.useState<CaptchaPolicy | undefined>(undefined)
  const { runCaptcha, bindContainerRef } = useCaptcha(captchaPolicy)
  const [turnstileToken, setTurnstileToken] = React.useState('')
  const [geetestProof, setGeeTestProof] = React.useState<GeeTestProof | undefined>(undefined)

  React.useEffect(() => {
    if (session) navigate('/', { replace: true })
  }, [session, navigate])

  // 加载注册策略
  React.useEffect(() => {
    let cancelled = false
    api.loginPolicy<Policy>()
      .then((p) => {
        if (cancelled) return
        setPolicy(p)
        setCaptchaPolicy(p?.captcha)
      })
      .catch(() => {
        if (!cancelled) {
          setPolicyError(true)
          toastError(t('signup.loadFailed'))
        }
      })
      .finally(() => {
        if (!cancelled) setPolicyLoaded(true)
      })
    return () => { cancelled = true }
  }, [t, toastError])

  React.useEffect(() => {
    if (countdown <= 0) return
    const t0 = window.setInterval(() => setCountdown((c) => Math.max(c - 1, 0)), 1000)
    return () => window.clearInterval(t0)
  }, [countdown])

  const reqs = policy?.passwordRequirements ?? DEFAULT_PASSWORD_REQUIREMENTS

  // 只有后台开启「注册时验证」（requiredForSignup）才要求完成人机验证；
  // 仅配置了提供商但未开启开关时不再强制弹出/校验。
  const captchaRequired = !!captchaPolicy?.enabled && !!captchaPolicy?.requiredForSignup

  const captchaPayload = async (): Promise<CaptchaPayload | null> => {
    if (captchaPolicy?.provider === 'turnstile') {
      if (captchaRequired && !turnstileToken) {
        throw new ApiError(t('login.needCaptcha'), { status: 0, code: 'captcha.required' })
      }
      return { turnstile: turnstileToken || undefined }
    }
    if (captchaPolicy?.provider === 'geetest') {
      if (!captchaRequired) return null
      // bind 模式：在提交时机弹出验证窗口，等待用户完成
      return runCaptcha()
    }
    return runCaptcha()
  }

  const setError = (key: string, msg: string) => {
    setErrors((prev) => ({ ...prev, [key]: msg }))
  }

  const validateDetails = (): boolean => {
    const next: Record<string, string> = {}
    const trimmedUsername = username.trim()
    if (!trimmedUsername) next.username = t('signup.usernameMin')
    else if (trimmedUsername.length < 3) next.username = t('signup.usernameMin')
    else if (trimmedUsername.length > 32) next.username = t('signup.usernameMax')
    else if (!USERNAME_RE.test(trimmedUsername)) next.username = t('signup.usernameFormat')
    if (!displayName.trim()) next.displayName = t('signup.displayNameRequired')
    else if (displayName.trim().length > 80) next.displayName = t('signup.displayNameMax')
    // 管理员关闭邮箱验证时邮箱可选：仅在用户填写了邮箱时才校验格式
    const emailOptional = policy?.signupEmailVerification === false
    if (email.trim()) {
      if (!EMAIL_RE.test(email.trim())) next.email = t('signup.emailInvalid')
    } else if (!emailOptional) {
      next.email = t('signup.emailInvalid')
    }
    setErrors(next)
    return Object.keys(next).length === 0
  }

  const validateCode = (): boolean => {
    if (!/^\d{6}$/.test(emailCode)) {
      setError('emailCode', t('signup.codeInvalid'))
      return false
    }
    return true
  }

  const validatePasswordFields = (): boolean => {
    const next: Record<string, string> = {}
    if (!validatePassword(password, reqs)) next.password = t('signup.passwordWeak')
    if (password !== confirmPassword) next.confirmPassword = t('signup.passwordMismatch')
    setErrors(next)
    return Object.keys(next).length === 0
  }

  const sendCode = async (): Promise<boolean> => {
    setErrors({})
    if (!EMAIL_RE.test(email.trim())) {
      setError('email', t('signup.emailInvalid'))
      return false
    }
    if (!policy?.signup || !policy.signupEmailVerification) {
      toastError(t('signup.disabled'))
      return false
    }
    setSending(true)
    try {
      const payload = await captchaPayload()
      await api.signupEmailCodeRequest(email.trim(), payload ?? undefined)
      setCountdown(60)
      toastSuccess(t('signup.sent'))
      return true
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : t('signup.sendFailed')
      if (err instanceof ApiError && err.status === 409) {
        setError('email', t('signup.emailExists'))
      } else {
        toastError(msg)
      }
      return false
    } finally {
      setSending(false)
    }
  }

  const goVerification = async () => {
    if (!validateDetails()) return
    if (policy?.signupEmailVerification) {
      const ok = await sendCode()
      if (ok) setStep('verification')
    } else {
      setStep('password')
    }
  }

  const goPassword = () => {
    if (!validateCode()) return
    setStep('password')
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (step === 'details') {
      goVerification()
      return
    }
    if (step === 'verification') {
      goPassword()
      return
    }
    // password 步骤
    if (!validatePasswordFields()) return
    setSubmitting(true)
    try {
      const payload = await captchaPayload()
      await signup({
        email: email.trim(),
        username: username.trim(),
        displayName: displayName.trim(),
        password,
        emailCode: policy?.signupEmailVerification ? emailCode.trim() : undefined,
        ...(payload ? { captcha: payload } : {}),
      })
      toastSuccess(t('signup.success'))
      navigate('/', { replace: true })
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : t('signup.fail')
      if (err instanceof ApiError && err.status === 409) {
        setError('email', t('signup.emailExists'))
        // 回到第一步时必须清掉旧验证码：它是发给「上一个邮箱」的，
        // 不清的话用户改完邮箱可直接跳过发码，用错码提交。
        setEmailCode('')
        setCountdown(0)
        setStep('details')
      } else {
        toastError(msg)
      }
    } finally {
      setSubmitting(false)
    }
  }

  const handleSocial = async (provider: string) => {
    setErrors({})
    try {
      // 三方登录不再要求人机验证：直接发起授权跳转。
      // 与登录页同理，人机验证仅用于本站凭据流程。
      api.providerAuthorize(provider)
    } catch (err) {
      toastError(err instanceof ApiError ? err.message : t('signup.thirdPartyFail'))
    }
  }

  // 仅当策略加载完成且 signup 未开启时才提示禁用（避免加载中闪烁）。
  // policyError 与「管理员关闭注册」分开判断：两者对用户的含义完全不同
  // （一个是稍后重试，一个是不接受注册），不能共用同一句文案。
  const signupDisabled = policyLoaded && !policyError && policy?.signup !== true
  const providers = policy?.providers ?? []

  return (
    <AuthLayout>
      <div data-slot="card" className="flex flex-col gap-0 rounded-3xl border border-border/70 bg-card/85 py-6 text-card-foreground shadow-sm backdrop-blur-md max-md:bg-card max-md:backdrop-filter-none">
        <div data-slot="card-header" className="flex flex-col items-start gap-3 border-b bg-card/80 px-6 py-5 sm:px-8 sm:py-6">
          {/* 移动端品牌 + 语言/主题 */}
          <AuthCardMobileHeader />

          <h2 data-slot="card-title" className="font-semibold text-xl tracking-tight">{t('signup.title')}</h2>
          <p data-slot="card-description" className="text-sm text-muted-foreground">
            {t('signup.desc')}{' '}
            <Link to="/sign-in" className="font-medium text-foreground underline underline-offset-4">{t('signup.loginLink')}</Link>
          </p>
        </div>

        <div data-slot="card-content" className="px-5 py-6 sm:px-8">
          {/* 未开放注册提示 */}
          {signupDisabled && (
            <div role="alert" data-slot="alert" className="relative w-full rounded-lg border border-destructive/30 bg-card px-4 py-3 text-sm text-destructive">
              {t('signup.disabled')}
            </div>
          )}

          {/* 策略加载失败：与「未开放注册」分开呈现，并给出重试入口 */}
          {policyError && (
            <div role="alert" data-slot="alert" className="relative w-full rounded-lg border border-destructive/30 bg-card px-4 py-3 text-sm text-destructive">
              <p>{t('signup.loadFailed')}</p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={() => window.location.reload()}
              >
                <RefreshCw className="size-4" /> {t('common.retry')}
              </Button>
            </div>
          )}

          {!signupDisabled && (
            <form onSubmit={submit} className="transition-[min-height] duration-300">
              {/* 步骤一：详情 */}
              {step === 'details' && (
                <div className="grid gap-5 motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-right-2">
                  <div className="grid gap-5 min-[480px]:grid-cols-2 sm:gap-7">
                    <Field label={t('signup.username')} htmlFor="signup-user-id" error={errors.username}>
                      <Input
                        id="signup-user-id"
                        autoComplete="username"
                        placeholder={t('signup.usernamePlaceholder')}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        aria-invalid={!!errors.username}
                      />
                    </Field>
                    <Field label={t('signup.displayName')} htmlFor="signup-display-name" error={errors.displayName}>
                      <Input
                        id="signup-display-name"
                        autoComplete="name"
                        placeholder={t('signup.displayNamePlaceholder')}
                        value={displayName}
                        onChange={(e) => setDisplayName(e.target.value)}
                        aria-invalid={!!errors.displayName}
                      />
                    </Field>
                  </div>
                  {/* 管理员开放注册但关闭邮箱验证时不再要求邮箱：直接用户名 + 密码即可 */}
                  {policy?.signupEmailVerification !== false && (
                    <Field label={t('signup.email')} htmlFor="signup-email" error={errors.email}>
                      <Input
                        id="signup-email"
                        type="email"
                        name="email"
                        autoComplete="email"
                        placeholder="name@example.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        aria-invalid={!!errors.email}
                      />
                    </Field>
                  )}
                  {captchaRequired && captchaPolicy?.provider === 'turnstile' && (
                    <TurnstileWidget policy={captchaPolicy} onToken={setTurnstileToken} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); toastError(t('login.captchaFail')) }} />
                  )}
                  {captchaRequired && captchaPolicy?.provider === 'geetest' && (
                    <GeeTestWidget policy={captchaPolicy} containerRef={bindContainerRef} onSuccess={setGeeTestProof} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); toastError(t('login.captchaFail')) }} />
                  )}
                  <Button type="button" className="w-full" disabled={sending || !policyLoaded || signupDisabled} onClick={goVerification}>
                    {sending ? (
                      <Loader2 data-icon="inline-start" className="animate-spin" />
                    ) : policy?.signupEmailVerification ? (
                      <Mail data-icon="inline-start" />
                    ) : (
                      <KeyRound data-icon="inline-start" />
                    )}
                    {policy?.signupEmailVerification ? t('signup.getCode') : t('signup.setPassword')}
                  </Button>
                </div>
              )}

              {/* 步骤二：邮箱验证码 */}
              {step === 'verification' && (
                <div className="grid gap-5 motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-right-2">
                  <div className="grid gap-1">
                    <p className="text-sm font-medium">{t('signup.verificationTitle')}</p>
                    <p className="text-sm text-muted-foreground">
                      {t('signup.verificationDesc', { email: maskEmail(email) })}
                    </p>
                  </div>
                  <Field label={t('signup.code')} htmlFor="signup-email-code" error={errors.emailCode}>
                    <InputOTP
                      id="signup-email-code"
                      maxLength={6}
                      value={emailCode}
                      onChange={(v) => { setEmailCode(v); if (errors.emailCode) setError('emailCode', '') }}
                      disabled={submitting}
                      autoFocus
                      aria-invalid={!!errors.emailCode}
                    />
                  </Field>
                  <div className="flex flex-wrap items-center gap-x-1 gap-y-2 text-xs text-muted-foreground">
                    <span>{t('signup.notReceived')}</span>
                    <Button type="button" variant="link" size="sm" className="h-auto px-0 text-xs" disabled={sending || countdown > 0} onClick={sendCode}>
                      {countdown > 0 ? `${countdown}s` : t('signup.resend')}
                    </Button>
                    <Button type="button" variant="link" size="sm" className="ms-auto h-auto px-0 text-xs" disabled={sending} onClick={() => { setStep('details'); setEmailCode('') }}>
                      {t('signup.changeEmail')}
                    </Button>
                  </div>
                  {captchaRequired && captchaPolicy?.provider === 'turnstile' && (
                    <TurnstileWidget policy={captchaPolicy} onToken={setTurnstileToken} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); toastError(t('login.captchaFail')) }} />
                  )}
                  {captchaRequired && captchaPolicy?.provider === 'geetest' && (
                    <GeeTestWidget policy={captchaPolicy} containerRef={bindContainerRef} onSuccess={setGeeTestProof} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); toastError(t('login.captchaFail')) }} />
                  )}
                  <Button type="button" className="w-full" disabled={submitting || !/^\d{6}$/.test(emailCode)} onClick={goPassword}>
                    <KeyRound data-icon="inline-start" />
                    {t('signup.setPassword')}
                  </Button>
                </div>
              )}

              {/* 步骤三：密码 */}
              {step === 'password' && (
                <div className="grid gap-5 motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-right-2">
                  <div className="grid gap-5 sm:grid-cols-2 sm:gap-7">
                    <Field label={t('signup.password')} htmlFor="signup-password" error={errors.password}>
                      <PasswordInput
                        id="signup-password"
                        autoComplete="new-password"
                        placeholder={t('signup.passwordPlaceholder', { min: reqs.minimumLength })}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        aria-invalid={!!errors.password}
                      />
                    </Field>
                    <Field label={t('signup.confirmPassword')} htmlFor="signup-confirm-password" error={errors.confirmPassword}>
                      <PasswordInput
                        id="signup-confirm-password"
                        autoComplete="new-password"
                        placeholder={t('signup.confirmPlaceholder')}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        aria-invalid={!!errors.confirmPassword}
                      />
                    </Field>
                  </div>
                  <div className="flex flex-col gap-2 rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
                    <p className="font-medium text-foreground">{t('signup.passwordRequirements')}</p>
                    <ul className="grid gap-1">
                      {passwordRequirementList(reqs, t).map((item) => (
                        <li key={item} className="flex items-center gap-2">
                          <Check className="size-3 shrink-0" />
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <Button type="submit" className="w-full" disabled={submitting || !policyLoaded || signupDisabled}>
                    {submitting ? (
                      <Loader2 data-icon="inline-start" className="animate-spin" />
                    ) : (
                      <UserPlus data-icon="inline-start" />
                    )}
                    {submitting ? t('signup.submitting') : t('signup.submit')}
                  </Button>
                </div>
              )}
            </form>
          )}

          {/* 第三方账号注册 */}
          {!signupDisabled && providers.length > 0 && (
            <>
              <div className="mt-6 flex items-center gap-3 text-xs text-muted-foreground">
                <span className="flex-1 border-t border-dashed" />
                <span>{t('signup.thirdParty')}</span>
                <span className="flex-1 border-t border-dashed" />
              </div>
              <div className="mt-4 flex flex-wrap justify-center gap-2">
                {providers.map((p) => (
                  <Button
                    key={p.name}
                    type="button"
                    variant="outline"
                    size="icon"
                    className="size-11 rounded-full border-2 p-0"
                    aria-label={t('signup.signupWith', { name: p.displayName })}
                    title={t('signup.signupWith', { name: p.displayName })}
                    disabled={submitting}
                    onClick={() => handleSocial(p.providerType ?? p.name)}
                  >
                    <span className="grid size-full place-items-center overflow-hidden rounded-full">
                      {p.logoUrl ? (
                        <img src={p.logoUrl} alt="" className="size-full object-cover" />
                      ) : (
                        <span className="text-sm font-medium">{p.displayName.slice(0, 1)}</span>
                      )}
                    </span>
                  </Button>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </AuthLayout>
  )
}

function maskEmail(email: string): string {
  const [name, domain] = email.split('@')
  if (!name || !domain) return email
  const keep = Math.min(2, Math.max(1, name.length - 1))
  return `${name.slice(0, keep)}***@${domain}`
}

function validatePassword(
  pw: string,
  reqs: { minimumLength: number; requireUppercase: boolean; requireLowercase: boolean; requireNumber: boolean; requireSymbol: boolean }
): boolean {
  if (pw.length < reqs.minimumLength) return false
  if (reqs.requireUppercase && !/[A-Z]/.test(pw)) return false
  if (reqs.requireLowercase && !/[a-z]/.test(pw)) return false
  if (reqs.requireNumber && !/\d/.test(pw)) return false
  if (reqs.requireSymbol && !/[^A-Za-z0-9]/.test(pw)) return false
  return true
}


