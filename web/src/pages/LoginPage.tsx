import * as React from 'react'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { KeyRound, Mail, Fingerprint, ShieldAlert, LogIn, Send } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input, Label } from '../components/ui/input'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs'
import { AuthLayout, AuthCardMobileHeader } from '../components/layout/AuthLayout'
import { useSession, type SessionData } from '../hooks/useSession'
import { useI18n } from '../i18n'
import { api, ApiError } from '../lib/api'
import { useCaptcha, TurnstileWidget, GeeTestWidget, type CaptchaPolicy, type GeeTestProof, CaptchaPayload } from '../lib/captcha'
import { useToast } from '../components/ui/toast'

// 登录页的第三方登录项。列表与 Logo 全部来自后端 login-policy
// （读取 oauth_providers 表，仅返回已开启的提供商），前端不再硬编码，
// 避免内置素材改名后这里残留一份不存在的路径。
interface SocialItem {
  name?: string
  providerType: string
  logo?: string
}

interface LoginResult {
  mfaRequired?: boolean
  challengeId?: string
  method?: string
  user?: { id: number; username: string; displayName: string; email?: string }
  [k: string]: unknown
}

interface LoginPolicy {
  enabled?: boolean
  provider?: 'turnstile' | 'geetest'
  siteKey?: string
  [k: string]: unknown
}

export function LoginPage() {
  const { session, loginWithPasskey, verifyMFA, applySession } = useSession()
  const { t } = useI18n()
  const { toast } = useToast()
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()
  // 回跳地址的两种来源，二者都必须当不可信输入处理（只放行站内单斜杠路径）：
  //  1. 前端路由守卫（RequireAuth）拦截时带上的来源路径；
  //  2. 后端 302 到 /sign-in?returnUrl=... 的查询参数（典型场景：在新浏览器里
  //     从第三方应用发起登录，通行证尚未登录 → 先登录再回到授权页）。
  // 后端整页跳转不经过前端路由，没有 router state，必须读查询参数，
  // 否则登录后只会回到首页，用户得手动重新发起一次认证。
  const rawReturnUrl = searchParams.get('returnUrl')
  const returnUrl = rawReturnUrl ? safeInternalPath(rawReturnUrl) : null
  const from = safeInternalPath((location.state as { from?: string } | null)?.from ?? returnUrl ?? undefined)
  const [tab, setTab] = React.useState('password')
  const [loginValue, setLoginValue] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const [mfa, setMfa] = React.useState<{ challengeId: string; method: string; user?: any } | null>(null)
  const [mfaCode, setMfaCode] = React.useState('')

  // 统一错误提示：右下角 toast
  const fail = React.useCallback((msg: string) => {
    if (msg) toast({ type: 'error', title: msg })
  }, [toast])

  // 邮箱验证码状态（两步式：先邮箱地址 → 验证码）
  const [email, setEmail] = React.useState('')
  const [code, setCode] = React.useState('')
  const [codeStep, setCodeStep] = React.useState<'address' | 'code'>('address')
  const [codeCountdown, setCodeCountdown] = React.useState(0)

  const [captchaPolicy, setCaptchaPolicy] = React.useState<CaptchaPolicy | undefined>(undefined)
  const { runCaptcha, bindContainerRef } = useCaptcha(captchaPolicy)
  const [turnstileToken, setTurnstileToken] = React.useState('')
  const [geetestProof, setGeeTestProof] = React.useState<GeeTestProof | undefined>(undefined)
  const [socials, setSocials] = React.useState<SocialItem[]>([])
  // 三方登录跳转进行中：禁用全部提供商按钮，避免连点产生多个授权跳转。
  const [socialPending, setSocialPending] = React.useState<string | null>(null)
  // 邮箱验证码是否可用（依赖 SMTP 邮件服务）
  const [emailCodeEnabled, setEmailCodeEnabled] = React.useState(true)
  // 通行密钥是否可用（依赖后台「身份验证 → 通行密钥」开关与依赖方配置）
  const [passkeyEnabled, setPasskeyEnabled] = React.useState(true)
  // 登录策略是否已返回。
  //
  // 上面两个开关初值只能是 true（未拿到策略前无法判断），若据此直接渲染页签，
  // 页面会先出现「密码 / 邮箱 / 通行密钥」三种方式，策略返回后再收窄为实际
  // 启用的那些——用户看到的是一次明显的闪烁与布局跳动。
  // 这里在策略返回前不渲染页签区，改为占位骨架，彻底消除该闪烁。
  const [policyLoaded, setPolicyLoaded] = React.useState(false)
  // 注册是否开放：关闭注册时登录页不再展示「注册」入口
  const [signupEnabled, setSignupEnabled] = React.useState(false)

  // 登录后跳转：
  //  - 回跳地址来自后端（returnUrl 查询参数，指向 /login/oauth/authorize 这类
  //    后端端点）时必须整页跳转。用前端路由导航会匹配不到任何路由而白屏，
  //    授权流程也就断了。
  //  - 回跳地址来自前端路由守卫（router state）时是 SPA 内部路径，正常软跳转。
  const goAfterLogin = React.useCallback(() => {
    if (returnUrl) {
      window.location.replace(returnUrl)
      return
    }
    navigate(from, { replace: true })
  }, [returnUrl, navigate, from])

  // 已登录用户访问登录页：直接回跳
  React.useEffect(() => {
    if (session) goAfterLogin()
  }, [session, goAfterLogin])

  // 读取登录策略（含验证码 siteKey、启用社交登录列表）
  React.useEffect(() => {
    let cancelled = false
    api.loginPolicy()
      .then((p: any) => {
        if (cancelled) return
        setCaptchaPolicy(p?.captcha)
        if (typeof p?.signup === 'boolean') setSignupEnabled(p.signup)
        if (typeof p?.emailCode === 'boolean') setEmailCodeEnabled(p.emailCode)
        if (typeof p?.webAuthn === 'boolean') setPasskeyEnabled(p.webAuthn)
        if (Array.isArray(p?.providers)) {
          setSocials(p.providers.map((x: any) => ({
            name: x.displayName ?? x.name,
            providerType: x.providerType,
            logo: x.logoUrl,
          })))
        }
      })
      .catch(() => {})
      .finally(() => {
        // 失败也要置为已加载：否则页签区永远停在骨架屏，用户完全无法登录。
        // 此时上面的开关保持初值 true，按「全部可用」渲染，是可接受的最坏情况。
        if (!cancelled) setPolicyLoaded(true)
      })
      return () => { cancelled = true }
      }, [])

  React.useEffect(() => {
    if (codeCountdown <= 0) return
    const t0 = window.setInterval(() => setCodeCountdown((c) => Math.max(c - 1, 0)), 1000)
    return () => window.clearInterval(t0)
  }, [codeCountdown])

  // 组装验证码负载：Turnstile 用 token；GeeTest 用滑块完成后返回的 proof。
  // 只有后台开启「登录时验证」（requiredForLogin）才要求完成人机验证；
  // 仅配置了提供商但未开启开关时不再强制弹出/校验。
  const captchaRequired = !!captchaPolicy?.enabled && !!captchaPolicy?.requiredForLogin

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

  // 发送邮箱验证码（邮箱登录第一步）
  const sendCode = async () => {
    const target = email.trim() || loginValue.trim()
    if (!target || !target.includes('@')) {
      fail(t('signup.emailInvalid'))
      return
    }
    try {
      const payload = await captchaPayload()
      await api.emailCodeRequest(target, payload ?? undefined)
      setEmail(target)
      setCodeStep('code')
      setCode('')
      setCodeCountdown(60)
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.fail'))
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const payload = await captchaPayload()
      const res = await api.login<LoginResult>(loginValue, password, undefined, payload ?? undefined)
      if (res?.mfaRequired) {
        setMfa({ challengeId: res.challengeId!, method: res.method!, user: res.user! })
        setMfaCode('')
      } else {
        // 直接应用已返回的会话，避免重复提交登录请求
        applySession(res as unknown as SessionData)
        goAfterLogin()
      }
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.fail'))
    } finally {
      setLoading(false)
    }
  }

  const submitEmailCode = async (e: React.FormEvent) => {
    e.preventDefault()
    if (codeStep === 'address') {
      setLoading(true)
      try {
        const payload = await captchaPayload()
        await api.emailCodeRequest(email.trim(), payload ?? undefined)
        setCodeStep('code')
        setCode('')
        setCodeCountdown(60)
      } catch (err) {
        fail(err instanceof ApiError ? err.message : t('login.fail'))
      } finally {
        setLoading(false)
      }
      return
    }
    setLoading(true)
    try {
      const payload = await captchaPayload()
      const res = await api.emailCodeVerify<LoginResult>(email.trim(), code.trim(), payload ?? undefined)
      if (res?.mfaRequired) {
        setMfa({ challengeId: res.challengeId!, method: res.method!, user: res.user! })
        setMfaCode('')
      } else {
        // 邮箱验证码校验已一次性消费并完成登录，直接应用返回的会话，避免重复校验
        applySession(res as unknown as SessionData)
        goAfterLogin()
      }
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.fail'))
    } finally {
      setLoading(false)
    }
  }

  const submitMFA = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await verifyMFA(mfa!.challengeId, mfaCode.trim())
      goAfterLogin()
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.passkeyFail'))
    } finally {
      setLoading(false)
    }
  }

  const submitPasskey = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      // 通行密钥本身即为强认证：不要求输入邮箱/用户名，也不强制人机验证。
      // 直接走可发现凭据（usernameless）登录，由浏览器弹出系统选择器。
      await loginWithPasskey('')
      goAfterLogin()
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.passkeyFail'))
    } finally {
      setLoading(false)
    }
  }

  const handleSocial = async (provider: string) => {
    if (socialPending) return
    setSocialPending(provider)
    // 跳转发起后就不再解锁按钮：页面正在导航，解锁反而会露出可重复点击的窗口。
    let navigating = false
    try {
      // 三方登录不再要求人机验证：直接发起授权跳转。
      // 人机验证仅用于密码 / 邮箱验证码等本站凭据流程，三方身份由提供商侧完成认证。
      navigating = true
      api.providerAuthorize(provider)
    } catch (err) {
      fail(err instanceof ApiError ? err.message : t('login.thirdPartyFail'))
    } finally {
      if (!navigating) setSocialPending(null)
    }
  }

  const onTabChange = (v: string) => {
    setTab(v)
    if (v === 'email') setCodeStep('address')
  }

  // 登录策略返回后，若通行密钥未启用而当前正停在该页签，回落到密码登录。
  // 否则用户会停留在一个点任何按钮都报 passkey.unavailable 的页签上。
  React.useEffect(() => {
    if (!passkeyEnabled) setTab((v) => (v === 'passkey' ? 'password' : v))
  }, [passkeyEnabled])

  // 实际渲染的登录方式数量，用于页签网格列数（未启用的方式不占位）。
  const tabCount = 1 + (emailCodeEnabled ? 1 : 0) + (passkeyEnabled ? 1 : 0)

  const brandName = t('brand.name')

  return (
    <AuthLayout>
      <div data-slot="card" className="flex flex-col gap-0 rounded-3xl border border-border/70 bg-card/85 py-6 text-card-foreground shadow-sm backdrop-blur-md max-md:bg-card max-md:backdrop-filter-none">
        <div data-slot="card-header" className="flex flex-col items-start gap-3 border-b bg-card/80 px-6 py-5 sm:px-8 sm:py-6">
          {/* 移动端品牌 + 语言/主题 */}
          <AuthCardMobileHeader />

          <h2 data-slot="card-title" className="font-semibold text-xl tracking-tight">{t('login.welcome')}</h2>
          <p data-slot="card-description" className="text-sm text-muted-foreground">
            {t('login.desc')}
            {signupEnabled && (
              <>
                {' '}
                {t('login.signupPrompt')}
                {' '}
                <a href="/signup" className="font-medium text-foreground underline underline-offset-4">{t('login.signupLink')}</a>
              </>
            )}
          </p>
        </div>

        <div data-slot="card-content" className="px-6 py-6 sm:px-8">
          {mfa ? (
            <form className="grid gap-5" onSubmit={submitMFA}>
              <div className="flex items-start gap-3 rounded-md border border-primary/20 bg-primary/5 px-3 py-3">
                <ShieldAlert className="mt-0.5 size-5 shrink-0 text-primary" />
                <div>
                  <div className="text-sm font-semibold">{t('login.mfaTitle')}</div>
                  <div className="mt-1 text-xs leading-5 text-muted-foreground">
                    {mfa.user?.email ?? mfa.user?.username} · {t('login.mfaDesc')}
                  </div>
                </div>
              </div>
              <div className="grid gap-2">
                <Label>{t('login.mfaCode')}</Label>
                <Input
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder={t('common.codePlaceholder')}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  autoFocus
                  required
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading || mfaCode.trim().length !== 6}>
                {loading ? t('login.verifying') : t('login.mfaVerify')}
              </Button>
              <Button type="button" variant="ghost" className="w-full text-muted-foreground" onClick={() => setMfa(null)}>
                {t('login.mfaBack')}
              </Button>
            </form>
          ) : !policyLoaded ? (
            // 策略未返回前用等高占位块：直接渲染页签会出现「三种方式 → 收窄」的闪烁。
            <div className="grid gap-5" aria-busy="true" aria-live="polite">
              <div className="h-9 w-full animate-pulse rounded-lg bg-muted" />
              <div className="grid gap-4">
                <div className="h-9 w-full animate-pulse rounded-md bg-muted" />
                <div className="h-9 w-full animate-pulse rounded-md bg-muted" />
                <div className="h-9 w-full animate-pulse rounded-md bg-muted" />
              </div>
            </div>
          ) : (
          <form className="grid gap-5" onSubmit={(e) => {
            e.preventDefault()
            if (tab === 'password') submit(e as any)
            else if (tab === 'email') submitEmailCode(e as any)
            else submitPasskey(e as any)
          }}>
            <Tabs value={tab} onValueChange={onTabChange} className="flex flex-col gap-2">
              <TabsList className={`grid h-9 w-full rounded-lg bg-muted p-0.75 text-muted-foreground ${tabCount === 3 ? 'grid-cols-3' : tabCount === 2 ? 'grid-cols-2' : 'grid-cols-1'}`}>
                <TabsTrigger value="password" className="min-w-0 px-2 sm:px-3">
                  <KeyRound className="size-4" />
                  <span className="sm:hidden">{t('login.tab.passwordShort')}</span>
                  <span className="hidden sm:inline">{t('login.tab.password')}</span>
                </TabsTrigger>
                {emailCodeEnabled && (
                <TabsTrigger value="email" className="min-w-0 px-2 sm:px-3">
                  <Mail className="size-4" />
                  <span className="sm:hidden">{t('login.tab.emailShort')}</span>
                  <span className="hidden sm:inline">{t('login.tab.email')}</span>
                </TabsTrigger>
                )}
                {passkeyEnabled && (
                <TabsTrigger value="passkey" className="min-w-0 px-2 sm:px-3">
                  <Fingerprint className="size-4" />
                  <span className="sm:hidden">{t('login.tab.passkeyShort')}</span>
                  <span className="hidden sm:inline">{t('login.tab.passkey')}</span>
                </TabsTrigger>
                )}
              </TabsList>

              {/* 密码登录 */}
              <TabsContent value="password" className="mt-5 grid gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="login">{t('login.account')}</Label>
                  <Input
                    id="login"
                    name="login"
                    placeholder={t('login.accountPlaceholder')}
                    value={loginValue}
                    onChange={(e) => setLoginValue(e.target.value)}
                    autoComplete="username"
                    required
                  />
                </div>
                <div className="grid gap-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password">{t('login.password')}</Label>
                    <a href="/forgot-password" className="text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">{t('login.forgot')}</a>
                  </div>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder={t('login.passwordPlaceholder')}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                </div>
                {captchaRequired && captchaPolicy?.provider === 'turnstile' && (
                  <TurnstileWidget policy={captchaPolicy} onToken={setTurnstileToken} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); fail(t('login.captchaFail')) }} />
                )}
                {captchaRequired && captchaPolicy?.provider === 'geetest' && (
                  <GeeTestWidget policy={captchaPolicy} containerRef={bindContainerRef} onSuccess={setGeeTestProof} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); fail(t('login.captchaFail')) }} />
                )}
                <Button type="submit" className="w-full" disabled={loading}>
                  <LogIn className="size-4" />
                  {loading ? t('login.submitting') : t('login.submit')}
                </Button>
              </TabsContent>

              {/* 邮箱验证码登录（两步式：先邮箱地址 → 验证码） */}
              <TabsContent value="email" className="mt-5 grid gap-4">
                {codeStep === 'address' ? (
                  <div className="grid gap-2">
                    <Label>{t('login.email')}</Label>
                    <Input
                      type="email"
                      name="email"
                      autoComplete="email"
                      placeholder="name@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                ) : (
                  <div className="grid gap-5">
                    <div className="grid gap-1">
                      <p className="text-sm font-medium">{t('login.emailVerifyTitle')}</p>
                      <p className="text-sm text-muted-foreground">
                        {t('login.emailSentTo')} {maskEmail(email)} {t('login.emailSentSuffix')}
                      </p>
                    </div>
                    <div className="grid gap-2">
                      <Label>{t('login.code')}</Label>
                      <Input
                        placeholder={t('common.codePlaceholder')}
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                        inputMode="numeric"
                        maxLength={6}
                        required
                      />
                    </div>
                    <div className="flex flex-wrap items-center gap-x-1 gap-y-2 text-xs text-muted-foreground">
                      <span>{t('login.emailResendPrompt')}</span>
                      <Button type="button" variant="link" size="sm" className="h-auto px-0 text-xs" disabled={codeCountdown > 0} onClick={sendCode}>
                        {codeCountdown > 0 ? `${codeCountdown}s` : t('login.sendCode')}
                      </Button>
                      <Button type="button" variant="link" size="sm" className="ms-auto h-auto px-0 text-xs" onClick={() => { setCodeStep('address'); setCode('') }}>
                        {t('login.emailChange')}
                      </Button>
                    </div>
                  </div>
                )}
                {captchaRequired && captchaPolicy?.provider === 'turnstile' && (
                  <TurnstileWidget policy={captchaPolicy} onToken={setTurnstileToken} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); fail(t('login.captchaFail')) }} />
                )}
                {captchaRequired && captchaPolicy?.provider === 'geetest' && (
                  <GeeTestWidget policy={captchaPolicy} containerRef={bindContainerRef} onSuccess={setGeeTestProof} onError={() => { setTurnstileToken(''); setGeeTestProof(undefined); fail(t('login.captchaFail')) }} />
                )}
                {codeStep === 'address' ? (
                  <Button type="submit" className="w-full" disabled={loading}>
                    <Send className="size-4" />
                    {loading ? t('login.submitting') : t('login.sendCode')}
                  </Button>
                ) : (
                  <Button type="submit" className="w-full" disabled={loading || code.trim().length !== 6}>
                    {loading ? t('login.submitting') : t('login.emailCodeSignIn')}
                  </Button>
                )}
              </TabsContent>

              {/* 通行密钥登录：免账号/邮箱输入，直接调用 WebAuthn 可发现凭据登录 */}
              <TabsContent value="passkey" className="mt-5 grid gap-4">
                <Button type="submit" className="w-full" disabled={loading}>
                  <Fingerprint className="size-4" />
                  {loading ? t('login.verifying') : t('login.passkeySubmit')}
                </Button>
              </TabsContent>
            </Tabs>

            {/* 其他登录方式：仅显示已配置且开启的三方登录；全部未开启时隐藏整块 */}
            {socials.length > 0 && (
              <>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex-1 border-t border-dashed" />
                  <span>{t('login.otherWays')}</span>
                  <span className="flex-1 border-t border-dashed" />
                </div>
                <div className="flex flex-wrap justify-center gap-2">
                  {socials.map((s) => (
                    <button
                      key={s.providerType}
                      title={`${t('login.submit')} ${s.name}`}
                      aria-label={`${t('login.submit')} ${s.name}`}
                      onClick={() => handleSocial(s.providerType)}
                      disabled={!!socialPending}
                      className="size-11 rounded-full border-2 bg-background p-0 shadow-xs transition-colors hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-50 dark:bg-input/30 dark:border-input dark:hover:bg-input/50"
                    >
                      <span className="grid size-full place-items-center overflow-hidden rounded-full">
                        <img alt="" className="size-full object-cover" src={s.logo} />
                      </span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </form>
          )}
        </div>
      </div>
    </AuthLayout>
  )
}

// safeInternalPath 只放行站内路径：必须以单个 / 开头，且第二个字符不能是 / 或 \。
// 这样 //evil.com 与 /\evil.com 都会被拒绝，避免登录后被重定向到外部站点。
function safeInternalPath(raw: string | undefined): string {
  if (!raw) return '/'
  if (!raw.startsWith('/')) return '/'
  if (raw.length > 1 && (raw[1] === '/' || raw[1] === '\\')) return '/'
  return raw
}

function maskEmail(email: string): string {
  const [name, domain] = email.split('@')
  if (!name || !domain) return email
  const keep = Math.min(2, Math.max(1, name.length - 1))
  return `${name.slice(0, keep)}***@${domain}`
}
