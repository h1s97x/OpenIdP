import * as React from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, User, Lock, Loader2, ArrowRight, Server, KeyRound } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input, Label } from '../components/ui/input'
import { AuthLayout } from '../components/layout/AuthLayout'
import { useSession, type SessionData } from '../hooks/useSession'
import { useSetup } from '../hooks/useSetup'
import { usePasswordPolicy } from '../hooks/usePasswordPolicy'
import { useI18n } from '../i18n'
import { useToast } from '../components/ui/toast'
import { api, ApiError } from '../lib/api'

// 首次部署初始化页：仅需设置初始管理员账号与密码（邮箱后续再绑定）。
// 数据库类型由部署时的 docker-compose 决定（PostgreSQL 或自动降级 SQLite），
// 因此不在初始化页中提供数据库选择。
// 系统尚未初始化（无任何用户）时，访问任何页面都会进入本页。

// 管理员用户名规则：与服务端一致，仅允许半角字母与数字，长度 3-32。
const USERNAME_RE = /^[A-Za-z0-9]{3,32}$/

export function SetupPage() {
  const { applySession } = useSession()
  const { checked, needsSetup, markInitialized } = useSetup()
  const { t } = useI18n()
  const { toast } = useToast()
  const navigate = useNavigate()
  // 密码长度提示与前端校验都跟随服务端策略，不写死 8 位。
  const passwordReqs = usePasswordPolicy()
  const [submitting, setSubmitting] = React.useState(false)

  const [username, setUsername] = React.useState('')
  const [displayName, setDisplayName] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [confirm, setConfirm] = React.useState('')

  // 系统已完成初始化（例如直接手输 /setup）→ 直接回到首页。
  // 初始化状态由 SetupProvider 统一探测，这里不再重复请求，避免两段 loading 造成闪烁。
  React.useEffect(() => {
    if (checked && !needsSetup) navigate('/', { replace: true })
  }, [checked, needsSetup, navigate])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!USERNAME_RE.test(username.trim())) {
      toast({ type: 'error', title: t('setup.usernameInvalid') })
      return
    }
    if (password.length < passwordReqs.minimumLength) {
      toast({ type: 'error', title: t('setup.passwordTooShort') })
      return
    }
    if (password !== confirm) {
      toast({ type: 'error', title: t('setup.passwordMismatch') })
      return
    }
    setSubmitting(true)
    try {
      const res = await api.setup<SessionData & { csrfToken?: string }>({ username, password, displayName })
      // 初始化成功即已签发会话，直接将 setup 返回的完整会话同步到 session 上下文，
      // 避免再次调用 login() 触发多余请求（也规避人机验证/风控等二次校验失败的风险）。
      if (res?.csrfToken) {
        applySession(res as SessionData)
      }
      // 先让守卫放行，再跳回首页：否则 SetupGuard 仍判定「未初始化」，
      // 会把刚跳转的 / 又重定向回 /setup，形成循环闪烁。
      markInitialized()
      navigate('/', { replace: true })
    } catch (err) {
      toast({ type: 'error', title: err instanceof ApiError ? err.message : t('setup.fail') })
    } finally {
      setSubmitting(false)
    }
  }

  if (!checked) {
    return (
      <AuthLayout>
        <div className="flex min-h-[40vh] items-center justify-center text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin me-2" />
          {t('setup.checking')}
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout>
      <div data-slot="card" className="flex flex-col gap-0 rounded-3xl border border-border/70 bg-card/85 py-6 text-card-foreground shadow-sm backdrop-blur-md max-md:bg-card max-md:backdrop-filter-none">
        <div data-slot="card-header" className="flex flex-col items-start gap-3 border-b bg-card/80 px-6 py-5 sm:px-8 sm:py-6">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-md bg-primary/10 text-primary">
              <Server className="size-5" />
            </div>
            <div>
              <h2 data-slot="card-title" className="font-semibold text-xl tracking-tight">{t('setup.title')}</h2>
              <p data-slot="card-description" className="mt-0.5 text-sm text-muted-foreground">
                {t('setup.desc')}
              </p>
            </div>
          </div>
        </div>

        <div data-slot="card-content" className="px-6 py-6 sm:px-8">
          <form className="grid gap-6" onSubmit={submit}>
            {/* 步骤 1：设置管理员账号 */}
            <div className="grid gap-3">
              <div className="flex items-center gap-2 text-sm font-medium">
                <span className="flex size-5 items-center justify-center rounded-full bg-primary text-[11px] text-primary-foreground">1</span>
                {t('setup.step')}
              </div>
              <div className="grid gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="setup-username">{t('setup.username')}</Label>
                  <div className="relative">
                    <User className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="setup-username"
                      className="pl-9"
                      placeholder={t('setup.usernamePlaceholder')}
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                      required
                    />
                  </div>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="setup-display">{t('setup.displayName')}</Label>
                  <div className="relative">
                    <KeyRound className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="setup-display"
                      className="pl-9"
                      placeholder={t('setup.displayNamePlaceholder')}
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                    />
                  </div>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="setup-password">{t('setup.password')}</Label>
                  <div className="relative">
                    <Lock className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="setup-password"
                      className="pl-9"
                      type="password"
                      placeholder={t('setup.passwordPlaceholder', { min: passwordReqs.minimumLength })}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="new-password"
                      required
                    />
                  </div>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="setup-confirm">{t('setup.confirm')}</Label>
                  <div className="relative">
                    <Lock className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="setup-confirm"
                      className="pl-9"
                      type="password"
                      placeholder={t('setup.confirmPlaceholder')}
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                      autoComplete="new-password"
                      required
                    />
                  </div>
                </div>
              </div>
              <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />
                {t('setup.adminHint')}
              </p>
            </div>

            <Button type="submit" className="w-full" disabled={submitting || !username || !password}>
              {submitting ? <Loader2 className="size-4 animate-spin" /> : <ArrowRight className="size-4" />}
              {submitting ? t('setup.submitting') : t('setup.submit')}
            </Button>
          </form>
        </div>
      </div>
    </AuthLayout>
  )
}
