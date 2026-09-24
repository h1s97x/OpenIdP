import * as React from 'react'
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { Loader2, ShieldCheck, MailWarning, MailX, MailQuestion, MailCheck, LogIn } from 'lucide-react'
import { Button } from '../components/ui/button'
import { AuthCardMobileHeader, AuthLayout } from '../components/layout/AuthLayout'
import { useSession } from '../hooks/useSession'
import { useI18n } from '../i18n'
import { api, ApiError } from '../lib/api'

// 邮箱验证结果页的状态集合。
// loading  —— 正在校验令牌
// success  —— 验证成功
// invalid  —— 令牌无效或已过期（一次性消费，重复打开也会落到这里）
// missing  —— 链接缺少令牌参数
// needLogin—— 当前未登录：不消费令牌，引导登录后跳回本页继续验证
// needEmail—— 账号未绑定邮箱，无法验证
type VerifyState = 'loading' | 'success' | 'invalid' | 'missing' | 'needLogin' | 'needEmail'

// 邮箱验证结果页（SPA 路由 /verify-email，不挂在登录守卫下）。
//
// 邮件链接直接指向本页并携带 token，页面在浏览器上下文中完成验证并按返回码
// 渲染图形化结果，因此语言天然跟随用户的本地语言偏好（localStorage 的
// openidp.lang），无需服务端猜测 Accept-Language，也无需透传 lang 参数。
//
// 未登录时后端返回 401，本页不消费令牌，改为引导登录并在登录后跳回原链接，
// 令牌始终留在 URL 中，不会在跳转链路里丢失。
export function VerifyEmailPage() {
  const { t } = useI18n()
  const { session, isLoading } = useSession()
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()
  const token = (searchParams.get('token') ?? '').trim()

  const [state, setState] = React.useState<VerifyState>(token ? 'loading' : 'missing')
  // 一次性闸门：会话探测结束后只发起一次校验，避免重复消费令牌导致
  // 「验证成功后又变成链接失效」。
  const submitted = React.useRef(false)

  // 登录后回跳的完整来源（路径 + 查询串），保留 token。
  const selfPath = `/verify-email${location.search}`

  React.useEffect(() => {
    if (!token) {
      setState('missing')
      return
    }
    // 等待会话探测完成，避免把「探测中」误判为「未登录」。
    if (isLoading) return
    if (submitted.current) return
    submitted.current = true

    // 未登录：交由下方渲染引导登录，不调用接口，令牌保持未被消费。
    if (!session) {
      setState('needLogin')
      return
    }

    let cancelled = false
    ;(async () => {
      try {
        await api.verifyEmail(token)
        if (!cancelled) setState('success')
      } catch (e) {
        if (cancelled) return
        if (e instanceof ApiError && e.status === 401) {
          // 会话在探测与提交之间失效：退回引导登录，令牌仍未被消费。
          submitted.current = false
          setState('needLogin')
          return
        }
        if (e instanceof ApiError && e.code === 'email.missing') {
          setState('needEmail')
          return
        }
        setState('invalid')
      }
    })()
    return () => {
      cancelled = true
    }
  }, [token, isLoading, session])

  const goLogin = () => {
    navigate('/sign-in', { state: { from: selfPath } })
  }

  return (
    <AuthLayout>
      <div
        data-slot="card"
        className="flex flex-col gap-0 rounded-3xl border border-border/70 bg-card/85 py-6 text-card-foreground shadow-sm backdrop-blur-md max-md:bg-card max-md:backdrop-filter-none"
      >
        <div data-slot="card-header" className="flex flex-col items-start gap-2 border-b bg-card/80 px-6 py-5 sm:px-8 sm:py-6">
          <AuthCardMobileHeader />
          <h2 data-slot="card-title" className="font-semibold text-xl tracking-tight">
            {t('verifyEmail.title')}
          </h2>
        </div>

        <div data-slot="card-content" className="grid gap-3 px-6 py-8 text-center sm:px-8">
          {state === 'loading' && (
            <>
              <Loader2 className="mx-auto size-12 animate-spin text-muted-foreground" />
              <h3 className="text-lg font-semibold">{t('verifyEmail.loading.title')}</h3>
              <p className="text-sm text-muted-foreground">{t('verifyEmail.loading.desc')}</p>
            </>
          )}

          {state === 'success' && (
            <>
              <ShieldCheck className="mx-auto size-12 text-success" />
              <h3 className="text-lg font-semibold">{t('verifyEmail.success.title')}</h3>
              <p className="text-sm text-muted-foreground">{t('verifyEmail.success.desc')}</p>
              <Link to="/settings/account">
                <Button className="mt-4 w-full">{t('verifyEmail.toSettings')}</Button>
              </Link>
            </>
          )}

          {state === 'invalid' && (
            <>
              <MailX className="mx-auto size-12 text-destructive" />
              <h3 className="text-lg font-semibold">{t('verifyEmail.invalid.title')}</h3>
              <p className="text-sm text-muted-foreground">{t('verifyEmail.invalid.desc')}</p>
              <Link to="/settings/account">
                <Button variant="outline" className="mt-4 w-full">{t('verifyEmail.resend')}</Button>
              </Link>
            </>
          )}

          {state === 'missing' && (
            <>
              <MailQuestion className="mx-auto size-12 text-muted-foreground" />
              <h3 className="text-lg font-semibold">{t('verifyEmail.missing.title')}</h3>
              <p className="text-sm text-muted-foreground">{t('verifyEmail.missing.desc')}</p>
            </>
          )}

          {state === 'needLogin' && (
            <>
              <MailWarning className="mx-auto size-12 text-warning" />
              <h3 className="text-lg font-semibold">{t('verifyEmail.needLogin.title')}</h3>
              <p className="text-sm text-muted-foreground">{t('verifyEmail.needLogin.desc')}</p>
              <Button className="mt-4 w-full" onClick={goLogin}>
                <LogIn className="size-4" /> {t('verifyEmail.needLogin.action')}
              </Button>
            </>
          )}

          {state === 'needEmail' && (
            <>
              <MailCheck className="mx-auto size-12 text-muted-foreground" />
              <h3 className="text-lg font-semibold">{t('verifyEmail.needEmail.title')}</h3>
              <p className="text-sm text-muted-foreground">{t('verifyEmail.needEmail.desc')}</p>
              <Link to="/settings/account">
                <Button variant="outline" className="mt-4 w-full">{t('verifyEmail.toSettings')}</Button>
              </Link>
            </>
          )}
        </div>
      </div>
    </AuthLayout>
  )
}
