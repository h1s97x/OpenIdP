import * as React from 'react'
import { useSearchParams } from 'react-router-dom'
import { ShieldCheck, Earth, ExternalLink, X, Check } from 'lucide-react'
import { Button } from '../components/ui/button'
import { PublicSiteFooter } from '../components/layout/SiteFooter'
import { api, ApiError } from '../lib/api'
import { useToast } from '../components/ui/toast'
import { useI18n } from '../i18n'
import { useSiteBrand } from '../hooks/useSiteBrand'

type ScopeInfo = {
  // key 是原始权限标识（如 openid），用于查语言包做本地化。
  key?: string
  name: string
  description: string
  level: 'standard' | 'high'
}

type ConsentData = {
  requestId: string
  client: {
    id: string
    name: string
    logoUrl: string
    description: string
    redirectUri: string
    scopes: ScopeInfo[]
  }
  account: {
    displayName: string
    username: string
    email: string
    avatarUrl: string
  }
}

export function OAuthConsentPage() {
  const { t } = useI18n()
  const { toast } = useToast()
  // 应用未配置 Logo 时回落到站点 Logo（后台「品牌信息」可配）。
  const { logo: brandLogo } = useSiteBrand()
  const [searchParams] = useSearchParams()
  const request = searchParams.get('request') ?? ''
  const [data, setData] = React.useState<ConsentData | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [submitting, setSubmitting] = React.useState(false)

  React.useEffect(() => {
    if (!request) {
      toast({ type: 'error', title: t('consent.missingRequest') })
      setLoading(false)
      return
    }
    let cancelled = false
    api
      .consentInfo(request)
      .then((d: any) => {
        if (cancelled) return
        setData(d)
      })
      .catch((e: unknown) => {
        if (cancelled) return
        toast({ type: 'error', title: e instanceof ApiError ? e.message : t('consent.loadFailed') })
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [request, t, toast])

  const handleAction = async (action: 'allow' | 'deny') => {
    setSubmitting(true)
    try {
      const res: any = await api.consentAction(request, action)
      if (res?.redirect) {
        window.location.assign(res.redirect)
        return
      }
      // 后端应始终返回 redirect；若缺失则恢复按钮并提示，避免页面卡死。
      toast({ type: 'error', title: t('consent.actionFailed') })
      setSubmitting(false)
    } catch (e) {
      toast({ type: 'error', title: e instanceof ApiError ? e.message : t('consent.actionFailed') })
      setSubmitting(false)
    }
  }

  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted/30 px-3 py-5 sm:px-6 sm:py-8 max-sm:p-0">
      <div data-slot="card" className="flex w-full max-w-xl flex-col gap-6 rounded-3xl border bg-card/85 py-6 text-card-foreground backdrop-blur-md max-md:bg-card max-md:backdrop-filter-none shadow-sm max-sm:min-h-svh max-sm:rounded-none max-sm:border-0 max-sm:shadow-none">
        {/* Card Header：应用图标 + 名称 + 请求授权文案 + 应用描述 */}
        <div data-slot="card-header" className="grid auto-rows-min grid-rows-[auto_auto] items-start gap-4 p-5 sm:p-6">
          <div className="flex items-center gap-3">
            <span className="relative flex size-12 shrink-0 overflow-hidden rounded-md border">
              <img className="aspect-square size-full" alt="" src={data?.client.logoUrl || brandLogo} />
            </span>
            <div className="min-w-0 flex-1">
              <div className="truncate font-semibold leading-none">{data?.client.name || '…'}</div>
              <div className="mt-1 text-sm text-muted-foreground">{t('consent.requestAccess')}</div>
            </div>
          </div>
          {data?.client.description && (
            <div className="text-sm text-muted-foreground">{data.client.description}</div>
          )}
        </div>

        {loading ? (
          <div data-slot="card-content" className="flex flex-col gap-5 px-5 pb-5 sm:px-6 sm:pb-6">
            <div className="text-sm text-muted-foreground">{t('common.loading')}…</div>
          </div>
        ) : data ? (
          <>
            <div data-slot="card-content" className="flex flex-col gap-5 px-5 pb-5 sm:px-6 sm:pb-6">
              {/* 当前账户 */}
              <div className="flex flex-wrap items-center gap-3 rounded-md border bg-muted/30 p-3">
                <span className="relative flex size-9 shrink-0 overflow-hidden rounded-full">
                  <img className="aspect-square size-full" alt="" src={data.account.avatarUrl || '/images/avatar.svg'} />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{data.account.displayName || data.account.username}</p>
                  <p className="truncate text-xs text-muted-foreground">{data.account.email}</p>
                </div>
                <span className="inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium border-transparent bg-secondary text-secondary-foreground">
                  <ShieldCheck className="size-3" />
                  {t('consent.currentAccount')}
                </span>
              </div>

              <div role="none" className="h-px w-full shrink-0 bg-border" />

              {/* 权限说明 */}
              <section className="flex flex-col gap-3">
                <div>
                  <p className="text-sm font-medium">{t('consent.scopeTitle')}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{t('consent.scopeDesc')}</p>
                </div>
                <div className="flex flex-col gap-2">
                  {data.client.scopes.map((s) => {
                    // 优先用语言包（admin.scopes.<key>）本地化；未收录则回落到后端文案。
                    const key = s.key ?? ''
                    const nameKey = `admin.scopes.${key}`
                    const descKey = `${nameKey}.desc`
                    const name = key && t(nameKey) !== nameKey ? t(nameKey) : s.name
                    const desc = key && t(descKey) !== descKey ? t(descKey) : s.description
                    return (
                      <div key={s.key || s.name} className="flex flex-wrap items-start gap-3 rounded-md border p-3">
                        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                        <div className="min-w-48 flex-1">
                          <p className="text-sm font-medium">{name}</p>
                          {desc && <p className="mt-1 text-xs text-muted-foreground">{desc}</p>}
                        </div>
                        {s.level === 'high' ? (
                          <span className="inline-flex w-fit items-center justify-center gap-1 overflow-hidden whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium border-transparent bg-destructive text-destructive-foreground">
                            {t('consent.levelHigh')}
                          </span>
                        ) : (
                          <span className="inline-flex w-fit items-center justify-center gap-1 overflow-hidden whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium text-foreground">
                            {t('consent.levelStandard')}
                          </span>
                        )}
                      </div>
                    )
                  })}
                </div>
              </section>

              {/* 完成后将返回 */}
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Earth className="size-4 shrink-0" />
                <span className="truncate">{t('consent.willReturn', { url: data.client.redirectUri })}</span>
                <ExternalLink className="size-4 shrink-0" />
              </div>
            </div>

            {/* 拒绝 / 同意授权 */}
            <div data-slot="card-footer" className="items-center px-6 grid grid-cols-1 gap-3 border-t bg-muted/20 sm:grid-cols-2">
              <Button type="button" variant="outline" className="w-full" disabled={submitting} onClick={() => handleAction('deny')}>
                <X className="size-4" />
                {t('consent.deny')}
              </Button>
              <Button type="button" className="w-full" disabled={submitting} onClick={() => handleAction('allow')}>
                <Check className="size-4" />
                {submitting ? t('consent.processing') : t('consent.allow')}
              </Button>
            </div>
          </>
        ) : null}
      </div>
      <PublicSiteFooter className="max-sm:px-4 max-sm:pb-6" />
    </main>
  )
}
