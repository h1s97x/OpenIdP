import * as React from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button } from '../components/ui/button'
import { api, ApiError } from '../lib/api'
import { useI18n } from '../i18n'
import { formatDateTimeI18n, safeExternalUrl, cn } from '../lib/utils'
import { useToast } from '../components/ui/toast'
import { useConfirm } from '../components/ui/confirm'
import { AppWindow, ExternalLink, Loader2, RefreshCw, AlertTriangle, ShieldAlert, KeyRound } from 'lucide-react'

interface ScopeDetail {
  /** 原始权限标识（如 openid），用于查语言包做本地化 */
  key?: string
  name?: string
  description?: string
  /** standard | high —— 高风险权限在明细里单独标注 */
  level?: string
}

interface GrantRow {
  id: string
  clientId: string
  clientName?: string
  clientLogo?: string
  clientUrl?: string
  /** 应用申请到的权限项（authoritative 名称或 scope 串） */
  scopes?: string[]
  /** 权限明细（名称 / 说明 / 风险等级），由后端与授权同意页共用同一份定义 */
  scopeDetails?: ScopeDetail[]
  /** 高风险权限数量 */
  highRiskCount?: number
  createdAt?: string
  /** 最近一次令牌签发/轮换时间，老数据可能没有 */
  lastUsedAt?: string
  [k: string]: unknown
}

export function AppsPage() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const { data: grants, isPending, isError, refetch } = useQuery({ queryKey: ['grants'], queryFn: () => api.grants<GrantRow[]>() })
  const items = Array.isArray(grants) ? grants : []
  // 正在撤销的那一行：只禁用它，不影响其它行
  const [pendingId, setPendingId] = React.useState<string | null>(null)

  const revoke = async (id: string) => {
    await confirm({
      title: t('apps.revokeConfirmTitle'),
      description: t('apps.revokeConfirmDesc'),
      confirmText: t('common.revoke'),
      variant: 'destructive',
      // 传 onConfirm：弹窗等到请求完成才关闭，期间锁定按钮，
      // 避免「弹窗已关、请求还在飞」时重复点击产生第二次 DELETE。
      onConfirm: async () => {
        setPendingId(id)
        try {
          await api.revokeGrant(id)
          // await 刷新完成再提示成功：否则列表可能还显示着已撤销的条目
          await qc.invalidateQueries({ queryKey: ['grants'] })
          toast({ type: 'success', title: t('apps.revoked') })
        } catch (err: any) {
          toast({ type: 'error', title: err instanceof ApiError ? err.message : (err?.message || t('apps.revokeFailed')) })
          throw err
        } finally {
          setPendingId(null)
        }
      },
    })
  }

  // scopeLabel / scopeDesc：与授权同意页一致，优先查语言包（admin.scopes.<key>），
  // 未收录时回落到后端下发的名称与说明，避免同一权限在两页文案不一致。
  const scopeLabel = (s: ScopeDetail) => {
    const key = s.key ?? ''
    const nameKey = `admin.scopes.${key}`
    if (key && t(nameKey) !== nameKey) return t(nameKey)
    return s.name || key
  }
  const scopeDesc = (s: ScopeDetail) => {
    const key = s.key ?? ''
    const descKey = `admin.scopes.${key}.desc`
    if (key && t(descKey) !== descKey) return t(descKey)
    return s.description || ''
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="mt-2 flex items-center gap-3 border-b pb-3 text-2xl font-semibold">
          <span className="inline-block h-5 w-1 rounded-full bg-primary" />
          {t('apps.title')}
        </h1>
      </div>

      {/* 加载中：给骨架，而不是落进空态 */}
      {isPending && (
        <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" /> {t('common.loading')}
        </div>
      )}

      {/* 请求失败：明确报错 + 重试。
          此前失败与「确实没有授权」长得一模一样（都是一个空列表 + 「0 个应用」），
          用户会把加载失败误读为「授权都已清除」。 */}
      {isError && (
        <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
          <AlertTriangle className="size-6 text-destructive" />
          <div className="text-sm font-medium">{t('common.loadFailed')}</div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="size-4" /> {t('common.retry')}
          </Button>
        </div>
      )}

      {!isPending && !isError && items.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
            <AppWindow className="size-6 text-muted-foreground" />
          </div>
          <div className="mt-4 text-sm font-medium">{t('apps.empty')}</div>
          <div className="mt-1 text-sm text-muted-foreground">{t('apps.emptyDesc')}</div>
        </div>
      )}

      {/* 卡片列表：单个应用一张卡。
            卡片结构（参考青桔身份中心的「应用授权」）：
              头部   —— 应用图标 + 名称 + 简介
              信息行 —— 权限数量 / 高风险数量 / 撤销提示 三个说明胶囊
              明细   —— 权限逐项展开（名称 + 风险 chip + 标识 + 说明），
                        用户能看到「这个应用到底能读什么」，而不是一句「已授权 N 项权限」
              底部   —— 最近活跃时间 + 访问应用 / 撤销授权 */}
      {!isPending && !isError && items.length > 0 && (
        <div className="space-y-4">
          {items.map((g) => {
            const details: ScopeDetail[] = Array.isArray(g.scopeDetails) && g.scopeDetails.length
              ? g.scopeDetails
              : (Array.isArray(g.scopes) ? g.scopes.map((s) => ({ key: s, name: s })) : [])
            const scopeCount = details.length
            // 后端已算好高风险数；老数据（无 scopeDetails）回落到 0，不会虚报。
            const highRisk = typeof g.highRiskCount === 'number'
              ? g.highRiskCount
              : details.filter((d) => d.level === 'high').length
            // 简介位：优先用后端下发的权限说明（让人一眼看懂「这应用能干什么」），
            // 没有就展示 scope 原始串，再没有就留空——绝不回落显示 Client ID。
            const summaryText = details.length
              ? details.map((d) => scopeDesc(d)).filter(Boolean).join('、')
              : ''
            const visitUrl = safeExternalUrl(g.clientUrl)
            const lastUsed = g.lastUsedAt || g.createdAt
            return (
              <div
                key={g.id}
                className="flex flex-col gap-4 rounded-3xl border bg-card/85 px-5 py-5 text-card-foreground shadow-sm backdrop-blur-md"
              >
                {/* 头部：应用图标 + 应用名 + 简介 */}
                <div className="flex items-start gap-3">
                  <div className="grid size-12 shrink-0 place-items-center overflow-hidden rounded-xl bg-muted">
                    {safeExternalUrl(g.clientLogo) ? (
                      <img src={safeExternalUrl(g.clientLogo)} alt="" className="size-full object-cover" />
                    ) : (
                      <AppWindow className="size-6 shrink-0 text-muted-foreground" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-base font-semibold">
                      {g.clientName || g.clientId}
                    </div>
                    {summaryText && (
                      <div className="mt-1 line-clamp-2 text-sm text-muted-foreground">{summaryText}</div>
                    )}
                  </div>
                </div>

                {/* 信息行：权限数量 / 高风险数量 / 撤销提示 */}
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex h-7 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md bg-muted px-2.5 text-xs text-muted-foreground">
                    <KeyRound className="size-3.5" aria-hidden />
                    {t('apps.scopeRange', { count: scopeCount })}
                  </span>
                  <span
                    className={cn(
                      'inline-flex h-7 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 text-xs',
                      highRisk > 0
                        ? 'bg-destructive/10 text-destructive'
                        : 'bg-muted text-muted-foreground',
                    )}
                  >
                    <ShieldAlert className="size-3.5" aria-hidden />
                    {highRisk > 0 ? t('apps.highRiskCount', { count: highRisk }) : t('apps.highRiskNone')}
                  </span>
                  <span className="inline-flex h-7 shrink-0 items-center whitespace-nowrap rounded-md bg-muted px-2.5 text-xs text-muted-foreground">
                    {t('apps.reauthHint')}
                  </span>
                </div>

                {/* 权限明细：逐项展开名称 / 风险 / 标识 / 说明 */}
                {details.length > 0 && (
                  <div className="rounded-2xl border bg-muted/20 p-3">
                    <div className="mb-2 text-xs font-medium text-muted-foreground">{t('apps.scopeDetails')}</div>
                    <div className="grid gap-2 sm:grid-cols-2">
                      {details.map((d) => {
                        const risky = d.level === 'high'
                        return (
                          <div key={d.key ?? d.name} className="rounded-xl border bg-card/70 px-3 py-2.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="truncate text-sm font-medium">{scopeLabel(d)}</span>
                              <span
                                className={cn(
                                  'shrink-0 rounded-full border px-2 py-0.5 text-[11px]',
                                  risky
                                    ? 'border-destructive/30 bg-destructive/10 text-destructive'
                                    : 'text-muted-foreground',
                                )}
                              >
                                {risky ? t('apps.riskHigh') : t('apps.riskStandard')}
                              </span>
                            </div>
                            <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">{d.key ?? d.name}</div>
                            {scopeDesc(d) && (
                              <div className="mt-1.5 line-clamp-2 text-xs leading-5 text-muted-foreground">{scopeDesc(d)}</div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* 底部：左侧时间，右侧操作按钮（访问应用 / 撤销授权） */}
                <div className="flex items-center gap-2">
                  <div className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
                    {lastUsed ? t('apps.lastUsedAt', { date: formatDateTimeI18n(lastUsed, lang) }) : ''}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {visitUrl && (
                      <a
                        href={visitUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex h-9 items-center justify-center gap-1.5 whitespace-nowrap rounded-md bg-secondary px-3 text-sm font-medium text-secondary-foreground transition-all hover:bg-secondary/80"
                      >
                        {t('apps.visit')}
                        <ExternalLink className="size-3.5 shrink-0" aria-hidden />
                      </a>
                    )}
                    <Button
                      variant="outline"
                      onClick={() => revoke(g.id)}
                      disabled={pendingId === g.id}
                    >
                      {pendingId === g.id ? t('common.loading') : t('apps.revokeGrant')}
                    </Button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
