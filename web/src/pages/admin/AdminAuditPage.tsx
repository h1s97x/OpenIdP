import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
import { api } from '../../lib/api'
import { useI18n } from '../../i18n'
import { formatDateTimeI18n, formatIpRegion } from '../../lib/utils'
import { Search, FileClock, User, KeyRound, RefreshCw, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Sparkline } from '../../components/ui/sparkline'
import { cn } from '../../lib/utils'
// 「授权记录」已并入本页面，作为第二个页签。
import { GrantsSection } from './AdminGrantsPage'

interface AuditStats {
  windowDays: number
  total: number
  success: number
  failed: number
  trend: { at: string; total: number; success: number; failed: number }[]
}

type AuditTab = 'events' | 'grants'

function parseTab(v: string | null): AuditTab {
  return v === 'grants' ? 'grants' : 'events'
}

interface AuditRow { id?: number; [k: string]: unknown }

export function AdminAuditPage() {
  const { t, lang } = useI18n()
  const [params, setParams] = useSearchParams()
  const tab = parseTab(params.get('tab'))
  const [q, setQ] = React.useState('')
  const [debounced, setDebounced] = React.useState('')
  const [user, setUser] = React.useState('')
  const [debouncedUser, setDebouncedUser] = React.useState('')
  const [page, setPage] = React.useState(1)

  // 页签写进地址栏：刷新后仍停留在「授权记录」，不会跳回审计日志。
  // 基于现有参数做 set/delete：此前整体替换 params，
  // 会顺手清掉 URL 上的其它 query 参数。
  const setTab = (v: AuditTab) => {
    const next = new URLSearchParams(params)
    if (v === 'events') next.delete('tab')
    else next.set('tab', v)
    setParams(next, { replace: true })
  }

  React.useEffect(() => {
    const t0 = setTimeout(() => setDebounced(q), 300)
    return () => clearTimeout(t0)
  }, [q])

  React.useEffect(() => {
    const t0 = setTimeout(() => setDebouncedUser(user), 300)
    return () => clearTimeout(t0)
  }, [user])

  const { data, isError, refetch } = useQuery({
    queryKey: ['admin', 'audit', debounced, debouncedUser, page],
    queryFn: () => api.adminAuditEvents<{ items: AuditRow[]; total: number }>({ q: debounced, user: debouncedUser, page, pageSize: 20 }),
  })
  const items: any[] = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / 20))

  // 统计摘要与列表相互独立：筛选/翻页不该改变统计卡口径（统计卡始终是全局口径）。
  const { data: stats } = useQuery({
    queryKey: ['admin', 'audit-stats'],
    queryFn: () => api.adminAuditStats<AuditStats>(7),
  })
  const trend = stats?.trend ?? []

  // 筛选后总数变小时当前页会越界，列表空白且只剩「上一页」，
  // 看起来像数据丢失。后端不夹取页码，前端把页码拉回有效范围。
  React.useEffect(() => {
    if (page > totalPages) setPage(totalPages)
  }, [page, totalPages])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t('admin.audit.title')}</h1>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as AuditTab)}>
        <TabsList>
          <TabsTrigger value="events"><FileClock className="size-4" /> {t('admin.audit.tab.events')}</TabsTrigger>
          <TabsTrigger value="grants"><KeyRound className="size-4" /> {t('admin.audit.tab.grants')}</TabsTrigger>
        </TabsList>

        <TabsContent value="events">
          {/* 统计卡：总量 / 成功 / 失败 + 近 7 天迷你趋势线。
              失败口径与列表筛选一致（事件类型含 .failed）。 */}
          <div className="mt-3 grid gap-4 sm:grid-cols-3">
            <AuditStatCard
              label={t('admin.audit.statTotal')}
              value={stats?.total ?? 0}
              trend={trend.map((p) => p.total)}
              icon={FileClock}
              color="var(--primary)"
            />
            <AuditStatCard
              label={t('admin.audit.statSuccess')}
              value={stats?.success ?? 0}
              trend={trend.map((p) => p.success)}
              icon={CheckCircle2}
              color="var(--success)"
            />
            <AuditStatCard
              label={t('admin.audit.statFailed')}
              value={stats?.failed ?? 0}
              trend={trend.map((p) => p.failed)}
              icon={XCircle}
              color="var(--destructive)"
            />
          </div>
          <Card className="mt-4">
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <CardTitle>{t('admin.audit.records')}</CardTitle>
                  <CardDescription>{t('admin.audit.total', { count: total })}</CardDescription>
                </div>
                <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
                  <div className="relative w-full min-w-0 flex-1 sm:w-56 sm:flex-none">
                    <User className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input value={user} onChange={(e) => { setUser(e.target.value); setPage(1) }} placeholder={t('admin.audit.userPlaceholder')} className="pl-8" />
                  </div>
                  <div className="relative w-full min-w-0 flex-1 sm:w-64 sm:flex-none">
                    <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} placeholder={t('admin.audit.searchPlaceholder')} className="pl-8" />
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('admin.audit.event')}</TableHead>
                    <TableHead>{t('admin.audit.user')}</TableHead>
                    <TableHead>{t('admin.audit.source')}</TableHead>
                    <TableHead>{t('admin.audit.region')}</TableHead>
                    <TableHead>{t('admin.audit.client')}</TableHead>
                    <TableHead>{t('admin.audit.time')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((e: any) => (
                    <TableRow key={e.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <FileClock className="size-4 text-muted-foreground" />
                          <span className="text-sm">{e.summary}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        {e.user ? (
                          <div className="flex flex-col">
                            <span className="text-xs font-medium">{e.user.displayName || e.user.username}</span>
                            <span className="text-[11px] text-muted-foreground">{e.user.email || e.user.username}</span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs">{e.ipAddress}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatIpRegion(e.ipRegion)}</TableCell>
                      <TableCell className="max-w-[12rem] truncate text-xs text-muted-foreground">{e.userAgent}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(e.createdAt, lang)}</TableCell>
                    </TableRow>
                  ))}
                  {/* 审计日志加载失败必须显式提示：显示「暂无记录」会被
                      误读为「这段时间没有任何操作」，是安全审计上的错误结论。 */}
                  {isError && (
                    <TableRow><TableCell colSpan={6} className="py-10 text-center">
                      <div className="flex flex-col items-center gap-3 text-sm text-muted-foreground">
                        <span className="inline-flex items-center gap-2 text-destructive">
                          <AlertTriangle className="size-4" /> {t('common.loadFailed')}
                        </span>
                        <Button variant="outline" size="sm" onClick={() => refetch()}>
                          <RefreshCw className="size-4" /> {t('common.retry')}
                        </Button>
                      </div>
                    </TableCell></TableRow>
                  )}
                  {!isError && items.length === 0 && (
                    <TableRow><TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">{t('admin.audit.empty')}</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>

              <div className="mt-4 flex items-center justify-between">
                <div className="text-xs text-muted-foreground">{t('common.page', { page, total: totalPages })}</div>
                <div className="flex gap-1">
                  <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>{t('common.prev')}</Button>
                  <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>{t('common.next')}</Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="grants">
          <GrantsSection />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// AuditStatCard 是审计页顶部的统计卡：标签 + 图标 + 数值 + 近 7 天迷你趋势线。
// 与个人总览保持同一套视觉（卡片贴底趋势线），成功/失败用语义色区分。
function AuditStatCard({ label, value, trend, icon: Icon, color }: {
  label: string
  value: number
  trend: number[]
  icon: LucideIcon
  color: string
}) {
  return (
    <Card className="flex flex-col py-5">
      <div className="flex items-center justify-between gap-3 px-5">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span className={cn('grid size-8 place-items-center rounded-lg bg-muted')} style={{ color }}>
          <Icon className="size-4" />
        </span>
      </div>
      <div className="px-5 pt-1 text-3xl font-semibold tabular-nums">{value}</div>
      <div className="mt-auto px-2 pt-3">
        <Sparkline data={trend} height={32} color={color} />
      </div>
    </Card>
  )
}
