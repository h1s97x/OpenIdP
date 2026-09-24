import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Select, SelectItem } from '../components/ui/select'
import { Pagination } from '../components/ui/pagination'
import { Button } from '../components/ui/button'
import { api } from '../lib/api'
import { useI18n } from '../i18n'
import { formatDateTimeI18n, methodLabelKey, formatIpRegion } from '../lib/utils'
import { ShieldCheck, LogIn, AlertTriangle, History, UserCog, AppWindow, MonitorSmartphone, Loader2, RefreshCw } from 'lucide-react'

const PAGE_SIZE = 10

// 事件分类：登录认证 / 账号变更 / 会话操作 / 应用授权
type Category = 'login' | 'profile' | 'session' | 'grant'

// categoryOf 按事件类型归入分类。
//
// 归类依据后端实际写入的事件类型：
//   登录认证 login.success / login.failed / mfa.verify_failed / mfa.challenge_locked
//   会话操作 session.* / logout / admin.grant_revoked（撤销授权连带会话失效）
//   应用授权 grant.created / grant.revoked
//   账号变更 其余（密码/邮箱/头像/MFA 开关/通行密钥/注销等）
function categoryOf(type: string): Category {
  const n = (type ?? '').toLowerCase()
  if (n.includes('grant')) return 'grant'
  if (n.includes('session') || n.includes('logout')) return 'session'
  if (n.includes('login') || n.includes('signin')) return 'login'
  // 二次验证失败属于登录链路（尝试登录被拒），MFA 开关本身则算账号变更。
  if (n === 'mfa.verify_failed' || n === 'mfa.challenge_locked') return 'login'
  return 'profile'
}

const TABS: { value: 'all' | Category; labelKey: string }[] = [
  { value: 'all', labelKey: 'events.tab.all' },
  { value: 'login', labelKey: 'events.tab.login' },
  { value: 'profile', labelKey: 'events.tab.profile' },
  { value: 'session', labelKey: 'events.tab.session' },
  { value: 'grant', labelKey: 'events.tab.grant' },
]

function iconFor(type: string) {
  switch (categoryOf(type)) {
    case 'login': return <LogIn className="size-4 text-primary" />
    case 'session': return <MonitorSmartphone className="size-4 text-foreground" />
    case 'grant': return <AppWindow className="size-4 text-foreground" />
    default: return <UserCog className="size-4 text-foreground" />
  }
}

interface EventRow { id?: number; type?: string; summary?: string; createdAt?: string; [k: string]: unknown }

export function EventsPage() {
  const { t, lang } = useI18n()
  const [tab, setTab] = React.useState<'all' | Category>('all')
  const [page, setPage] = React.useState(1)

  // 分类过滤交给服务端（/?category=）：此前是一次取大页再在前端 filter，
  // 而后端 parsePage 对超界 pageSize 会静默降级为 20，
  // 于是分类统计只覆盖最新 20 条——低频分类长期显示 0，
  // 用户会误判「没有可疑活动」。现在 tab 与 page 一起进 queryKey，
  // 分页与总数都由服务端的 total 决定。
  const {
    data: eventsData,
    isPending,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['events', tab, page],
    queryFn: () => api.events<{ items: EventRow[]; total?: number }>(undefined, page, PAGE_SIZE, tab === 'all' ? undefined : tab),
  })

  const items: any[] = eventsData?.items ?? []
  // 服务端返回的全量总数（跨页、跨分类都准确）
  const totalCount: number = eventsData?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE))
  const safePage = Math.min(page, totalPages)
  React.useEffect(() => { if (safePage !== page) setPage(safePage) }, [safePage, page])
  const pageItems = items

  // 分类计数无法从单次请求得到，单独取一次各分类的总数。
  const { data: countsData } = useQuery({
    queryKey: ['events-counts'],
    queryFn: () => api.eventCounts<{ all?: number; login?: number; profile?: number; session?: number; grant?: number }>(),
  })
  const counts = {
    all: countsData?.all ?? 0,
    login: countsData?.login ?? 0,
    profile: countsData?.profile ?? 0,
    session: countsData?.session ?? 0,
    grant: countsData?.grant ?? 0,
  }

  return (
    <div className="space-y-6">
      {/* 页头：左侧色条 + 标题 + 右侧分类选择 */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b pb-6">
        <div className="border-l-2 border-primary pl-3">
          <h1 className="text-2xl font-bold md:text-3xl">{t('events.title')}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t('events.desc')}</p>
        </div>
        <Select value={tab} onValueChange={(v) => { setTab(v as 'all' | Category); setPage(1) }} className="w-36" ariaLabel={t('events.filter')}>
          {TABS.map((tb) => (
            <SelectItem key={tb.value} value={tb.value}>{t(tb.labelKey)}</SelectItem>
          ))}
        </Select>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_17rem]">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>{t('events.allTitle')}</CardTitle>
                <CardDescription>{t('events.allDesc')}</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            <Table className="[&_td]:px-3 [&_td]:py-3">
              <TableHeader>
                <TableRow>
                  <TableHead>{t('events.event')}</TableHead>
                  <TableHead>{t('events.source')}</TableHead>
                  <TableHead>{t('events.client')}</TableHead>
                  <TableHead className="text-right">{t('events.time')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isPending && (
                  <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">
                    <span className="inline-flex items-center gap-2"><Loader2 className="size-4 animate-spin" /> {t('common.loading')}</span>
                  </TableCell></TableRow>
                )}
                {isError && (
                  <TableRow><TableCell colSpan={4} className="py-10 text-center">
                    {/* 请求失败必须显式区分于「确实没有事件」：
                        安全事件页显示「暂无事件」会被误读为没有可疑活动。 */}
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
                {pageItems.map((e: any) => (
                  <TableRow key={e.id}>
                    <TableCell>
                      <div className="flex items-start gap-3">
                        <span className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">
                          {e.type === 'login.failed' ? <AlertTriangle className="size-4 text-warning" /> : iconFor(e.type)}
                        </span>
                        <div className="min-w-0">
                          <div className="truncate text-sm font-medium">{e.summary}</div>
                          <div className="mt-1 flex flex-wrap items-center gap-1.5">
                            <Badge variant="outline">{t(`events.category.${categoryOf(e.type)}`)}</Badge>
                            <span className="text-xs text-muted-foreground">{t(methodLabelKey(e.metadata?.method))}</span>
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">{e.ipAddress}</div>
                      <div className="text-xs text-muted-foreground">{formatIpRegion(e.ipRegion)}</div>
                    </TableCell>
                    {/* 客户端 UA 过长会撑破表格，统一截断并用 title 保留完整值 */}
                    <TableCell className="max-w-64">
                      <div className="truncate text-xs text-muted-foreground" title={e.userAgent}>{e.userAgent}</div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right text-xs text-muted-foreground">{formatDateTimeI18n(e.createdAt, lang)}</TableCell>
                  </TableRow>
                ))}
                {!isPending && !isError && pageItems.length === 0 && (
                  <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">{t('events.empty')}</TableCell></TableRow>
                )}
              </TableBody>
            </Table>
            <Pagination page={safePage} totalPages={totalPages} onPageChange={setPage} />
          </CardContent>
        </Card>

        {/* 摘要卡：按分类统计数量 */}
        <Card className="h-fit">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-4" /> {t('events.summary')}</CardTitle>
            <CardDescription>{t('events.summaryDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">{t('events.total')}</span>
              <span className="text-xl font-semibold tabular-nums">{counts.all}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">{t('events.loginAuth')}</span>
              <span className="text-xl font-semibold tabular-nums">{counts.login}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">{t('events.securityChanges')}</span>
              <span className="text-xl font-semibold tabular-nums">{counts.profile}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">{t('events.tab.session')}</span>
              <span className="text-xl font-semibold tabular-nums">{counts.session}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">{t('events.tab.grant')}</span>
              <span className="text-xl font-semibold tabular-nums">{counts.grant}</span>
            </div>
            <div className="border-t pt-3">
              <div className="text-xs text-muted-foreground">{t('events.recentActive')}</div>
              <div className="mt-1 flex items-center gap-2 text-sm">
                <History className="size-4 text-muted-foreground" />
                {items[0] ? formatDateTimeI18n(items[0].createdAt, lang) : '—'}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
