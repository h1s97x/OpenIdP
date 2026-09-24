import * as React from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs'
import { Button } from '../components/ui/button'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator } from '../components/ui/dropdown-menu'
import { Pagination } from '../components/ui/pagination'
import { api } from '../lib/api'
import { useI18n } from '../i18n'
import { useToast } from '../components/ui/toast'
import { useConfirm } from '../components/ui/confirm'
import { formatDateTimeI18n, formatIpRegion } from '../lib/utils'
import {
  MonitorSmartphone, Laptop, Smartphone, RefreshCw, ShieldCheck, ShieldX, History,
  UserCheck, Ellipsis, Clock,
} from 'lucide-react'

const PAGE_SIZE = 10

// 设备图标：按 UA 判断形态，未识别时回落到通用时钟图标。
function deviceIcon(ua: string) {
  if (/iphone|android|mobile/i.test(ua)) return <Smartphone className="size-4 text-muted-foreground" />
  if (/windows|macintosh|mac os|linux/i.test(ua)) return <Laptop className="size-4 text-muted-foreground" />
  return <MonitorSmartphone className="size-4 text-muted-foreground" />
}

// 过期可信设备不再生效，列表里需要如实标注。
function isExpired(expiresAt?: string): boolean {
  if (!expiresAt) return false
  const t = new Date(expiresAt).getTime()
  return Number.isFinite(t) && t <= Date.now()
}

// 设备名称：直接按 UA 判定，未识别的客户端（curl / Python 等）归入「未知设备」，
// 不再错误地笼统显示成「桌面设备」。
function deviceLabel(ua: string, lang?: string): string {
  if (ua && /iphone|android|mobile/i.test(ua)) return '移动设备'
  if (/macintosh|mac os/i.test(ua)) return 'Mac'
  if (/windows/i.test(ua)) return 'Windows 设备'
  if (/linux/i.test(ua)) return 'Linux 设备'
  if (lang === 'en') return 'Unknown device'
  return '未知设备'
}

// 会话是否有效：当前会话，或未过期。
//
// 后端 Session 模型没有 revokedAt 字段、下线是物理删除，
// 因此不做「已下线」判断（此前那行是死代码）。
// expiresAt 缺失时按有效处理：缺省判为失效会让正常会话从有效列表里消失。
function sessionValid(s: any): boolean {
  if (s.current) return true
  if (!s.expiresAt) return true
  const t = new Date(s.expiresAt).getTime()
  return Number.isFinite(t) && t > Date.now()
}

interface SessionRow { id: string; [k: string]: unknown }
interface DeviceRow { id: string; [k: string]: unknown }
interface TrustedRow { id: string; [k: string]: unknown }

export function SessionsPage() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const { data: sessions, refetch, isFetching } = useQuery({ queryKey: ['sessions'], queryFn: () => api.sessions<SessionRow[]>() })
  const { data: devices } = useQuery({ queryKey: ['devices'], queryFn: () => api.devices<DeviceRow[]>() })
  const { data: trusted } = useQuery({ queryKey: ['trusted-devices'], queryFn: () => api.trustedDevices<TrustedRow[]>() })
  const [page, setPage] = React.useState(1)

  const sessionList: any[] = sessions ?? []
  const deviceList: any[] = devices ?? []
  const trustedList: any[] = trusted ?? []
  const activeSessions = sessionList.filter((s) => sessionValid(s))
  const pastSessions = sessionList.filter((s) => !sessionValid(s))

  // 当前使用的设备是否已被标记为可信（用于「设为可信设备」的可用性与文案）
  const currentDeviceTrusted = trustedList.some((td) => td.current && !isExpired(td.expiresAt))

  // 列表数据源：有效会话 / 历史会话 / 登录设备 / 可信设备
  const lists = {
    sessions: activeSessions,
    past: pastSessions,
    devices: deviceList,
    trusted: trustedList,
  }
  const [tab, setTab] = React.useState<keyof typeof lists>('sessions')
  const current = lists[tab]
  const totalPages = Math.max(1, Math.ceil(current.length / PAGE_SIZE))
  // 切换分类或列表缩减后（如下线会话）修正越界页码。
  const safePage = Math.min(page, totalPages)
  React.useEffect(() => { if (safePage !== page) setPage(safePage) }, [safePage, page])
  const pageItems = current.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE)

  // 破坏性操作的进行中标识：pendingId 针对单行，busyAction 针对整页操作。
  const [pendingId, setPendingId] = React.useState<string | null>(null)
  const [busyAction, setBusyAction] = React.useState<string | null>(null)
  // 手动刷新进行中。refetch 只覆盖 sessions，故这里走 invalidate。
  const [refreshing, setRefreshing] = React.useState(false)

  const refreshAll = async () => {
    setRefreshing(true)
    try {
      await invalidate()
    } finally {
      setRefreshing(false)
    }
  }

  // 刷新必须覆盖三个数据源：此前只刷新 sessions，
  // 在「登录设备 / 可信设备」页签点刷新时列表纹丝不动，只有按钮在转。
  const invalidate = async () => {
    await Promise.all([
      qc.invalidateQueries({ queryKey: ['sessions'] }),
      qc.invalidateQueries({ queryKey: ['devices'] }),
      qc.invalidateQueries({ queryKey: ['trusted-devices'] }),
    ])
  }

  const kickSession = async (id: string) => {
    await confirm({
      title: t('sessions.kickConfirmTitle'),
      description: t('sessions.kickConfirmDesc'),
      confirmText: t('sessions.kick'),
      onConfirm: async () => {
        setPendingId(id)
        try {
          await api.deleteSession(id)
          await invalidate()
          toast({ type: 'success', title: t('sessions.kicked') })
        } catch (err) {
          toast({ type: 'error', title: t('sessions.kickFailed'), description: err instanceof Error ? err.message : undefined })
          throw err
        } finally {
          setPendingId(null)
        }
      },
    })
  }

  const trustSession = async (s: any) => {
    if (!s.current) {
      toast({ type: 'error', title: t('sessions.trustCurrentOnly') })
      return
    }
    if (pendingId) return
    setPendingId(s.id)
    try {
      await api.addTrustedDevice(deviceLabel(s.userAgent, lang))
      await invalidate()
      toast({ type: 'success', title: t('sessions.trusted') })
    } catch (err: any) {
      toast({ type: 'error', title: err?.message || t('sessions.trustFailed') })
    } finally {
      setPendingId(null)
    }
  }

  const removeTrusted = async (id: string) => {
    await confirm({
      title: t('sessions.untrustConfirmTitle'),
      description: t('sessions.untrustConfirmDesc'),
      confirmText: t('sessions.untrust'),
      variant: 'destructive',
      onConfirm: async () => {
        setPendingId(id)
        try {
          await api.deleteTrustedDevice(id)
          await invalidate()
          toast({ type: 'success', title: t('sessions.untrusted') })
        } catch (err: any) {
          toast({ type: 'error', title: err?.message || t('sessions.untrustFailed') })
          throw err
        } finally {
          setPendingId(null)
        }
      },
    })
  }

  const logoutOthers = async () => {
    await confirm({
      title: t('sessions.logoutOthersConfirmTitle'),
      description: t('sessions.logoutOthersConfirmDesc'),
      confirmText: t('sessions.logoutOthers'),
      onConfirm: async () => {
        setBusyAction('logoutOthers')
        try {
          await api.deleteOtherSessions()
          await invalidate()
          toast({ type: 'success', title: t('sessions.logoutOthersDone') })
        } catch (err) {
          toast({ type: 'error', title: t('sessions.logoutOthersFailed'), description: err instanceof Error ? err.message : undefined })
          throw err
        } finally {
          setBusyAction(null)
        }
      },
    })
  }

  // 三点菜单：仅在会话仍可操作时渲染（历史/已下线会话没有可执行动作）
  const canAct = (s: any) => sessionValid(s)

  // 页签内的上下文统计所需的值：当前会话设备名、当前设备识别数、可信设备过期数。
  const currentSession = activeSessions.find((s: any) => s.current)
  const currentDeviceCount = deviceList.filter((d: any) => d.current).length
  const trustedExpired = trustedList.filter((td: any) => isExpired(td.expiresAt)).length

  return (
    <div className="space-y-6">
      {/* 页头：左侧色条 + 标题 + 右侧刷新/下线其他会话 */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b pb-6">
        <div className="border-l-2 border-primary pl-3">
          <h1 className="text-2xl font-bold md:text-3xl">{t('sessions.title')}</h1>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={refreshAll} disabled={refreshing || isFetching}>
            <RefreshCw className={(refreshing || isFetching) ? 'size-4 animate-spin' : 'size-4'} /> {t('sessions.refresh')}
          </Button>
          <Button variant="outline" size="sm" onClick={logoutOthers} disabled={busyAction === 'logoutOthers' || refreshing}>
            {t('sessions.logoutOthers')}
          </Button>
        </div>
      </div>

      {/* 分段页签：等宽铺满 + 计数。
          计数与页签一一对应，原先另有一排 4 张统计卡展示同样的数字（信息重复）；
          现在把「上下文统计」下沉到各页签内部，见下方 StatTile。 */}
      <Tabs value={tab} onValueChange={(v) => { setTab(v as keyof typeof lists); setPage(1) }}>
        <TabsList className="grid h-auto w-full grid-cols-2 gap-1 rounded-xl bg-muted p-1 text-muted-foreground sm:grid-cols-4">
          <TabsTrigger value="sessions" className="h-9">
            {t('sessions.tab.active')}
            <span className="tabular-nums opacity-70">{activeSessions.length}</span>
          </TabsTrigger>
          <TabsTrigger value="past" className="h-9">
            {t('sessions.tab.past')}
            <span className="tabular-nums opacity-70">{pastSessions.length}</span>
          </TabsTrigger>
          <TabsTrigger value="devices" className="h-9">
            {t('sessions.tab.devices')}
            <span className="tabular-nums opacity-70">{deviceList.length}</span>
          </TabsTrigger>
          <TabsTrigger value="trusted" className="h-9">
            {t('sessions.tab.trusted')}
            <span className="tabular-nums opacity-70">{trustedList.length}</span>
          </TabsTrigger>
        </TabsList>

        {/* 有效会话：设备 / 来源地址 / 最近活动 / 状态（三点菜单） */}
        <TabsContent value="sessions">
          {/* 上下文统计：页签只回答「有多少条」，统计块补充当前设备与可信设备情况 */}
          <div className="mb-3 mt-3 grid gap-3 sm:grid-cols-2">
            <StatTile label={t('sessions.stat.active')} value={activeSessions.length} />
            <StatTile
              label={t('sessions.currentSession')}
              value={currentSession ? deviceLabel(currentSession.userAgent, lang) : '—'}
            />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>{t('sessions.activeTitle')}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <Table className="[&_td]:px-3 [&_td]:py-3">
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('sessions.device')}</TableHead>
                    <TableHead>{t('sessions.source')}</TableHead>
                    <TableHead>{t('sessions.lastActive')}</TableHead>
                    <TableHead className="text-right">{t('common.status')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pageItems.map((s: any) => (
                    <TableRow key={s.id} data-current={s.current ? 'true' : undefined} className={s.current ? 'bg-primary/[0.04]' : undefined}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <span className="grid size-9 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">
                            {deviceIcon(s.userAgent)}
                          </span>
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium">{deviceLabel(s.userAgent, lang)}</div>
                            <div className="max-w-72 truncate text-xs text-muted-foreground" title={s.userAgent}>{s.userAgent}</div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">{s.ipAddress}</div>
                        <div className="text-xs text-muted-foreground">{formatIpRegion(s.ipRegion)}</div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(s.lastSeenAt, lang)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          {s.current
                            ? <Badge>{t('sessions.currentSession')}</Badge>
                            : <Badge variant="outline">{t('sessions.valid')}</Badge>}
                          {canAct(s) && (
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="size-8" aria-label={t('sessions.actions')}>
                                  <Ellipsis className="size-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end" className="w-52">
                                <DropdownMenuLabel>{t('sessions.actions')}</DropdownMenuLabel>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  disabled={!s.current || currentDeviceTrusted || pendingId === s.id}
                                  title={s.current ? (currentDeviceTrusted ? t('sessions.trustedAlready') : undefined) : t('sessions.trustCurrentOnly')}
                                  onClick={() => trustSession(s)}
                                >
                                  <ShieldCheck className="size-4" />
                                  {currentDeviceTrusted ? t('sessions.trustedAlready') : t('sessions.trust')}
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  disabled={s.current || pendingId === s.id}
                                  title={s.current ? t('sessions.kickCurrentDisabled') : undefined}
                                  className="text-destructive data-[disabled]:text-destructive"
                                  onClick={() => kickSession(s.id)}
                                >
                                  <ShieldX className="size-4" />
                                  {s.current ? t('sessions.kickCurrentDisabled') : t('sessions.kick')}
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {current.length === 0 && (
                    <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">{t('sessions.emptySessions')}</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
              {current.length > PAGE_SIZE && (
                <Pagination page={safePage} totalPages={totalPages} onPageChange={setPage} />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 历史会话：已过期/已下线，仅作留痕展示，不提供操作 */}
        <TabsContent value="past">
          <div className="mb-3 mt-3 grid gap-3 sm:grid-cols-2">
            <StatTile label={t('sessions.stat.past')} value={pastSessions.length} />
            <StatTile
              label={t('sessions.lastActive')}
              value={pastSessions[0]?.lastSeenAt ? formatDateTimeI18n(pastSessions[0].lastSeenAt, lang) : '—'}
            />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>{t('sessions.pastTitle')}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <Table className="[&_td]:px-3 [&_td]:py-3">
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('sessions.device')}</TableHead>
                    <TableHead>{t('sessions.source')}</TableHead>
                    <TableHead>{t('sessions.lastActive')}</TableHead>
                    <TableHead className="text-right">{t('common.status')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pageItems.map((s: any) => (
                    <TableRow key={s.id}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <span className="grid size-9 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">
                            <Clock className="size-4" />
                          </span>
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium">{deviceLabel(s.userAgent, lang)}</div>
                            <div className="max-w-72 truncate text-xs text-muted-foreground" title={s.userAgent}>{s.userAgent}</div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">{s.ipAddress}</div>
                        <div className="text-xs text-muted-foreground">{formatIpRegion(s.ipRegion)}</div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(s.lastSeenAt, lang)}</TableCell>
                      <TableCell className="text-right">
                        <Badge variant="secondary">{t('sessions.expired')}</Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                  {current.length === 0 && (
                    <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">{t('sessions.emptyPast')}</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
              {current.length > PAGE_SIZE && (
                <Pagination page={safePage} totalPages={totalPages} onPageChange={setPage} />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 登录设备 */}
        <TabsContent value="devices">
          <div className="mb-3 mt-3 grid gap-3 sm:grid-cols-2">
            <StatTile label={t('sessions.stat.devices')} value={deviceList.length} />
            <StatTile label={t('sessions.currentDevice')} value={currentDeviceCount} />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>{t('sessions.devicesTitle')}</CardTitle>
              <CardDescription>{t('sessions.devicesCount', { count: deviceList.length })}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4">
              <Table className="[&_td]:px-3 [&_td]:py-3">
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('sessions.device')}</TableHead>
                    <TableHead>{t('sessions.firstLogin')}</TableHead>
                    <TableHead>{t('sessions.lastActive')}</TableHead>
                    <TableHead>{t('sessions.sessionCount')}</TableHead>
                    <TableHead className="text-right">{t('common.status')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pageItems.map((d: any) => (
                    <TableRow key={d.id} data-current={d.current ? 'true' : undefined} className={d.current ? 'bg-primary/[0.04]' : undefined}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <span className="grid size-9 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">
                            {deviceIcon(d.userAgent)}
                          </span>
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium">{deviceLabel(d.userAgent, lang)}</div>
                            <div className="truncate text-xs text-muted-foreground">{d.lastIpAddress} · {formatIpRegion(d.lastIpRegion)}</div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(d.firstSeenAt, lang)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(d.lastSeenAt, lang)}</TableCell>
                      <TableCell className="tabular-nums">{d.sessionCount}</TableCell>
                      <TableCell className="text-right">
                        {d.current
                          ? <Badge>{t('sessions.currentDevice')}</Badge>
                          : <Badge variant="outline">{t('sessions.valid')}</Badge>}
                      </TableCell>
                    </TableRow>
                  ))}
                  {current.length === 0 && (
                    <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">{t('sessions.emptyDevices')}</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
              {current.length > PAGE_SIZE && (
                <Pagination page={safePage} totalPages={totalPages} onPageChange={setPage} />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 可信设备 */}
        <TabsContent value="trusted">
          <div className="mb-3 mt-3 grid gap-3 sm:grid-cols-2">
            <StatTile label={t('sessions.stat.trusted')} value={trustedList.length} />
            <StatTile label={t('sessions.expired')} value={trustedExpired} />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>{t('sessions.trustedTitle')}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <Table className="[&_td]:px-3 [&_td]:py-3">
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('sessions.trustedName')}</TableHead>
                    <TableHead>{t('sessions.trustedIp')}</TableHead>
                    <TableHead>{t('sessions.trustedRegion')}</TableHead>
                    <TableHead className="text-right">{t('common.status')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pageItems.map((td: any) => (
                    <TableRow key={td.id} data-current={td.current ? 'true' : undefined} className={td.current ? 'bg-primary/[0.04]' : undefined}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <span className="grid size-9 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">
                            <UserCheck className="size-4" />
                          </span>
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium">{td.name}</div>
                            <div className="max-w-72 truncate text-xs text-muted-foreground" title={td.userAgent}>{deviceLabel(td.userAgent, lang)}</div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">{td.ipAddress}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatIpRegion(td.ipRegion)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          {td.current
                            ? <Badge>{t('sessions.trustedCurrent')}</Badge>
                            : <Badge variant="outline">{t('sessions.valid')}</Badge>}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:text-destructive"
                            disabled={pendingId === td.id} onClick={() => removeTrusted(td.id)}
                          >
                            {t('sessions.untrust')}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {current.length === 0 && (
                    <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">{t('sessions.emptyTrusted')}</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
              {current.length > PAGE_SIZE && (
                <Pagination page={safePage} totalPages={totalPages} onPageChange={setPage} />
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

// StatTile 是页签内的上下文统计块：浅灰底、无边框，比统计卡更轻。
// 页签只回答「共有多少条」，统计块负责补充「其中当前设备 / 可信 / 过期的细分」，
// 避免把同一批数字既放在顶部统计卡又放在页签上造成重复。
function StatTile({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-xl bg-muted/50 px-4 py-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 truncate text-2xl font-semibold tabular-nums">{value}</div>
    </div>
  )
}
