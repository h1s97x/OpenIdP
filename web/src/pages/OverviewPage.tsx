import { useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { Card } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Select, SelectItem } from '../components/ui/select'
import { Sparkline } from '../components/ui/sparkline'
import { api } from '../lib/api'
import { useI18n } from '../i18n'
import { Button } from '../components/ui/button'
import { formatDayI18n, formatIpRegion, cn } from '../lib/utils'
import { AppWindow, UserRoundCheck, ShieldCheck, KeyRound, RefreshCw } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import * as React from 'react'

interface TrendPoint { at: string; count: number }

interface Dashboard {
  generatedAt: string
  loginMethods: Record<string, number>
  loginTrend: TrendPoint[]
  /** 新增会话的按天序列（统计卡趋势线用，与登录趋势区分） */
  sessionTrend?: TrendPoint[]
  /** 新增授权的按天序列 */
  grantTrend?: TrendPoint[]
  /** 过去 24 小时（含当前小时）的成功登录数 */
  todayLogins?: number
  /** 过去 24 小时的逐小时登录序列（固定 24 桶，含空桶） */
  todayHourly?: TrendPoint[]
  recentLogins: any[]
}

const WINDOWS = [
  { value: '7d', labelKey: 'overview.window7d' },
  { value: '30d', labelKey: 'overview.window30d' },
]

export function OverviewPage() {
  const { t, lang } = useI18n()
  // 变量不能叫 window：它会遮蔽全局 window 对象，
  // 组件内一旦用到 window.location / addEventListener 就会直接报错。
  const [windowKey, setWindowKey] = React.useState('7d')
  const {
    data, refetch, isFetching, isPending, isError,
  } = useQuery({
    queryKey: ['dashboard', windowKey],
    queryFn: () => api.dashboard(windowKey),
    // 切换时间窗口时保留上一份数据并叠加半透明遮罩，
    // 避免 data 变 undefined 导致统计卡与图表闪成 0。
    placeholderData: keepPreviousData,
  })
  const { data: sessions } = useQuery({ queryKey: ['sessions'], queryFn: api.sessions })
  // 已授权应用数：此前硬编码为 '0'，与实际授权数无关。
  const { data: grants } = useQuery({ queryKey: ['grants'], queryFn: api.grants })
  const dash = data as Dashboard | undefined
  const sessionCount = Array.isArray(sessions) ? sessions.length : '—'
  const grantCount = Array.isArray(grants) ? String(grants.length) : '—'

  // 统计卡的迷你趋势线：各自使用真实数据源（授权 / 会话 / 登录 / 逐小时登录），
  // 不用同一条登录曲线糊弄三张卡——那样趋势线只是装饰，读起来是误导。
  const trendOf = (list?: TrendPoint[]) => (list ?? []).map((p) => p.count)
  const stats: {
    label: string
    value: string
    sub: string
    icon: LucideIcon
    trend?: number[]
    trendLabel?: string
  }[] = [
    {
      label: t('overview.stat.apps'), value: grantCount, sub: t('overview.stat.appsSub'), icon: AppWindow,
      trend: trendOf(dash?.grantTrend), trendLabel: t('overview.stat.appsTrend'),
    },
    {
      // 「今日登录」取后端按过去 24 小时统计的 todayLogins；此前用的是
      // loginMethods.password（既不是今日口径，也不含验证码/通行密钥登录）。
      label: t('overview.stat.today'), value: String(dash?.todayLogins ?? 0), sub: t('overview.stat.todaySub'), icon: UserRoundCheck,
      trend: trendOf(dash?.todayHourly), trendLabel: t('overview.stat.todayTrend'),
    },
    {
      label: t('overview.stat.sessions'), value: String(sessionCount), sub: t('overview.stat.sessionsSub'), icon: ShieldCheck,
      trend: trendOf(dash?.sessionTrend), trendLabel: t('overview.stat.sessionsTrend'),
    },
    {
      label: t('overview.stat.logins'), value: String(dash?.loginTrend?.reduce((a, b) => a + b.count, 0) ?? 0), sub: t('overview.stat.loginsSub'), icon: KeyRound,
      trend: trendOf(dash?.loginTrend), trendLabel: t('overview.stat.loginsTrend'),
    },
  ]

  const trendData = (dash?.loginTrend ?? []).map((p) => ({
    ...p,
    label: formatDayI18n(p.at, lang),
  }))

  // 刷新要覆盖本页两个数据源：此前只 refetch dashboard，
  // 「活跃会话」统计卡不会更新。
  const [refreshing, setRefreshing] = React.useState(false)
  const qc = useQueryClient()
  const refreshAll = async () => {
    setRefreshing(true)
    try {
      await Promise.all([
        qc.invalidateQueries({ queryKey: ['dashboard'] }),
        qc.invalidateQueries({ queryKey: ['sessions'] }),
        qc.invalidateQueries({ queryKey: ['grants'] }),
      ])
    } finally {
      setRefreshing(false)
    }
  }

  const totalLogins = dash?.loginTrend?.reduce((a, b) => a + b.count, 0) ?? 0
  const passwordCount = dash?.loginMethods?.password ?? 0
  const passwordPct = totalLogins > 0 ? Math.round((passwordCount / totalLogins) * 100) : 0

  // 认证方式分布：此前只画 password 一片，后端已返回
  // password / emailCode / passkey / thirdParty / other 五项，应全部呈现。
  const METHOD_COLORS = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)']
  const METHOD_KEYS = ['password', 'emailCode', 'passkey', 'thirdParty', 'other']
  const pieData = METHOD_KEYS
    .map((k, i) => ({ name: t(`overview.methods.${k}`), value: dash?.loginMethods?.[k] ?? 0, fill: METHOD_COLORS[i] }))
    .filter((d) => d.value > 0)

  // 「最常用方式」改为按实际分布取最大值，不再固定写死为密码
  const topMethod = pieData.reduce<(typeof pieData)[number] | null>(
    (best, d) => (best === null || d.value > best.value ? d : best), null)
  const topMethodName = topMethod?.name
  const topMethodPct = topMethod && totalLogins > 0 ? Math.round((topMethod.value / totalLogins) * 100) : 0

  return (
    <div className="space-y-6">
      {/* 页头：左侧色条 + badge + 标题 + 右侧窗口选择/刷新 */}
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b pb-6">
        <div className="border-l-2 border-primary pl-3">
          <h1 className="text-2xl font-bold md:text-3xl">{t('overview.title')}</h1>
        </div>
        <div className="flex items-center gap-2">
          <Select
            value={windowKey}
            onValueChange={setWindowKey}
            className="w-[9.5rem] shrink-0 whitespace-nowrap"
            ariaLabel={t('overview.window')}
          >
            {WINDOWS.map((w) => (
              <SelectItem key={w.value} value={w.value}>{t(w.labelKey)}</SelectItem>
            ))}
          </Select>
          <button
            onClick={() => refreshAll()}
            disabled={refreshing}
            title={t('overview.refresh')}
            aria-label={t('overview.refresh')}
            className="flex size-9 items-center justify-center rounded-md border bg-background shadow-xs transition-colors hover:bg-accent hover:text-accent-foreground disabled:opacity-50 dark:bg-input/30 dark:border-input dark:hover:bg-input/50"
          >
            <RefreshCw className={(isFetching || refreshing) ? 'size-4 animate-spin' : 'size-4'} />
          </button>
        </div>
      </div>

      {/* 请求失败：明确提示并提供重试。
          此前失败与「确实没有数据」都渲染成 0，用户会把加载失败误读为「当天没有登录」。 */}
      {isError && (
        <Card className="border-destructive/30 bg-destructive/5">
          <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
            <span className="text-sm text-destructive">{t('common.loadFailed')}</span>
            <Button variant="outline" size="sm" onClick={() => refreshAll()} disabled={refreshing}>
              <RefreshCw className={refreshing ? 'size-4 animate-spin' : 'size-4'} /> {t('common.retry')}
            </Button>
          </div>
        </Card>
      )}

      {/* 统计卡片（含迷你趋势线：底部 mt-auto 贴底，同行卡片高度由 grid 拉伸对齐） */}
      <div className={cn('grid gap-4 sm:grid-cols-2 xl:grid-cols-4', isPending && 'opacity-60')}>
        {stats.map((s) => (
          <Card key={s.label} className="flex flex-col rounded-3xl border bg-card/85 py-6 shadow-sm backdrop-blur-md">
            <div className="flex flex-row items-center justify-between gap-3 px-6 pb-2">
              <div className="text-sm font-medium">{s.label}</div>
              <div className="grid size-9 place-items-center rounded-lg bg-muted text-muted-foreground">
                <s.icon className="size-4" />
              </div>
            </div>
            <div className="px-6">
              <div className="text-2xl font-bold tabular-nums">{s.value}</div>
              <p className="mt-1 text-xs text-muted-foreground">{s.sub}</p>
            </div>
            <div className="mt-auto px-3 pt-3">
              {/* 全 0 序列也会留出高度，保证四张卡基线一致 */}
              <Sparkline data={s.trend ?? []} height={36} label={s.trendLabel} />
            </div>
          </Card>
        ))}
      </div>

      {/* 登录趋势 + 最近活动（1.4fr/0.6fr） */}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(300px,0.6fr)]">
        <Card className="min-w-0 rounded-3xl border bg-card/85 py-6 shadow-sm backdrop-blur-md">
          <div className="grid auto-rows-min grid-rows-[auto_auto] items-start gap-1.5 px-6">
            <div className="font-semibold leading-none">{t('overview.trend')}</div>
            <div className="text-sm text-muted-foreground">{t('overview.trendDesc')}</div>
          </div>
          <div className="px-6">
            <div className="h-72">
              {/* 空数据时不画坐标轴：否则只剩两根轴，无法区分「真的没数据」和「渲染失败」 */}
              {trendData.length === 0 ? (
                <div className="grid h-full place-items-center text-sm text-muted-foreground">{t('overview.noData')}</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={trendData} margin={{ top: 12, right: 8, left: -12, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="label" tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" axisLine={false} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" width={30} axisLine={false} tickLine={false} />
                    <Tooltip cursor={{ fill: 'var(--muted)', opacity: 0.4 }} />
                    <Bar dataKey="count" name={t('overview.stat.logins')} fill="var(--primary)" radius={[4, 4, 0, 0]} maxBarSize={74} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </Card>

        <Card className="min-w-0 rounded-3xl border bg-card/85 py-6 shadow-sm backdrop-blur-md">
          <div className="grid auto-rows-min grid-rows-[auto_auto] items-start gap-1.5 px-6">
            <div className="font-semibold leading-none">{t('overview.recent')}</div>
          </div>
          {/* 描述与列表之间留出分隔（mt-3 + divide-y），条目间距收紧为 gap-3 */}
          <div className="px-6">
            <div className="mt-3 grid gap-3 divide-y divide-border">
              {(dash?.recentLogins ?? []).slice(0, 5).map((l: any) => (
                <div key={l.id} className="flex items-start gap-3 pt-3 first:pt-0">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{l.application}</p>
                    <p className="truncate text-xs text-muted-foreground">{formatIpRegion(l.ipRegion)}</p>
                  </div>
                  <Badge variant="outline" className="shrink-0 text-[11px]">{formatDayI18n(l.at, lang)}</Badge>
                </div>
              ))}
              {!dash?.recentLogins?.length && <div className="py-8 text-center text-sm text-muted-foreground">{t('overview.recentEmpty')}</div>}
            </div>
          </div>
        </Card>
      </div>

      {/* 认证方式（环形图 + 统计） */}
      <Card className="rounded-3xl border bg-card/85 py-6 shadow-sm backdrop-blur-md">
        <div className="grid auto-rows-min grid-rows-[auto_auto] items-start gap-1.5 px-6">
          <div className="font-semibold leading-none">{t('overview.methods')}</div>
        </div>
        <div className="px-6">
          <div className="grid gap-6 md:grid-cols-[11rem_minmax(0,1fr)] md:items-center">
            <div className="relative mx-auto h-44 w-full max-w-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={48} outerRadius={70} paddingAngle={0} strokeWidth={0}>
                    {pieData.map((p, i) => <Cell key={i} fill={p.fill} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
                <div>
                  <div className="text-xl font-bold tabular-nums">{totalLogins}</div>
                  <p className="text-xs text-muted-foreground">{t('overview.methodsSuccess')}</p>
                </div>
              </div>
            </div>
            <div className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
              <div className="grid grid-cols-2 gap-4 border-b pb-5 sm:col-span-2">
                <div>
                  <p className="text-xs text-muted-foreground">{t('overview.methodsTotal')}</p>
                  <p className="mt-1 text-2xl font-semibold tabular-nums">{totalLogins}</p>
                </div>
                <div className="border-s ps-4">
                  <p className="text-xs text-muted-foreground">{t('overview.methodsCommon')}</p>
                  <p className="mt-1 truncate text-sm font-semibold">{topMethodName ?? '—'}</p>
                  <p className="text-xs tabular-nums text-muted-foreground">{topMethodPct}%</p>
                </div>
              </div>
              {/* 图例：按认证方式全量列出，与环形图扇区一一对应 */}
              {pieData.length === 0 ? (
                <div className="text-sm text-muted-foreground sm:col-span-2">{t('overview.noData')}</div>
              ) : (
                pieData.map((p) => {
                  const pct = totalLogins > 0 ? Math.round((p.value / totalLogins) * 100) : 0
                  return (
                    <div key={p.name} className="flex items-center justify-between gap-3 text-sm">
                      <span className="flex min-w-0 items-center gap-2 font-medium">
                        <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: p.fill }} />
                        <span className="truncate">{p.name}</span>
                      </span>
                      <span className="shrink-0 tabular-nums text-muted-foreground">
                        {p.value} {t('overview.methodsUnit')}<span className="ms-1 text-xs">{pct}%</span>
                      </span>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}
