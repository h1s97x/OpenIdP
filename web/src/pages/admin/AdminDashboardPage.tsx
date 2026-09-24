import * as React from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card'
import { api } from '../../lib/api'
import { useI18n } from '../../i18n'
import { formatDateTimeI18n, formatDayI18n, formatIpRegion } from '../../lib/utils'
import { Users, Activity, LogIn, AppWindow, ShieldCheck, AlertTriangle, ArrowUpRight } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'

interface AdminDashboardData {
  generatedAt: string
  stats: {
    totalUsers: number
    todayNewUsers: number
    activeSessions: number
    totalEvents: number
    todayLogins: number
    activeApps: number
  }
  loginTrend: { at: string; count: number }[]
  recentEvents: any[]
}

export function AdminDashboardPage() {
  const { t, lang } = useI18n()
  const { data } = useQuery({
    queryKey: ['admin', 'dashboard'],
    queryFn: () => api.adminDashboard<AdminDashboardData>(),
  })
  const stats = data?.stats

  const cards = [
    { label: t('admin.dashboard.totalUsers'), value: stats?.totalUsers ?? 0, sub: t('admin.dashboard.todayNew', { count: stats?.todayNewUsers ?? 0 }), icon: Users },
    { label: t('admin.dashboard.activeSessions'), value: stats?.activeSessions ?? 0, sub: t('admin.dashboard.activeSessionsSub'), icon: ShieldCheck },
    { label: t('admin.dashboard.todayLogins'), value: stats?.todayLogins ?? 0, sub: t('admin.dashboard.todayLoginsSub'), icon: LogIn },
    { label: t('admin.dashboard.loginEvents'), value: stats?.totalEvents ?? 0, sub: t('admin.dashboard.loginEventsSub'), icon: Activity },
    { label: t('admin.dashboard.apps'), value: stats?.activeApps ?? 0, sub: t('admin.dashboard.appsSub'), icon: AppWindow },
  ]

  // 趋势横轴按系统时区解析 at（后端已按系统时区切分日界）。
  const trend = (data?.loginTrend ?? []).map((p) => ({
    ...p,
    label: formatDayI18n(p.at, lang),
  }))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t('admin.dashboard.title')}</h1>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map((c) => (
          <Card key={c.label}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{c.label}</span>
                <c.icon className="size-4 text-muted-foreground" />
              </div>
              <div className="mt-2 text-3xl font-semibold">{c.value}</div>
              <div className="mt-1 text-xs text-muted-foreground">{c.sub}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('admin.dashboard.trend')}</CardTitle>
          <CardDescription>{t('admin.dashboard.trendDesc')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trend}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" width={30} />
                <Tooltip />
                <Line type="monotone" dataKey="count" stroke="var(--primary)" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('admin.dashboard.watchEvents')}</CardTitle>
          <CardDescription className="flex flex-wrap items-center justify-between gap-2">
            <span>{t('admin.dashboard.watchEventsDesc')}</span>
            <Link
              to="/admin/audit"
              className="inline-flex items-center gap-1 text-xs font-medium text-primary underline-offset-4 hover:underline"
            >
              {t('admin.dashboard.openAudit')} <ArrowUpRight className="size-3" />
            </Link>
          </CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          {(data?.recentEvents ?? []).map((e: any) => (
            <div key={e.id} className="flex items-center gap-3 py-2.5">
              {/* 列表里全是失败/异常事件，用警示色 tile 与其它卡片区分 */}
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-destructive/10 text-destructive">
                <AlertTriangle className="size-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{e.summary}</div>
                <div className="text-xs text-muted-foreground">{e.ipAddress} · {formatIpRegion(e.ipRegion)}</div>
              </div>
              <div className="text-xs text-muted-foreground">{formatDateTimeI18n(e.createdAt, lang)}</div>
            </div>
          ))}
          {!data?.recentEvents?.length && <div className="py-10 text-center text-sm text-muted-foreground">{t('admin.dashboard.noWatchEvents')}</div>}
        </CardContent>
      </Card>
    </div>
  )
}
