import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { BellRing, CheckCheck, ShieldAlert, Megaphone, Info, Trash2, Check } from 'lucide-react'
import { api } from '../../lib/api'
import { formatDateTimeI18n } from '../../lib/utils'
import { cn } from '../../lib/utils'
import { useI18n } from '../../i18n'
import { useToast } from '../ui/toast'
import { useConfirm } from '../ui/confirm'

function iconFor(type: string) {
  switch (type) {
    case 'new_device_login': return <ShieldAlert className="size-4 text-warning" />
    case 'admin': return <Megaphone className="size-4 text-primary" />
    default: return <Info className="size-4 text-muted-foreground" />
  }
}

interface NotificationItem {
  id: number
  title?: string
  summary?: string
  read?: boolean
  createdAt?: string
  [k: string]: unknown
}

export function NotificationCenter() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const [open, setOpen] = React.useState(false)
  const ref = React.useRef<HTMLDivElement>(null)
  const prevFirstId = React.useRef<number | null>(null)

  const { data } = useQuery({
    queryKey: ['notifications'],
    queryFn: () => api.notifications<{ items: NotificationItem[]; unreadCount?: number }>(1, 50),
    refetchInterval: 60_000,
  })
  // 未读数走独立端点：轮询时无需拉取全量列表，显著省流量。
  const { data: unreadData } = useQuery({
    queryKey: ['notifications', 'unread-count'],
    queryFn: () => api.unreadNotificationCount<{ unreadCount: number }>(),
    refetchInterval: 30_000,
  })
  const items: any[] = data?.items ?? []
  const unread: number = unreadData?.unreadCount ?? data?.unreadCount ?? 0

  // 右下角弹窗提醒新通知（仅非首次加载）
  React.useEffect(() => {
    if (open) return
    const firstId = items[0]?.id
    if (firstId == null) return
    if (prevFirstId.current === null) {
      prevFirstId.current = firstId
      return
    }
    if (firstId !== prevFirstId.current) {
      prevFirstId.current = firstId
      const n = items[0]
      toast({
        type: 'info',
        title: n.title || t('nc.newNotification'),
        description: n.summary,
      })
    }
  }, [items, open, toast, t])

  const markAll = useMutation({
    mutationFn: api.markAllNotificationsRead,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['notifications'] })
    },
  })
  const markOne = useMutation({
    mutationFn: (id: number) => api.markNotificationRead(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['notifications'] })
    },
  })

  // 清空：不可恢复，先确认再执行；完成后同时刷新列表与未读计数。
  const clearAll = async () => {
    const ok = await confirm({
      title: t('nc.clearConfirmTitle'),
      description: t('nc.clearConfirmDesc'),
      confirmText: t('nc.clear'),
      variant: 'destructive',
      onConfirm: async () => {
        try {
          await api.clearNotifications()
          await qc.invalidateQueries({ queryKey: ['notifications'] })
          toast({ type: 'success', title: t('nc.clearDone') })
        } catch (err: any) {
          toast({ type: 'error', title: t('nc.clearFailed'), description: err?.message })
          throw err
        }
      },
    })
    void ok
  }

  React.useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onEsc)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onEsc)
    }
  }, [open])

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        title={t('topbar.notifications')}
        aria-label={`${t('topbar.notifications')}，${unread} ${t('nc.unread')}`}
        className="relative inline-flex size-9 items-center justify-center rounded-full text-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
      >
        <BellRing className="size-[1.15rem]" />
        {unread > 0 && (
          <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-medium text-primary-foreground">
            {unread > 99 ? '99+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="fixed inset-x-3 top-[4.75rem] z-50 overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-xl sm:absolute sm:inset-x-auto sm:right-0 sm:top-11 sm:w-[22rem]">
          <div className="flex items-center justify-between border-b px-4 py-3">
            <div>
              <div className="text-sm font-semibold">{t('nc.title')}</div>
              <div className="text-xs text-muted-foreground">
                {unread > 0 ? t('nc.unreadCount', { count: unread }) : t('nc.desc')}
              </div>
            </div>
            <div className="flex items-center gap-3">
              {unread > 0 && (
                <button
                  onClick={() => markAll.mutate()}
                  className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                >
                  <CheckCheck className="size-3.5" /> {t('nc.markAllRead')}
                </button>
              )}
              {items.length > 0 && (
                <button
                  onClick={clearAll}
                  className="flex items-center gap-1 text-xs text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="size-3.5" /> {t('nc.clear')}
                </button>
              )}
            </div>
          </div>

          <div className="max-h-[22rem] overflow-y-auto">
            {items.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                  <BellRing className="size-5 text-muted-foreground" />
                </div>
                <div className="mt-3 text-sm font-medium">{t('nc.empty')}</div>
                <div className="mt-1 text-xs text-muted-foreground">{t('nc.desc')}</div>
              </div>
            ) : (
              <div className="divide-y">
                {items.map((n: any) => (
                  <div
                    key={n.id}
                    className={cn(
                      'flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-accent/60',
                      !n.read && 'bg-primary/[0.04]'
                    )}
                  >
                    <div className={cn(
                      'mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg',
                      n.read ? 'bg-muted' : 'bg-primary/10'
                    )}>
                      {iconFor(n.type)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className={cn('truncate text-sm', n.read ? 'font-normal text-muted-foreground' : 'font-medium')}>
                          {n.title}
                        </span>
                        {/* 未读 chip：与「全部已读」按钮呼应，比一个小圆点更容易识别 */}
                        {!n.read && (
                          <span className="shrink-0 rounded-full border border-primary/30 bg-primary/10 px-1.5 py-px text-[10px] font-medium text-primary">
                            {t('nc.unreadChip')}
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">{n.summary}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground/70">{formatDateTimeI18n(n.createdAt, lang)}</div>
                      {/* 行内动作：不必先「点开」再操作，未读可单条已读，详情直达事件页 */}
                      <div className="mt-1.5 flex items-center gap-3">
                        {!n.read && (
                          <button
                            type="button"
                            onClick={() => markOne.mutate(n.id)}
                            className="inline-flex items-center gap-1 text-[11px] text-muted-foreground underline-offset-4 transition-colors hover:text-foreground hover:underline"
                          >
                            <Check className="size-3" /> {t('nc.markRead')}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
