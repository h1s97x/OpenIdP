// 通知偏好：原「通知设置」独立页面的内容，现并入「个人资料」页的偏好小节。
//
// 保留原实现的两个关键行为：
//   1) 乐观更新 + 保存失败回滚（开关拨了但服务端未写入时，UI 不能停在「已开启」）；
//   2) invalidate 重灌不覆盖未保存改动（dirtyRef），否则用户拨到一半会被静默重置。
import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../ui/card'
import { Button } from '../ui/button'
import { Switch } from '../ui/switch'
import { api, ApiError } from '../../lib/api'
import { cn } from '../../lib/utils'
import { useI18n } from '../../i18n'
import { useToast } from '../ui/toast'
import { useSession } from '../../hooks/useSession'
import { AlertTriangle, BellRing, RefreshCw, Save } from 'lucide-react'

// 与远端对比的偏好项。后端不存在 thirdPartyPassword* / privacyEmailInApp，
// 那些开关改了也不会生效，故不在此列出。
const PREF_KEYS = ['newDeviceInApp', 'newDeviceEmail', 'privacyEmailReminder']

interface NotificationPrefsData {
  newDeviceInApp?: boolean
  newDeviceEmail?: boolean
  privacyEmailReminder?: boolean
  // emailAvailable：邮件类通道是否可用（依赖 SMTP 配置）。由接口直接下发，
  // 与 /capabilities 的 personal.notificationEmail 同源，两者都作为判定依据。
  emailAvailable?: boolean
  [k: string]: unknown
}

export function NotificationPreferences() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { capabilities } = useSession()

  const { data: prefs, isPending, isError, refetch } = useQuery({
    queryKey: ['notif-prefs'],
    queryFn: () => api.notificationPrefs<NotificationPrefsData>(),
  })

  // 邮件类通知依赖 SMTP：未配置时对应开关展示为不可用，
  // 而不是让用户打开一个「永远不会生效」的开关。
  // 两个来源取或：接口自己下发的 emailAvailable 更贴近数据，capabilities 兼容旧响应；
  // 服务端也会拒绝开启（notification.email_unavailable），前端禁用只是第一道提示。
  const emailAvailable = !!((prefs as NotificationPrefsData | undefined)?.emailAvailable
    ?? capabilities?.personal?.notificationEmail)
  const [local, setLocal] = React.useState<any>(null)
  // 记录是否存在未保存改动。invalidate 引起的重灌会带回 prefs，
  // 若无条件覆盖，用户拨到一半的开关会被静默重置。
  const dirtyRef = React.useRef(false)
  // 是否已完成首次同步。判定「首次」不能用 local === null，
  // 因为回滚后 local 可能非 null 但仍需重新同步。
  const syncedRef = React.useRef(false)

  React.useEffect(() => {
    if (!prefs) return
    if (!syncedRef.current || !dirtyRef.current) {
      setLocal(prefs)
      syncedRef.current = true
    }
  }, [prefs])

  // 无变更时禁用保存按钮（避免无效的保存请求）。
  // 注意这里不校验 !!prefs：prefs 缺失时由错误态接管，
  // 若在这里短路，请求失败会导致保存按钮永久禁用且无任何提示。
  const isDirty = React.useMemo(
    () => !!local && !!prefs && PREF_KEYS.some((k) => !!local[k] !== !!(prefs as Record<string, unknown>)[k]),
    [local, prefs]
  )

  const toggle = (key: string, v: boolean) => {
    dirtyRef.current = true
    setLocal((p: any) => ({ ...p, [key]: v }))
  }

  const save = useMutation({
    mutationFn: () => api.patchNotificationPrefs(local),
    onSuccess: () => {
      dirtyRef.current = false
      // 直接用提交值写回缓存：不依赖 invalidate + effect 覆盖，
      // 既少一次请求，也避免 effect 把刚提交的值又冲掉。
      // emailAvailable 不是偏好项、不在提交值里，必须原样带上，
      // 否则写回后它变成 undefined，邮件开关会瞬间从可用变灰。
      qc.setQueryData(['notif-prefs'], { ...local, emailAvailable: prefs?.emailAvailable })
      toast({ type: 'success', title: t('notifications.saved') })
    },
    onError: (e: any) => {
      // 保存失败必须回滚：开关是乐观更新的，
      // 不回滚的话 UI 显示「已开启」而服务端仍是旧值。
      if (prefs) setLocal(prefs)
      dirtyRef.current = false
      toast({
        type: 'error',
        title: t('notifications.saveFailed'),
        description: e instanceof ApiError ? e.message : (e?.message ?? ''),
      })
    },
  })

  // 类别在前、渠道在后：类别是「通知什么事」，行内是「通过哪个渠道」。
  const groups = [
    {
      title: t('notifications.newDevice'),
      items: [
        { key: 'newDeviceInApp', label: t('notifications.inApp'), disabled: false },
        { key: 'newDeviceEmail', label: t('notifications.email'), disabled: !emailAvailable },
      ],
    },
    {
      title: t('notifications.privacyEmail'),
      items: [
        { key: 'privacyEmailReminder', label: t('notifications.email'), disabled: !emailAvailable },
      ],
    },
  ]

  return (
    <Card>
      <CardHeader className="border-b px-6 pb-5">
        <CardTitle className="flex items-center gap-2">
          <BellRing className="size-4" /> {t('profile.prefs')}
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-5 pt-6">
        {/* 请求失败：明确告知并提供重试，而不是渲染成一排「关闭」的开关让人以为自己没开过 */}
        {isError ? (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
            <span className="inline-flex items-center gap-2 text-sm text-destructive">
              <AlertTriangle className="size-4" /> {t('common.loadFailed')}
            </span>
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="size-4" /> {t('common.retry')}
            </Button>
          </div>
        ) : (
          <>
            {groups.map((g) => (
              <div key={g.title} className="space-y-2">
                <div className="text-sm font-medium">{g.title}</div>
                <div className="divide-y rounded-lg border px-4">
                  {g.items.map((item) => {
                    const on = !isPending && !!local?.[item.key]
                    return (
                      <div key={item.key} className="flex items-center justify-between gap-3 py-3.5">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">{item.label}</span>
                            {/* 状态 chip：一眼看清每个渠道当前开没开，不必去读开关位置 */}
                            <span
                              className={cn(
                                'shrink-0 rounded-full border px-2 py-0.5 text-[11px]',
                                on ? 'border-success/30 bg-success/10 text-success' : 'text-muted-foreground',
                              )}
                            >
                              {on ? t('notifications.chipOn') : t('notifications.chipOff')}
                            </span>
                          </div>
                        </div>
                        <Switch
                          // 数据未就绪时禁用并给出不确定的勾选态，
                          // 而不是默认 false——否则首屏开关都显示「关」，
                          // 数据到位后突然跳变，用户可能在这几百毫秒内误拨。
                          checked={isPending ? false : !!local?.[item.key]}
                          // disabled 渠道（如未配置 SMTP 时的邮件通知）同样禁用：
                          // 打开一个永远不会生效的开关只会造成误导。
                          disabled={isPending || save.isPending || !!item.disabled}
                          onCheckedChange={(v) => toggle(item.key, v)}
                        />
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
          </>
        )}
      </CardContent>

      {/* 保存按钮收敛到卡片底部一处：多个开关共用同一份 isDirty 与 mutation */}
      <CardFooter className="justify-end gap-3 border-t bg-muted/20">
        {isDirty && <span className="text-xs text-muted-foreground">{t('notifications.unsavedHint')}</span>}
        <Button onClick={() => save.mutate()} disabled={isError || isPending || save.isPending || !isDirty}>
          {save.isPending ? <RefreshCw className="size-4 animate-spin" /> : <Save className="size-4" />}
          {t('notifications.save')}
        </Button>
      </CardFooter>
    </Card>
  )
}
