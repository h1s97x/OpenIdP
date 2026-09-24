import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '../components/ui/card'
import { Field } from '../components/ui/field'
import { Button } from '../components/ui/button'
import { Input, Label } from '../components/ui/input'
import { api, ApiError } from '../lib/api'
import { NotificationPreferences } from '../components/settings/NotificationPreferences'
import { useI18n } from '../i18n'
import { useSession } from '../hooks/useSession'
import { useToast } from '../components/ui/toast'
import { Camera, Save, RefreshCw } from 'lucide-react'

interface ProfileData {
  username?: string
  subject?: string
  displayName?: string
  phone?: string
  address?: string
  avatarUrl?: string
  email?: string
  emailVerified?: boolean
  id?: number
  tickets?: { id?: number; subject?: string }[]
}

export function ProfilePage() {
  const { session } = useSession()
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data: profile, isError, refetch } = useQuery({ queryKey: ['profile'], queryFn: () => api.profile<ProfileData>() })
  const [displayName, setDisplayName] = React.useState('')
  const [address, setAddress] = React.useState('')

  const fileRef = React.useRef<HTMLInputElement>(null)

  // 站点是否允许上传头像（后端 siteInfo.avatarUploadEnabled）
  const avatarUploadEnabled = !!session?.site?.avatarUploadEnabled

  // 是否存在未保存改动。此前 effect 无条件把 profile 灌回表单，
  // 任何一次 invalidate（含其它页面触发的）都会把正在编辑的内容冲掉。
  const dirtyRef = React.useRef(false)
  const syncedRef = React.useRef(false)

  React.useEffect(() => {
    if (!profile) return
    if (!syncedRef.current || !dirtyRef.current) {
      setDisplayName(profile.displayName ?? '')
      setAddress(profile.address ?? '')
      syncedRef.current = true
    }
  }, [profile])

  const isDirty =
    !!profile &&
    (displayName !== (profile.displayName ?? '') ||
      address !== (profile.address ?? ''))

  const save = useMutation({
    mutationFn: () =>
      // 不再提交 phone：手机号由安全中心的 /me/phone* 流程维护，
      // 该端点会忽略请求体里的 phone（早期版本会把漏传当空串写入，清空已有号码）。
      api.patchProfile({ displayName, address }),
    onSuccess: () => {
      dirtyRef.current = false
      qc.invalidateQueries({ queryKey: ['profile'] })
      qc.invalidateQueries({ queryKey: ['session'] })
      toast({ type: 'success', title: t('profile.savedToast') })
    },
    onError: (e) => {
      toast({ type: 'error', title: t('profile.saveFail'), description: e instanceof ApiError ? e.message : '' })
    },
  })

  // 头像上传（2MB 以内）
  const uploadAvatar = useMutation({
    mutationFn: (file: File) => api.uploadAvatar(file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['profile'] })
      qc.invalidateQueries({ queryKey: ['session'] })
      toast({ type: 'success', title: t('profile.avatarUploaded') })
    },
    onError: (e) => toast({ type: 'error', title: t('profile.avatarFail'), description: e instanceof ApiError ? e.message : '' }),
  })

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (!f) return
    if (f.size > 2 * 1024 * 1024) {
      toast({ type: 'error', title: t('profile.avatarTooLarge') })
      return
    }
    uploadAvatar.mutate(f)
    e.target.value = ''
  }

  const avatarUrl = profile?.avatarUrl

  return (
    <div className="space-y-6">
      {/* 页头：左侧色条 + 标题 */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b pb-6">
        <div className="border-l-2 border-primary pl-3">
          <h1 className="text-2xl font-bold md:text-3xl">{t('profile.title')}</h1>
        </div>
      </div>

      {/* 个人资料：头像上传 + 只读 ID/用户名 + 昵称/地址 + 底部保存 */}
      {/* 手机号不在本页维护，统一走安全中心的 /me/phone* 流程 */}
      <Card>
        <CardHeader className="border-b px-6 pb-5">
          <CardTitle>{t('profile.cardTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 pt-6">
          {/* 头像区：加大头像 + 圆环，仅保留「更换头像」 */}
          <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-start">
            <div className="flex flex-col items-center gap-3">
              <div className="flex size-24 items-center justify-center overflow-hidden rounded-full border-4 border-background bg-primary text-3xl font-semibold text-primary-foreground shadow-sm ring-1 ring-border">
                {avatarUrl
                  ? <img src={avatarUrl} alt="" className="size-full object-cover" />
                  : (displayName || profile?.username || 'Y')[0]}
              </div>
              <input
                ref={fileRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/svg+xml,image/gif"
                className="hidden"
                onChange={onFileChange}
              />
              {avatarUploadEnabled && (
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={uploadAvatar.isPending}>
                    <Camera className="size-4" /> {t('profile.changeAvatar')}
                  </Button>
                </div>
              )}
            </div>
            <div className="w-full min-w-0 space-y-4 sm:flex-1">
              <Field label={t('profile.userId')} className="gap-2" disabled>
                <Input value={profile?.subject ? `#${profile.subject}` : `#${profile?.id ?? ''}`} readOnly disabled className="bg-muted text-muted-foreground" />
              </Field>
              <Field label={t('profile.username')} className="gap-2" disabled>
                <Input value={profile?.username ?? ''} readOnly disabled className="bg-muted text-muted-foreground" />
              </Field>
            </div>
          </div>

          {/* 昵称 / 地址（手机号与邮箱在安全中心维护） */}
          <div className="grid gap-5 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label>{t('profile.displayName')}</Label>
              <Input
                value={displayName}
                onChange={(e) => { dirtyRef.current = true; setDisplayName(e.target.value) }}
              />
            </div>
            <div className="space-y-1.5 md:col-span-2">
              <Label>{t('profile.address')}</Label>
              <Input
                value={address}
                onChange={(e) => { dirtyRef.current = true; setAddress(e.target.value) }}
                placeholder={t('profile.addressPlaceholder')}
              />
            </div>
          </div>

          {/* 请求失败：给出明确提示与重试入口，而不是把三个空输入框呈现为「资料为空」 */}
          {isError && (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
              <span className="text-sm text-destructive">{t('common.loadFailed')}</span>
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                <RefreshCw className="size-4" /> {t('common.retry')}
              </Button>
            </div>
          )}

        </CardContent>
        <CardFooter className="justify-end gap-3 border-t bg-muted/20">
          {isDirty && <span className="text-xs text-muted-foreground">{t('notifications.unsavedHint')}</span>}
          <Button onClick={() => save.mutate()} disabled={save.isPending || !isDirty}>
            <Save className="size-4" /> {t('profile.save')}
          </Button>
        </CardFooter>
      </Card>

      {/* 偏好：原「通知设置」页并入此处（侧栏不再单列该入口） */}
      <NotificationPreferences />

    </div>
  )
}
