import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Input, Label } from '../../components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
import { api, ApiError } from '../../lib/api'
import { useI18n } from '../../i18n'
import { useToast } from '../../components/ui/toast'
import { useConfirm } from '../../components/ui/confirm'
import { usePasswordPolicy } from '../../hooks/usePasswordPolicy'
import { formatDateTimeI18n } from '../../lib/utils'
import { Search, UserPlus, ShieldCheck, ShieldOff, Trash2, RefreshCw, AlertTriangle } from 'lucide-react'

// 用户名规则：与服务端一致，仅允许半角字母与数字，长度 3-32。
const USERNAME_RE = /^[A-Za-z0-9]{3,32}$/

interface UserRow { id: number; username: string; [k: string]: unknown }

// UserAvatar 渲染用户真实头像（u.avatarUrl 指向 /api/v1/files/{publicId}，该端点对
// purpose=avatar 免鉴权直出）。此前只画首字母圆块，管理员无法核对用户头像。
// 无头像或加载失败时回退首字母，避免出现破图。
type AvatarUser = { displayName?: string; username?: string; avatarUrl?: string }

function UserAvatar({ user }: { user: AvatarUser }) {
  const [failed, setFailed] = React.useState(false)
  const initial = (user.displayName || user.username || '?')[0]
  const url = user.avatarUrl
  if (!url || failed) {
    return (
      <span className="flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-primary/10 text-sm font-semibold text-primary">
        {initial}
      </span>
    )
  }
  return (
    <img
      src={url}
      alt={user.displayName || user.username || ''}
      className="h-8 w-8 shrink-0 rounded-full object-cover ring-1 ring-border"
      onError={() => setFailed(true)}
    />
  )
}

export function AdminUsersPage() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const [q, setQ] = React.useState('')
  const [debounced, setDebounced] = React.useState('')
  const [page, setPage] = React.useState(1)
  const [creating, setCreating] = React.useState(false)
  const [form, setForm] = React.useState({ username: '', email: '', displayName: '', password: '', isAdmin: false })
  // 建号时的密码长度提示跟随服务端策略，不写死 8 位。
  const passwordReqs = usePasswordPolicy()

  React.useEffect(() => {
    const t0 = setTimeout(() => setDebounced(q), 300)
    return () => clearTimeout(t0)
  }, [q])

  const { data, isError, refetch } = useQuery({
    queryKey: ['admin', 'users', debounced, page],
    queryFn: () => api.adminUsers<{ items: UserRow[]; total: number }>(debounced, page, 20),
  })
  const items: any[] = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / 20))

  // 删除/降级后总数可能变小，当前页会越界（列表空白、只剩「上一页」）。
  // 后端不夹取页码，这里在前端把页码拉回最后一页。
  React.useEffect(() => {
    if (page > totalPages) setPage(totalPages)
  }, [page, totalPages])

  const toggleAdmin = useMutation({
    mutationFn: (u: any) => api.adminUpdateUser(u.id, { isAdmin: !u.isAdmin }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'dashboard'] })
      toast({ type: 'success', title: t('admin.users.roleUpdated') })
    },
    // 此前缺 onError：管理员对自己点「取消管理员」时后端返回
    // admin.self_demote，界面毫无反应也不知道原因。
    onError: (e) => toast({
      type: 'error',
      title: t('admin.users.roleUpdateFail'),
      description: e instanceof ApiError ? e.message : '',
    }),
  })
  const delUser = useMutation({
    mutationFn: (id: number) => api.adminDeleteUser(id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'dashboard'] })
      toast({ type: 'success', title: t('admin.users.deleted') })
    },
    onError: (e) => toast({ type: 'error', title: t('admin.users.deleteFail'), description: e instanceof ApiError ? e.message : '' }),
  })
  const createUser = useMutation({
    mutationFn: () => {
      if (!USERNAME_RE.test(form.username.trim())) {
        throw new ApiError(t('admin.users.usernameInvalid'), { status: 0, code: 'username.invalid' })
      }
      return api.adminCreateUser({ ...form, username: form.username.trim() })
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'dashboard'] })
      setCreating(false)
      setForm({ username: '', email: '', displayName: '', password: '', isAdmin: false })
      // 列表按 created_at DESC 排序，新用户在第一页；
      // 停在第 3 页新建会「看起来没创建成功」，故回到第一页。
      setPage(1)
      toast({ type: 'success', title: t('admin.users.created') })
    },
    onError: (e) => toast({ type: 'error', title: t('admin.users.createFail'), description: e instanceof ApiError ? e.message : '' }),
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold">{t('admin.users.title')}</h1>
        </div>
        <Button onClick={() => setCreating(!creating)}>
          <UserPlus className="size-4" /> {t('admin.users.new')}
        </Button>
      </div>

      {creating && (
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.users.newTitle')}</CardTitle>
            <CardDescription>{t('admin.users.newDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="max-w-lg space-y-4">
            <div className="space-y-1.5">
              <Label>{t('admin.users.username')}</Label>
              <Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder={t('admin.users.usernamePlaceholder')} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.users.email')}</Label>
              <Input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder={t('admin.users.emailPlaceholder')} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.users.displayName')}</Label>
              <Input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} placeholder={t('admin.users.displayNamePlaceholder')} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.users.password')}</Label>
              <Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder={t('admin.users.passwordPlaceholder', { min: passwordReqs.minimumLength })} />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={form.isAdmin} onChange={(e) => setForm({ ...form, isAdmin: e.target.checked })} className="rounded border-input" />
              {t('admin.users.setAdmin')}
            </label>
            <div className="flex justify-end gap-2">
              <Button onClick={() => createUser.mutate()} disabled={createUser.isPending || !form.username.trim() || !form.password}>{t('common.create')}</Button>
              <Button variant="outline" onClick={() => setCreating(false)}>{t('common.cancel')}</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <CardTitle className="break-words">{t('admin.users.listTitle')}</CardTitle>
              <CardDescription>{t('admin.users.total', { count: total })}</CardDescription>
            </div>
            <div className="relative w-full sm:w-64 sm:shrink-0">
              <Search className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} placeholder={t('admin.users.searchPlaceholder')} className="pl-8" />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.users.user')}</TableHead>
                <TableHead>{t('admin.users.email')}</TableHead>
                <TableHead>{t('admin.users.role')}</TableHead>
                <TableHead>{t('admin.users.registeredAt')}</TableHead>
                <TableHead className="text-right">{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((u: any) => (
                <TableRow key={u.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {/* 已上传头像时显示真实头像，加载失败或无头像回退首字母圆块 */}
                      <UserAvatar user={u} />
                      <div>
                        <div className="text-sm font-medium">{u.displayName || u.username}</div>
                        <div className="text-xs text-muted-foreground">@{u.username}</div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm">{u.email || '—'}</TableCell>
                  <TableCell>
                    {u.isAdmin
                      ? <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary"><ShieldCheck className="size-3" /> {t('admin.users.admin')}</span>
                      : <span className="text-xs text-muted-foreground">{t('admin.users.normal')}</span>}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(u.createdAt, lang)}</TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        title={u.isAdmin ? t('admin.users.role') : t('admin.users.setAdmin')}
                        disabled={toggleAdmin.isPending || delUser.isPending}
                        onClick={async () => {
                          const ok = await confirm({
                            title: u.isAdmin ? t('admin.users.demoteConfirm', { name: u.username }) : t('admin.users.promoteConfirm', { name: u.username }),
                            confirmText: t('common.confirm'),
                          })
                          if (ok) toggleAdmin.mutate(u)
                        }}
                      >
                        {u.isAdmin ? <ShieldOff className="size-4" /> : <ShieldCheck className="size-4" />}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        title={t('common.delete')}
                        className="text-destructive hover:text-destructive"
                        disabled={toggleAdmin.isPending || delUser.isPending}
                        onClick={async () => {
                          const ok = await confirm({
                            title: t('admin.users.deleteConfirm', { name: u.username }),
                            confirmText: t('common.delete'),
                            variant: 'destructive',
                          })
                          if (ok) delUser.mutate(u.id)
                        }}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {isError && (
                <TableRow><TableCell colSpan={5} className="py-10 text-center">
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
                <TableRow><TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">{t('admin.users.empty')}</TableCell></TableRow>
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
    </div>
  )
}
