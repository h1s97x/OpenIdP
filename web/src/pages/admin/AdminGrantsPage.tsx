import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
import { api, ApiError } from '../../lib/api'
import { useI18n } from '../../i18n'
import { useToast } from '../../components/ui/toast'
import { useConfirm } from '../../components/ui/confirm'
import { formatDateTimeI18n } from '../../lib/utils'
import { AppWindow, Trash2, User, Loader2, RefreshCw, AlertTriangle } from 'lucide-react'

interface GrantItem {
  id: string
  userId: number
  clientId: string
  createdAt: string
  // 后端 LEFT JOIN 补齐的展示字段；客户端已被删除时为空，回落到 clientId。
  clientName?: string
  clientLogo?: string
  username?: string
  displayName?: string
  email?: string
}

// 「授权记录」已并入审计日志，作为其中的一个页签渲染，因此不自带页面级标题。
export function GrantsSection() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { confirm } = useConfirm()
  const { toast } = useToast()
  const { data: grants, isPending, isError, refetch } = useQuery({
    queryKey: ['admin', 'grants'],
    queryFn: () => api.adminOAuthGrants<GrantItem[]>(),
  })

  const revoke = useMutation({
    mutationFn: (id: string) => api.adminRevokeGrant(id),
    onSuccess: async () => {
      // await 刷新完成再提示，避免「提示已撤销但列表里还在」
      await qc.invalidateQueries({ queryKey: ['admin', 'grants'] })
      await qc.invalidateQueries({ queryKey: ['admin', 'dashboard'] })
      toast({ type: 'success', title: t('admin.grants.revoked') })
    },
    // 此前缺 onError：请求失败（403/404/CSRF 失效）时界面零反馈，
    // 管理员会误判为已撤销。
    onError: (err: any) => toast({
      type: 'error',
      title: t('admin.grants.revokeFailed'),
      description: err instanceof ApiError ? err.message : (err?.message ?? ''),
    }),
  })

  // 撤销会让用户侧的授权立即失效，属不可逆操作，必须二次确认。
  const handleRevoke = (id: string) => {
    confirm({
      title: t('admin.grants.revokeConfirmTitle'),
      description: t('admin.grants.revokeConfirmDesc'),
      confirmText: t('common.revoke'),
      variant: 'destructive',
      onConfirm: async () => {
        await revoke.mutateAsync(id)
      },
    })
  }

  const items: GrantItem[] = grants ?? []

  // 存量授权行的 created_at 可能为零值（历史写入时未赋值），此时显示「—」
  // 而不是 0001-01-01 这种明显错误的时间。
  const isZeroDate = (v?: string) => !v || v.startsWith('0001-01-01')

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.grants.listTitle')}</CardTitle>
        <CardDescription>{t('admin.grants.count', { count: items.length })}</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('admin.grants.app')}</TableHead>
              <TableHead>{t('admin.grants.user')}</TableHead>
              <TableHead>{t('admin.grants.grantedAt')}</TableHead>
              <TableHead className="text-right">{t('common.actions')}</TableHead>
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
            {items.map((g) => (
              <TableRow key={g.id}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    {g.clientLogo
                      ? <img src={g.clientLogo} alt="" className="h-7 w-7 rounded" />
                      : <span className="flex h-7 w-7 items-center justify-center rounded bg-muted"><AppWindow className="size-4 text-muted-foreground" /></span>}
                    <span className="text-sm font-medium">{g.clientName || g.clientId}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted">
                      <User className="size-3.5 text-muted-foreground" />
                    </span>
                    <div className="min-w-0">
                      <div className="truncate text-sm">{g.displayName || g.username || t('admin.grants.unknownUser')}</div>
                      <div className="truncate text-xs text-muted-foreground">{g.email || g.username}</div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {isZeroDate(g.createdAt) ? '—' : formatDateTimeI18n(g.createdAt, lang)}
                </TableCell>
                <TableCell>
                  <div className="flex justify-end">
                    {/* 行级 loading：只禁用当前行，其余行仍可操作 */}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:text-destructive"
                      disabled={revoke.isPending && revoke.variables === g.id}
                      onClick={() => handleRevoke(g.id)}
                    >
                      {(revoke.isPending && revoke.variables === g.id)
                        ? <Loader2 className="size-4 animate-spin" />
                        : <Trash2 className="size-4" />}
                      {t('common.revoke')}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
            {!isPending && !isError && items.length === 0 && (
              <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">{t('admin.grants.empty')}</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
