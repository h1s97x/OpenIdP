import * as React from 'react'
import { Navigate } from 'react-router-dom'
import { useSession } from '../../hooks/useSession'
import { useI18n } from '../../i18n'
import { ShieldAlert } from 'lucide-react'

// AdminRoute guards admin pages: requires a logged-in admin.
export function AdminRoute({ children }: { children: React.ReactNode }) {
  const { session, isLoading, capabilities } = useSession()
  const { t } = useI18n()

  if (isLoading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="text-sm text-muted-foreground">{t('adminRoute.loading')}</div>
      </div>
    )
  }
  if (!session) return <Navigate to="/sign-in" replace />
  if (!session.user.isAdmin) {
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
          <ShieldAlert className="size-6 text-muted-foreground" />
        </div>
        <div>
          <div className="text-sm font-medium">{t('adminRoute.denied')}</div>
          <div className="mt-1 text-sm text-muted-foreground">{t('adminRoute.deniedDesc')}</div>
        </div>
      </div>
    )
  }
  // 说明：这里曾有一条 `capabilities.admin.dashboard` 的细粒度守卫，但实际是死代码——
  // 非管理员已在上面 return，管理员该位恒为 true；而 capabilities 查询 retry:false，
  // 一旦失败就恒为 undefined，短路条件反而直接放行。
  //
  // 分区级授权若将来要做，应由后端下发完整的 capabilities.admin.*，
  // 前端据此过滤侧栏与分区，而不是靠单个布尔位。当前阶段删除该死分支，
  // 权限判定统一依赖后端每个 admin 接口的 requireAdmin。
  return <>{children}</>
}
