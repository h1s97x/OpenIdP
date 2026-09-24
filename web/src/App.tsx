import { Routes, Route, useLocation, Navigate } from 'react-router-dom'
import * as React from 'react'
import { LoginPage } from './pages/LoginPage'
import { SetupPage } from './pages/SetupPage'
import { SignupPage } from './pages/SignupPage'
import { ForgotPasswordPage } from './pages/ForgotPasswordPage'
import { VerifyEmailPage } from './pages/VerifyEmailPage'
import { OAuthConsentPage } from './pages/OAuthConsentPage'
import { AppShell } from './components/layout/AppShell'
import { SessionProvider } from './hooks/useSession'
import { ThemeProvider } from './hooks/useTheme'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from './components/ui/toast'
import { ConfirmProvider } from './components/ui/confirm'
import { AppsPage } from './pages/AppsPage'
import { ProfilePage } from './pages/ProfilePage'
import { SecurityPage } from './pages/SecurityPage'
import { SessionsPage } from './pages/SessionsPage'
import { EventsPage } from './pages/EventsPage'
import { AdminRoute } from './pages/admin/AdminRoute'
import { AdminUsersPage } from './pages/admin/AdminUsersPage'
import { AdminAuditPage } from './pages/admin/AdminAuditPage'
import { AdminSettingsPage } from './pages/admin/AdminSettingsPage'
import { SetupProvider, useSetup, BootSplash } from './hooks/useSetup'
import { useSession } from './hooks/useSession'
import { useI18n } from './i18n'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 1, refetchOnWindowFocus: false } },
})

// 图表页（总览 / 管理仪表盘）按需加载：图表库体积占整个产物近四成，
// 首屏（登录页）用不到，拆出去后登录路径不再下载这部分代码。
const OverviewPage = React.lazy(() => import('./pages/OverviewPage').then((m) => ({ default: m.OverviewPage })))
const AdminDashboardPage = React.lazy(() =>
  import('./pages/admin/AdminDashboardPage').then((m) => ({ default: m.AdminDashboardPage })),
)

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <SetupProvider>
          <SessionProvider>
            <ToastProvider>
              <ConfirmProvider>
                <SetupGuard>
                  <Routes>
                    <Route path="/setup" element={<SetupPage />} />
                    <Route path="/oauth/consent" element={<OAuthConsentPage />} />
                    {/* 登录入口统一为 /sign-in；/ 作为站点首页 */}
                    <Route path="/sign-in" element={<LoginPage />} />
                    <Route path="/login" element={<Navigate to="/sign-in" replace />} />
                    <Route path="/signup" element={<SignupPage />} />
                    <Route path="/forgot-password" element={<ForgotPasswordPage />} />
                    {/* 邮箱验证结果页：邮件链接直达，未登录也要能打开（页内再引导登录后回跳），
                        因此不挂在 RequireAuth 下。 */}
                    <Route path="/verify-email" element={<VerifyEmailPage />} />
                    {/* 登录后区域：未登录统一引导到 /sign-in，避免先渲染外壳再跳转造成闪烁 */}
                    <Route element={<RequireAuth><AppShell /></RequireAuth>}>
                      {/* 首页：登录后即个人总览 */}
                      <Route
                        path="/"
                        element={
                          <React.Suspense fallback={<Loading />}>
                            <OverviewPage />
                          </React.Suspense>
                        }
                      />
                      <Route
                        path="/overview"
                        element={
                          <React.Suspense fallback={<Loading />}>
                            <OverviewPage />
                          </React.Suspense>
                        }
                      />
                      <Route path="/apps" element={<AppsPage />} />
                      <Route path="/settings" element={<ProfilePage />} />
                      <Route path="/settings/account" element={<SecurityPage />} />
                      {/* 通知偏好已并入「个人资料」的偏好小节：旧地址保留重定向，
                          避免收藏/外链失效（与 /admin/apps 的处理一致）。 */}
                      <Route path="/settings/notifications" element={<Navigate to="/settings" replace />} />
                      {/* 外观设置没有独立页面：顶栏调色板唤起的 AppearanceDrawer 是其超集
                          （主题 / 侧栏样式 / 布局 / 字体 / 重置），
                          旧的 /settings/appearance 页面无任何入口，已移除。 */}
                      <Route path="/settings/appearance" element={<Navigate to="/settings" replace />} />
                      <Route path="/sessions" element={<SessionsPage />} />
                      <Route path="/events" element={<EventsPage />} />

                      {/* Admin console (仅管理员) */}
                      <Route
                        path="/admin"
                        element={
                          <AdminRoute>
                            <React.Suspense fallback={<Loading />}>
                              <AdminDashboardPage />
                            </React.Suspense>
                          </AdminRoute>
                        }
                      />
                      <Route path="/admin/users" element={<AdminRoute><AdminUsersPage /></AdminRoute>} />
                      <Route path="/admin/audit" element={<AdminRoute><AdminAuditPage /></AdminRoute>} />
                      {/* 应用管理已并入系统设置、授权记录已并入审计日志：
                          旧地址保留重定向，避免收藏/外链失效。 */}
                      <Route path="/admin/apps" element={<Navigate to="/admin/settings?section=apps" replace />} />
                      <Route path="/admin/grants" element={<Navigate to="/admin/audit?tab=grants" replace />} />
                      <Route path="/admin/settings" element={<AdminRoute><AdminSettingsPage /></AdminRoute>} />
                      <Route path="/admin/settings/*" element={<AdminRoute><AdminSettingsPage /></AdminRoute>} />
                    </Route>
                  </Routes>
                </SetupGuard>
              </ConfirmProvider>
            </ToastProvider>
          </SessionProvider>
        </SetupProvider>
      </ThemeProvider>
    </QueryClientProvider>
  )
}

// Loading 是按需加载页面的统一占位，避免图表库下载期间出现空白路由出口。
function Loading() {
  const { t } = useI18n()
  return (
    <div className="flex min-h-[40vh] items-center justify-center gap-2 text-sm text-muted-foreground">
      <span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
      {t('common.loading')}
    </div>
  )
}

// RequireAuth 是登录区域的统一守卫：会话探测期间保持稳定的加载占位，
// 未登录时直接导向 /sign-in（带上来源路径，登录后便于回跳）。
function RequireAuth({ children }: { children: React.ReactNode }) {
  const { session, isLoading } = useSession()
  const location = useLocation()
  if (isLoading) return <BootSplash />
  if (!session) return <Navigate to="/sign-in" replace state={{ from: location.pathname + location.search }} />
  return <>{children}</>
}

// SetupGuard 在系统尚未初始化（无任何用户）时，将除 /setup 外的所有页面重定向到初始化页。
// 状态来自 SetupProvider（全 app 只探测一次），SetupPage 初始化成功后会调用
// markInitialized() 立即放行，因此不会再出现「跳到首页又被拉回 /setup」的循环闪烁。
function SetupGuard({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const { checked, needsSetup } = useSetup()

  // 探测未完成时保持稳定的加载占位（此前返回 null 会造成白屏 → 内容的闪烁）
  if (!checked) return <BootSplash />

  // 未初始化且不在初始化页 → 强制跳转到 /setup
  if (needsSetup && location.pathname !== '/setup') {
    return <Navigate to="/setup" replace />
  }
  return <>{children}</>
}
