package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/version"
)

// Router assembles all API and OIDC routes.
func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()
	// 兜底 panic 恢复放在最外层：任何中间件或 handler 的 panic 都要转成
	// 可解析的 500 响应并落盘堆栈，而不是让连接被标准库直接断开。
	r.Use(middleware.Recover)
	r.Use(middleware.WithRequestID)
	r.Use(middleware.SecurityHeaders(strings.HasPrefix(strings.ToLower(h.cfg.SiteURL), "https://"), h.cfg.CDNBaseURL))
	r.Use(h.withClientIP)
	r.Use(middleware.CORS(h.cfg.CORSAllowedOrigins))
	// 统一请求体大小上限：所有 handler 都直接解码 r.Body，缺少上限时
	// 恶意客户端可以发送超大请求体打爆内存。
	r.Use(middleware.BodyLimit)
	// 访问日志放在最外层：这样即使请求被后面的中间件（限流、CSRF、鉴权）拒绝，
	// 也能留下访问痕迹——被拒绝的请求往往正是排障最关心的。
	r.Use(middleware.AccessLog(middleware.AccessLogConfig{
		Enabled:    h.cfg.AccessLogEnabled,
		SkipHealth: h.cfg.AccessLogSkipHealth,
	}))

	// health
	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	// version
	r.Get("/api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, version.Get())
	})

	// ---- OIDC / OAuth ----
	r.Get("/.well-known/openid-configuration", h.HandleDiscovery)
	r.Get("/.well-known/jwks", h.HandleJWKS)
	r.Get("/login/oauth/authorize", h.HandleAuthorize)
	r.With(middleware.RateLimit(h.oauthLimiter, clientIP)).Post("/api/login/oauth/access_token", h.HandleToken)
	r.Get("/api/userinfo", h.HandleUserInfo)
	r.With(middleware.RateLimit(h.oauthLimiter, clientIP)).Post("/api/login/oauth/device_authorization", h.HandleDeviceAuthorization)
	r.With(middleware.RateLimit(h.oauthLimiter, clientIP)).Post("/api/login/oauth/introspect", h.HandleIntrospect)
	r.With(middleware.RateLimit(h.oauthLimiter, clientIP)).Post("/api/login/oauth/revoke", h.HandleRevoke)
	r.Get("/api/logout", h.HandleLogout)

	// ---- 首次部署初始化（公开，免 CSRF；未初始化时才可用）----
	// 初始化端点同样需要限流，避免被反复调用抢占管理员账号创建。
	r.Get("/api/v1/setup/status", h.handleSetupStatus)
	r.With(middleware.RateLimit(h.setupLimiter, clientIP)).Post("/api/v1/setup", h.handleSetup)

	// ---- public auth endpoints (no CSRF) ----
	// 登录/验证码等公开端点加内存限流，防止无验证码配置时的暴力破解/枚举。
	r.With(middleware.RateLimit(h.loginLimiter, clientIP)).Post("/api/v1/session/login", h.handleSessionLogin)
	r.Get("/api/v1/login-policy", h.handleLoginPolicy)
	r.Get("/api/v1/site", h.handleGetSite)
	r.Get("/api/v1/login/providers", h.handleLoginProviders)
	r.Get("/api/v1/oauth/consent", h.HandleConsentInfo)
	r.Get("/api/v1/session/ip", h.handleClientIP)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/session/email-code/request", h.handleEmailCodeRequest)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/session/email-code/verify", h.handleEmailCodeVerify)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/session/mfa/verify", h.handleSessionMFAVerify)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/session/passkey/begin", h.handlePasskeyBegin)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/session/passkey/finish", h.handlePasskeyFinish)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/signup/email-code/request", h.handleSignupEmailCodeRequest)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/signup", h.handleSignup)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/password-reset/request", h.handlePasswordResetRequest)
	r.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/api/v1/password-reset/confirm", h.handlePasswordResetConfirm)

	// ---- 第三方登录 OAuth（免 CSRF）----
	// 登录与绑定统一使用同一个回调路径 /api/oauth/callback/{type}（基于访问域名动态拼接），
	// 通过 state 前缀区分登录/绑定流程，三方平台只需登记一个回调地址。
	r.Get("/api/oauth/callback/{type}", h.handleProviderCallback)
	// 发起第三方授权（前端内部跳转，非三方回调）
	r.Get("/api/login/provider/{type}/authorize", h.handleProviderAuthorize)
	// 已登录用户绑定第三方（前端整页跳转，GET + 会话 Cookie 校验，免 CSRF）
	r.Get("/api/v1/login/provider/{type}/bind", h.handleProviderBind)

	// ---- 邮箱验证（免 CSRF）----
	// 邮件链接指向前端 /verify-email 页面，由页面以 JSON 提交 token 完成验证；
	// 端点免 CSRF 是因为用户常从邮件直接打开、此时可能未登录，需要返回 401
	// 让页面引导登录；安全性由「登录态 + 一次性 token 归属校验」共同保证。
	r.With(middleware.RateLimit(h.loginLimiter, clientIP)).
		Post("/api/v1/me/email/verify", h.handleEmailVerify)

	// ---- 文件读取（免 CSRF；头像等公开用途免鉴权直出）----
	// 放在 CSRF 组外：浏览器 <img> 直连不带自定义头，带 CSRF 会导致头像 403。
	r.With(middleware.RateLimit(h.fileLimiter, clientIP)).
		Get("/api/v1/files/{publicId}", h.handleFileGet)

	// ---- CSRF-protected API ----
	r.Group(func(pr chi.Router) {
		pr.Use(middleware.CSRF(h.cfg.CSRFHeader, h.tokens, h.cfg.SessionCookieName))
		pr.Route("/api/v1", func(api chi.Router) {
			// OAuth 授权确认（consent）提交（同意/拒绝）
			api.Post("/oauth/consent", h.HandleConsentAction)
			// 设备授权流（RFC 8628）：用户在门户确认/拒绝设备上展示的 user_code
			api.Get("/oauth/device-authorizations", h.handleDeviceAuthList)
			api.Post("/oauth/device-authorizations", h.handleDeviceAuthVerify)
			api.Get("/oauth/device-authorizations/{id}", h.handleDeviceAuthGet)
			api.Post("/oauth/device-authorizations/{id}", h.handleDeviceAuthDecide)

			api.Get("/session", h.handleGetSession)
			api.Delete("/session", h.handleLogout)
			api.Get("/capabilities", h.handleCapabilities)

			// me endpoints
			api.Get("/me/profile", h.handleGetProfile)
			api.Patch("/me/profile", h.handlePatchProfile)
			api.Post("/me/password", h.handleChangePassword)
			api.Post("/me/email/verify/send", h.handleEmailVerifySend)
			// 向待绑定的「新邮箱」发送验证码（添加/更换邮箱一步式验证）
			api.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/me/email/code", h.handleSendNewEmailCode)
			api.Post("/me/email", h.handleChangeEmail)
			// 手机号验证：发送/校验验证码 + 保存（未验证）手机号
			api.With(middleware.RateLimit(h.codeLimiter, clientIP)).Post("/me/phone/send-code", h.handleSendPhoneCode)
			api.Post("/me/phone/verify", h.handleVerifyPhone)
			api.Patch("/me/phone", h.handlePatchPhone)
			// 头像上传加限流：该端点会写磁盘/对象存储，无限流时可被刷爆存储配额。
			// 与附件上传分开计数：两处配额互不影响。
			api.With(middleware.RateLimit(h.avatarLimiter, clientIP)).Post("/me/avatar", h.handleAvatarUpload)
			api.Post("/me/avatar/reset", h.handleAvatarReset)
			// 通用文件上传（工单附件等）
			api.With(middleware.RateLimit(h.uploadLimiter, clientIP)).Post("/files", h.handleFileUpload)
			api.Get("/me/dashboard", h.handleDashboard)
			// counts 先注册，避免将来 /me/events 下新增参数路由时遮蔽它
			api.Get("/me/events/counts", h.handleEventCounts)
			api.Get("/me/events", h.handleEvents)
			api.Get("/me/sessions", h.handleSessions)
			api.Delete("/me/sessions", h.handleDeleteOtherSessions)
			api.Delete("/me/sessions/{id}", h.handleDeleteSession)
			api.Get("/me/devices", h.handleDevices)
			api.Get("/me/grants", h.handleGrants)
			api.Delete("/me/grants/{id}", h.handleRevokeGrant)
			api.Get("/me/trusted-devices", h.handleTrustedDevices)
			api.Post("/me/trusted-devices", h.handleAddTrustedDevice)
			api.Delete("/me/trusted-devices/{id}", h.handleDeleteTrustedDevice)
			api.Get("/me/identities", h.handleIdentitiesList)
			api.Delete("/me/identities/{id}", h.handleIdentityDelete)
			api.Get("/me/mfa", h.handleMFAGet)
			api.Get("/me/mfa/begin", h.handleMFABegin)
			api.Post("/me/mfa/confirm", h.handleMFAConfirm)
			api.Post("/me/mfa/disable", h.handleMFADisable)
			api.Post("/me/mfa/recovery-codes", h.handleMFARecoveryCodes)
			api.Get("/me/passkeys", h.handleMePasskeysList)
			api.Post("/me/passkeys/begin", h.handleMePasskeyBegin)
			api.Post("/me/passkeys/finish", h.handleMePasskeyFinish)
			api.Delete("/me/passkeys/{id}", h.handleMePasskeyDelete)
			api.Get("/me/export", h.handleExport)
			// 账号注销：申请 + 冷静期 + 管理员审核（见 handleRequestAccountDeletion）
			api.Get("/me/account-deletion", h.handleGetAccountDeletion)
			api.Post("/me/account-deletion", h.handleRequestAccountDeletion)
			api.Delete("/me/account-deletion", h.handleCancelAccountDeletion)
			api.Post("/me/account-deletion/email-code", h.handleSendDeletionEmailCode)
			// 敏感操作二次验证（step-up）：改邮箱等
			api.Post("/me/step-up", h.handleStepUp)
			// 重新验证身份：改密码/解绑等敏感操作的通用前置
			api.Post("/me/reauthenticate", h.handleReauthenticate)
			api.Post("/me/step-up/email-code", h.handleSendStepUpEmailCode)

			// notifications (个人通知中心)
			// 独立未读计数端点：前端轮询时无需拉取全量列表，显著省流量。
			api.Get("/me/notifications/unread-count", h.handleUnreadNotificationCount)
			api.Get("/me/notifications", h.handleListNotifications)
			api.Patch("/me/notifications/{id}", h.handleUpdateNotification)
			api.Post("/me/notifications/read-all", h.handleMarkAllNotificationsRead)
			api.Delete("/me/notifications", h.handleClearNotifications)

			// notification prefs
			api.Get("/me/notification-preferences", h.handleGetNotificationPrefs)
			api.Patch("/me/notification-preferences", h.handlePatchNotificationPrefs)

			// ---- admin console（管理员，默认拥有全部能力）----
			// 管理端点独立限流（叠加在全局 IP 限流之上），保护创建用户、
			// 修改邮件/安全策略、读取审计日志等高危操作。
			api.Group(func(ar chi.Router) {
				ar.Use(middleware.RateLimit(h.adminLimiter, clientIP))
				ar.Route("/admin", h.registerAdminRoutes)
			})
		})
	})

	return r
}

// registerAdminRoutes 注册管理后台的全部端点（挂载在 /admin 下）。
//
// 从 Router 中拆出：管理端点数量最多（60+ 条），与主流程路由混在一起时
// Router 长达 250 行，既难定位也容易在多人改动时冲突。这里按职责分段组织，
// 调用方（Router）负责叠加 adminLimiter 限流。
func (h *Handler) registerAdminRoutes(a chi.Router) {
	// 概览与统计
	a.Get("/dashboard", h.handleAdminDashboard)
	a.Get("/stats", h.handleAdminStats)

	// 用户管理
	a.Get("/users", h.handleAdminUsers)
	a.Post("/users", h.handleAdminCreateUser)
	a.Patch("/users/{id}", h.handleAdminUpdateUser)
	a.Delete("/users/{id}", h.handleAdminDeleteUser)

	// 审计与日志（单一端点：支持 q / type / endpoint / outcome / userId 过滤）
	a.Get("/audit-events", h.handleAdminAuditEvents)
	a.Get("/audit-stats", h.handleAdminAuditStats)
	a.Get("/audit-settings", h.handleAdminGetAuditSettings)
	a.Put("/audit-settings", h.handleAdminUpdateAuditSettings)

	// 分类数据清理策略
	a.Get("/data-cleanup", h.handleAdminGetDataCleanup)
	a.Get("/data-cleanup/usage", h.handleAdminGetDataCleanupUsage)
	a.Put("/data-cleanup", h.handleAdminUpdateDataCleanup)
	a.Post("/data-cleanup/run", h.handleAdminRunDataCleanup)

	// 数据备份：导出 ZIP（分组可选）/ 上传解析内容 / 用备份 ZIP 恢复
	a.Get("/backup/export", h.handleAdminBackupExport)
	a.Post("/backup/inspect", h.handleAdminBackupInspect)
	a.Post("/backup/restore", h.handleAdminBackupRestore)

	// 站点与安全策略
	a.Get("/site", h.handleAdminGetSite)
	a.Patch("/site", h.handleAdminUpdateSite)
	a.Get("/security-policy", h.handleAdminGetSecurityPolicy)
	a.Patch("/security-policy", h.handleAdminUpdateSecurityPolicy)

	// OAuth 应用 / 提供商 / 授权 / 权限项
	a.Get("/oauth-clients", h.handleAdminOAuthClients)
	a.Post("/oauth-clients", h.handleAdminCreateOAuthClient)
	a.Patch("/oauth-clients/{id}", h.handleAdminUpdateOAuthClient)
	a.Post("/oauth-clients/{id}/secret", h.handleAdminRotateOAuthClientSecret)
	a.Delete("/oauth-clients/{id}", h.handleAdminDeleteOAuthClient)
	a.Get("/oauth-providers", h.handleAdminOAuthProviders)
	a.Post("/oauth-providers", h.handleAdminCreateOAuthProvider)
	a.Patch("/oauth-providers/{id}", h.handleAdminUpdateOAuthProvider)
	// 按该提供商真实的出站配置（含「使用代理」）探测端点可达性，供排障使用。
	a.Post("/oauth-providers/{id}/test", h.handleAdminTestOAuthProvider)
	a.Delete("/oauth-providers/{id}", h.handleAdminDeleteOAuthProvider)
	a.Get("/oauth-grants", h.handleAdminOAuthGrants)
	// 管理员撤销任意用户的授权（普通用户端点只能撤销自己的，见 handleRevokeGrant）。
	a.Delete("/oauth-grants/{id}", h.handleAdminRevokeGrant)
	a.Get("/oauth-scopes", h.handleAdminOAuthScopes)
	a.Put("/oauth-scopes", h.handleAdminUpdateOAuthScope)
	a.Post("/oauth-scopes/{id}/enable", h.handleAdminEnableOAuthScope)
	a.Post("/oauth-scopes/{id}/disable", h.handleAdminDisableOAuthScope)

	// 注销账号申请审核
	a.Get("/account-deletion-requests", h.handleAdminListDeletionRequests)
	a.Post("/account-deletion-requests/{id}/approve", h.handleAdminApproveDeletionRequest)
	a.Post("/account-deletion-requests/{id}/reject", h.handleAdminRejectDeletionRequest)

	// 邮件服务（SMTP 配置 + 测试发送）
	a.Get("/mail", h.handleAdminMail)
	a.Patch("/mail", h.handleAdminUpdateMail)
	a.Post("/mail/test", h.handleAdminMailTest)

	// 人机验证
	a.Get("/captcha", h.handleAdminCaptcha)
	a.Patch("/captcha", h.handleAdminUpdateCaptcha)
	a.Post("/captcha/test", h.handleAdminCaptchaTest)

	// 短信验证码
	a.Get("/sms", h.handleAdminSms)
	a.Patch("/sms", h.handleAdminUpdateSms)
	a.Post("/sms/test", h.handleAdminSmsTest)

	// 存储管理：配置 + 文件记录 + 孤儿回收
	a.Get("/storage", h.handleAdminGetStorage)
	a.Put("/storage", h.handleAdminUpdateStorage)
	a.Post("/storage/test-and-save", h.handleAdminStorageTestAndSave)
	a.Get("/storage/stats", h.handleAdminStorageStats)
	a.Get("/files", h.handleAdminFiles)
	a.Delete("/files/{publicId}", h.handleAdminDeleteFile)
	a.Get("/files/orphans", h.handleAdminOrphanFiles)
	a.Post("/files/orphans/cleanup", h.handleAdminCleanupOrphans)

	// IP 归属地配置
	// 代理设置：仅对开启「使用代理」的登录提供商生效，不全局生效
	a.Get("/proxy", h.handleAdminGetProxy)
	a.Patch("/proxy", h.handleAdminUpdateProxy)
	a.Post("/proxy/test", h.handleAdminTestProxy)
	a.Get("/location", h.handleAdminGetLocation)
	a.Put("/location", h.handleAdminUpdateLocation)
	a.Post("/location/test", h.handleAdminTestLocation)

	// 系统健康面板
	a.Get("/system-status", h.handleAdminSystemStatus)

	// 定点通知（广播）
	a.Get("/notifications", h.handleAdminListNotifications)
	a.Get("/notification-presets", h.handleAdminNotificationPresets)
	a.Post("/notifications", h.handleAdminBroadcastNotification)
}
