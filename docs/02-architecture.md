# 02 · 整体架构

## 1. 部署形态与进程视图

OpenIdP 是**单进程单端口**架构：一个 Go 二进制同时承载 API、OIDC 端点、静态前端。

```
                        ┌────────────────────────────────────────────┐
   Browser ──HTTPS──▶   │  Go HTTP Server  (:6099)                   │
   (用户)               │                                            │
                        │  rootHandler (cmd/server/main.go)          │
                        │   ├─ /api/*  /.well-known/*  /login/oauth/* │
                        │   │      └─▶ chi Router (handler.Router)    │
                        │   └─ 其它路径 ⇢ 内嵌 SPA (embed dist)       │
                        └──────────┬───────────────────┬─────────────┘
                                   │                   │
                        ┌──────────▼────────┐  ┌───────▼──────────┐
                        │  DB (bun)         │  │  Cache (可选)     │
                        │  SQLite/PG/MySQL  │  │  Redis ⇄ 内存     │
                        └───────────────────┘  └──────────────────┘
                                   │
                   ┌───────────────┼─────────────────┬──────────────┐
                   │               │                 │              │
              SMTP 邮件        短信服务商        对象存储        外部 Webhook
             (net/smtp)      (7 家内置)      (本地/S3)      (HMAC 签名)
```

外部依赖**全部可选**：未配置时对应能力自动降级或关闭，服务照常启动。

### 关键分派逻辑

`cmd/server/main.go` 的 `rootHandler` 决定请求归谁：

```go
// API & OIDC 路径 → chi 路由（并强制 no-store）
if p == "/api" || strings.HasPrefix(p, "/api/") ||
   p == "/.well-known" || strings.HasPrefix(p, "/.well-known/") ||
   p == "/login/oauth" || strings.HasPrefix(p, "/login/oauth/") {
    apiNoStore(w)
    api.ServeHTTP(w, r)
    return
}
// 其余 → 内嵌 SPA（真实文件命中则直出，否则 index.html fallback）
secure(http.HandlerFunc(...serveSPA...)).ServeHTTP(w, r)
```

开发模式下设置 `OPENIDP_DEV_FRONTEND_URL=http://localhost:5173`，
`serveSPA` 会走 `httputil.ReverseProxy` 把所有非 API 请求转发给 Vite dev server（保留 HMR）。
**开发与生产的入口行为一致（都是 :6099）**，避免"本地能跑线上白屏"。

### HTTP Server 超时（防 Slowloris）

```go
ReadHeaderTimeout: 10 * time.Second   // 慢速发头
ReadTimeout:       5 * time.Minute    // 需容纳 10MB 附件在慢网下的上传
WriteTimeout:      5 * time.Minute    // 邮件发送 / 令牌签发的窗口
IdleTimeout:       2 * time.Minute    // keep-alive 空闲回收
MaxHeaderBytes:    64 << 10           // 默认 1MB 偏大，可被用来放大内存
```

## 2. 后端分层

```
cmd/server/main.go                    ← 进程编排：初始化顺序 + 优雅退出
      │
      ├─ internal/config              ← 环境变量 → Config 结构
      ├─ internal/timezone            ← 全局时区（必须最早，影响日志与日界）
      ├─ internal/logging                ← 文件日志 + Access/Audit/Config 分类日志
      ├─ internal/appcrypto              ← AES-256-GCM 应用层加密
      ├─ internal/db                  ← 连接、迁移、索引、存量数据回填
      ├─ internal/seed                ← 内置数据（提供商端点、默认安全策略）
      ├─ internal/oidc                ← RSA 密钥 + JWKS + ID Token 签发
      ├─ internal/cache               ← Redis / 内存 + 熔断降级
      └─ internal/handler             ← ★ 全部 HTTP 处理（Handler 聚合所有依赖）
            ├─ router.go              ← 路由注册（含中间件顺序）
            ├─ session.go             ← Handler 构造 + 会话/登录核心
            ├─ oidc*.go               ← OIDC 协议端点
            ├─ me*.go                 ← 用户自助端点
            ├─ admin*.go              ← 管理后台端点
            ├─ provider_sso.go        ← 第三方登录
            ├─ passkey_login.go       ← 通行密钥
            ├─ device_auth.go         ← 设备码流
            ├─ files.go               ← 文件上传/读取
            └─ ...

被 handler 依赖的领域包（无 HTTP 概念，可单独测试）：
      auth · password/bcrypt · mfa(TOTP) · passkey · captcha · sms · mail
      storage · geo · stats · sysinfo · event · webhook · task · middleware
      oauth2 · proxyutil · secret · version · timezone · logx · cache · db · models
```

### 依赖方向

```
        ┌──────────────────────────────────────────────┐
        │  handler  (HTTP 编排层)                       │
        └───────┬──────────────────────────────────────┘
                │ 依赖（单向）
   ┌────────────▼────────────────────────────────────────┐
   │ 领域包：auth mfa passkey captcha sms mail storage    │
   │        geo stats sysinfo oauth2 event webhook task   │
   └────────────┬────────────────────────────────────────┘
                │
   ┌────────────▼────────────────────────────────────────┐
   │ 基础设施：db models cache secret logx timezone       │
   │          config middleware version                  │
   └─────────────────────────────────────────────────────┘
```

规则：**下层不认识上层**。领域包不 import `handler`；`models` 不 import 任何业务包。
唯一例外是 `middleware` 被 `handler` 与 `cmd/server` 共用（依赖 `cache`、`logx`）。

## 3. 启动顺序（顺序即依赖）

`cmd/server/main.go` 的 `main()` 严格按下列顺序执行，**改动顺序前请先看注释的原因说明**：

| # | 步骤 | 失败行为 | 为什么必须在这个位置 |
|---|------|---------|-------------------|
| 1 | `config.FromEnv()` | - | 一切配置来源 |
| 2 | `timezone.Apply()` | **exit(1)** | 必须在日志初始化前，否则日志时间戳与统计日界全错 |
| 3 | `logging.Init()` | 降级仅 stderr | 后续所有初始化日志要能落盘，但不能因日志失败阻断启动 |
| 4 | `appcrypto.Init()` | **Fatal** | 加密密钥必须先就绪，否则敏感字段无法解密 |
| 5 | `db.Open()` | Fatal / 可降级 | 未配置走 SQLite；PG/MySQL 连不上默认 fail-fast |
| 6 | `cache.New()` | 自动降级内存 | 支撑 TokenStore / 限流 / consent / passkey 仪式 |
| 7 | `db.Migrate()` | Fatal | 建表 + 索引 + 存量数据回填 |
| 8 | `seed.Run()` | Fatal | 内置提供商端点、默认安全策略 |
| 9 | `oidc.NewProvider()` | Fatal | 加载/生成 RSA 私钥 |
| 10 | `handler.New()` | - | 聚合全部依赖，初始化限流器与存储 Provider |
| 11 | `scheduler.Scheduler` 注册周期任务 | - | **必须在 Migrate 之后**，否则首次启动打到不存在的表 |
| 12 | `h.InitPasskeys()` / `h.InitStorage()` | - | 依赖 handler 已构造 |
| 13 | `h.Router()` → `http.Server` | - | 挂载路由并监听 |
| 14 | 等待 `SIGINT/SIGTERM` → `srv.Shutdown(5s)` | - | 优雅退出 |

### 周期任务清单

```go
sched.Every("cleanup-expired",     1h,  db.CleanupExpired)   // 过期会话/令牌/验证码/授权码
sched.Every("audit-archive",       24h, db.ArchiveEvents)    // 审计日志归档为 JSONL
sched.Every("file-orphan-cleanup", 24h, h.CleanupOrphanFiles) // 孤儿文件回收（宽限期 7 天）
```

调度器实现见 `internal/scheduler/scheduler.go`：每任务独立定时器，`Start(ctx)` 返回 `stop()`，任务 panic 不影响调度器。

## 4. 请求生命周期（以受保护的 API 为例）

```
① SecurityHeaders / Recover / WithRequestID   (router.go 的 r.Use 顺序)
② withClientIP      → 解析可信客户端 IP + 归属地缓存注入 context
③ CORS
④ BodyLimit         → 限制请求体大小（含 multipart）
⑤ AccessLog         → 记录访问日志（放在外层，被拒的请求也要留痕）
⑥ RateLimit         → 按端点分组限流（login/code/oauth/admin/upload/...）
⑦ CSRF              → 校验 X-OpenIdP-CSRF 与 Cookie 会话绑定
⑧ 业务 handler：
     currentUser()  → 用 Cookie 原始值取 SHA-256 摘要查 sessions 表
     loadSecurityPolicy() / loadSiteSetting()  → 5s TTL 进程内配置缓存
     业务逻辑 → db / cache / mail / webhook
⑨ writeJSON / ok / fail   → 统一响应封装（response.go）
⑩ logEvent + audit        → 事件落库 + 事件总线发布 + 分类日志
```

注意 `Recover` 放在**最外层**：任何中间件或 handler 的 panic 都要转成可解析的 500 并落盘堆栈。

## 5. 横切机制

### 5.1 配置缓存（避免每请求查库）

`handler/config_cache.go` + `consent_cache.go`：站点设置 / 安全策略 / 邮件 / 短信 / 人机验证
等单行配置在进程内做 **5 秒 TTL 缓存**；管理后台写操作后主动失效（`conf.Invalidate()`）。
读取入口：`loadSiteSetting()`、`loadSecurityPolicy()`、`loadMailSetting()`、`loadSmsSetting()`、
`loadCaptchaSetting()`、`loadStorageSetting()`、`loadLocationSetting()`、`loadAuditSetting()`。

### 5.2 事件总线（解耦副作用）

`internal/event/event.go`：进程内 pub/sub，支持 `"security.*"` 前缀通配。

- 发布点：`Handler.logEvent()`（所有安全事件统一从这里发出）
- 事件类型：`security.<event.Type>`，如 `security.login.success`、`security.password.changed`
- 消费方：`internal/webhook`（签名投递到外部系统）
- 背压保护：有界队列 4096 + 64 个 worker；队列满则丢弃并计数（`dropped`），
  **绝不无限堆积**——大量失败登录会瞬间产生等量事件，无上限会演变成 goroutine/内存雪崩。

### 5.3 会话与 CSRF

- Cookie `openidp_session` 携带**原始会话 ID**；数据库只存 `sha256(id)`（`session_hash` 列）。
  库/备份泄露 ≠ 会话可被劫持。
- 登录成功后 `rotateSession()` 删除旧会话记录 → 防会话固定攻击。
- CSRF 令牌存在共享缓存（`middleware.TokenStore`），**绑定会话**且与会话同生命周期，
  通过 `X-OpenIdP-CSRF` 头提交。
- 设备标识 `openidp_device_id` 用于设备聚合与可信设备跳过 MFA。

详见 [09-security.md](./09-security.md)。

### 5.4 时区一致性

`internal/timezone` 是唯一时区来源：

- 默认 `Asia/Shanghai`，`OPENIDP_TIMEZONE` 可覆盖；非法时区名**直接终止启动**。
- `timezone.Now()`、`timezone.StartOfDay()`、`timezone.StartOfNextDay()` 供统计日界使用。
- 前端启动时 `fetchSiteTimezone()` 拉取，所有时间展示与导出文件名按它渲染。

## 6. 前端架构

```
web/src/main.tsx
  └─ BrowserRouter
      └─ I18nProvider
          └─ App.tsx
              └─ QueryClientProvider → ThemeProvider → SetupProvider
                  └─ SessionProvider → ToastProvider → ConfirmProvider
                      └─ SetupGuard
                          ├─ 未初始化 → 强制 /setup
                          └─ Routes
                              ├─ 公开路由：/sign-in /signup /forgot-password /verify-email /oauth/consent
                              └─ RequireAuth → AppShell（侧栏 + 内容区）
                                   ├─ /overview /apps /settings /sessions /events
                                   └─ AdminRoute 保护：/admin /admin/users /admin/audit /admin/settings
```

- 会话状态由 `hooks/useSession.tsx`（react-query）统一持有，`/api/v1/session` 为唯一数据源。
- 首次访问探测由 `hooks/useSetup.tsx` 全 app 只做一次，避免重复请求导致的闪烁。
- 图表页 `OverviewPage` / `AdminDashboardPage` 用 `React.lazy` 懒加载：
  recharts 占产物近四成，登录首屏用不到。

详见 [07-frontend.md](./07-frontend.md)。
