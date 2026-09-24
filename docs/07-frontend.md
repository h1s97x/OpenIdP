# 07 · 前端结构

技术栈：React 18 + TypeScript 5 + Vite 6 + Tailwind CSS v4 + react-query 5 + react-router 7 + i18next。

## 1. 目录结构

```
web/
├── index.html               # 含 <!-- cdn:fonts --> 占位（构建期注入字体 CDN）
├── vite.config.ts           # 构建插件、manualChunks 分包策略
├── public/images/           # logo.svg / avatar.svg
└── src/
    ├── main.tsx             # 入口：字体偏好 + 时区预取 + 渲染
    ├── App.tsx              # 路由表 + 全局 Provider 嵌套
    ├── index.css
    ├── components/
    │   ├── ui/              # button/input/select/dialog/table/tabs/toast/confirm/field/pagination...
    │   ├── layout/          # AppShell / AuthLayout / UserMenu / NotificationCenter / SiteFooter
    │   ├── appearance/      # 外观抽屉：主题 / 侧栏样式 / 布局 / 字体
    │   └── settings/        # NotificationPreferences
    ├── hooks/
    │   ├── useSession.tsx   # ★ 会话与能力位（全 app 单一数据源）
    │   ├── useSetup.tsx     # 首次初始化探测（只探一次）
    │   ├── useTheme.tsx / useAppearance.tsx
    │   ├── useReauth.tsx / useSecondFactor.ts / usePasswordPolicy.ts
    │   ├── useSiteBrand.ts / useMediaQuery.ts
    ├── pages/               # 业务页面（见 §2）
    ├── lib/
    │   ├── api.ts           # ★ fetch 封装：CSRF、401、错误解包
    │   ├── api-types.ts     # 与后端对齐的请求/响应类型
    │   ├── captcha.tsx      # Turnstile / 极验组件与策略
    │   ├── webauthn.ts      # 通行密钥浏览器 API 封装
    │   ├── settings-sections.ts  # 系统设置分区清单（唯一事实来源）
    │   ├── timezone.ts / utils.ts
    └── i18n/
        ├── index.tsx        # 语言状态 + t() + 字典按需加载
        └── zh-CN.ts / zh-TW.ts / ja.ts / en.ts
```

## 2. 路由表（`App.tsx`）

```
/setup                     SetupPage           首次部署初始化（SetupGuard 强制跳转）

/sign-in                   LoginPage           登录（/login → 302 重定向到此处）
/signup                    SignupPage
/forgot-password           ForgotPasswordPage
/verify-email              VerifyEmailPage     邮件链接直达，不要求登录
/oauth/consent             OAuthConsentPage    OIDC 同意页

RequireAuth + AppShell（登录后区域）
├── /         /overview    OverviewPage        个人总览（懒加载，含图表）
├── /apps                  AppsPage            我的授权应用
├── /settings              ProfilePage         个人资料
├── /settings/account      SecurityPage        安全中心
├── /sessions              SessionsPage
├── /events                EventsPage
└── AdminRoute（仅管理员）
    ├── /admin             AdminDashboardPage（懒加载）
    ├── /admin/users       AdminUsersPage
    ├── /admin/audit       AdminAuditPage
    └── /admin/settings    AdminSettingsPage（按 ?section=&tab= 渲染分区）

兼容重定向：
  /login                → /sign-in
  /settings/notifications → /settings        （通知偏好已并入个人资料）
  /settings/appearance    → /settings        （已改为顶栏外观抽屉）
  /admin/apps             → /admin/settings?section=apps
  /admin/grants           → /admin/audit?tab=grants
```

## 3. 状态与数据流

### 3.1 Provider 嵌套（`App.tsx`）

```
QueryClientProvider（staleTime 30s，retry 1，窗口聚焦不重取）
  └─ ThemeProvider
      └─ SetupProvider          ← 只探测一次 /setup/status
          └─ SessionProvider    ← 只用 /api/v1/session 作为会话来源
              └─ ToastProvider
                  └─ ConfirmProvider
                      └─ SetupGuard
                          └─ Routes
```

### 3.2 路由守卫

```tsx
// RequireAuth：探测期间显示稳定占位（BootSplash），避免"先渲染外壳再跳转"的闪烁
function RequireAuth({ children }) {
  const { session, isLoading } = useSession()
  if (isLoading) return <BootSplash />
  if (!session) return <Navigate to="/sign-in" replace state={{ from: location.pathname + location.search }} />
  return <>{children}</>
}

// SetupGuard：系统未初始化时把除 /setup 外的所有页面重定向到初始化页
function SetupGuard({ children }) {
  const { checked, needsSetup } = useSetup()
  if (!checked) return <BootSplash />           // 返回 null 会造成白屏→内容闪烁
  if (needsSetup && location.pathname !== '/setup') return <Navigate to="/setup" replace />
  return <>{children}</>
}
```

`SetupPage` 初始化成功后立即调用 `markInitialized()` 放行，
避免"跳到首页又被拉回 /setup"的循环闪烁。

### 3.3 `lib/api.ts`：请求封装要点

- `API = '/api/v1'`，CSRF 头 `X-OpenIdP-CSRF`，请求 ID 头 `X-Request-ID`
- `CSRF_FREE` 集合列出免 CSRF 端点，与后端保持一致
- **401 自动刷新 CSRF 重试一次**（`refreshCsrfToken`）：
  服务重启后内存 TokenStore 被清空，旧 CSRF 会失效，不重试会表现为"所有写操作 403"
- `ApiError` 携带 `status / code / requestId / fields`
- 所有请求默认 `credentials: 'include'`

### 3.4 `hooks/useSession.tsx`：单一数据源

持有 `SessionData`（`csrfToken`、`site`、`user`、`ipAddress`、`ipRegion`），
并提供登录动作：`loginWithPasskey`、`verifyMFA`、`applySession`、`logout`。

同时导出**强类型能力位**：

```ts
export type PersonalCapability =
  | 'profileEdit' | 'avatarUpload' | 'passwordChange' | 'emailChange'
  | 'sessionManagement' | 'grantManagement' | 'identityManagement'
  | 'securityEvents' | 'accountDeletion' | 'phoneVerify' | 'phoneAdd'
  | 'notificationEmail'

export type AdminCapability =
  | 'dashboard' | 'auditEvents' | 'notifications' | 'users' | ...
```

> 刻意不写成 `Record<string, boolean>`：宽松类型会让"后端新增/下线能力位、前端漏消费"
> 在编译期完全静默（拼错 key 取到 `undefined`，与"能力确实为 false"无法区分）。

## 4. 页面职责

| 页面 | 关键行为 |
|------|---------|
| `LoginPage` | 四个 Tab（密码 / 邮箱验证码 / 通行密钥 / 第三方）；`returnUrl` 只放行站内单斜杠路径；MFA 二段式提交 |
| `SignupPage` | 受 `login-policy` 与安全策略（注册开关、邮箱验证、域名白名单）控制 |
| `ForgotPasswordPage` | 发码 + 重置 |
| `VerifyEmailPage` | 邮件链接直达，未登录时引导登录后回跳 |
| `OAuthConsentPage` | 从 `?request=ticket` 拉取应用信息与 scope 中文说明，同意/拒绝 |
| `OverviewPage` | 个人总览：登录方式分布、24h 小时趋势、7/30 天趋势、最近活动（懒加载图表） |
| `AppsPage` | 我的授权：按应用聚合 grant，可撤销 |
| `ProfilePage` | 资料编辑 + 通知偏好（原独立页面已合并） |
| `SecurityPage` | MFA、通行密钥、可信设备、第三方绑定、改密、手机号、注销账号 |
| `SessionsPage` | 在线会话与设备 |
| `EventsPage` | 安全事件（分类过滤在服务端） |
| `AdminDashboardPage` | 管理仪表盘（懒加载） |
| `AdminUsersPage` | 用户管理 |
| `AdminAuditPage` | 审计日志 + 授权记录（`?tab=grants`） |
| `AdminSettingsPage` | 系统设置全部分区（3271 行，按 `?section=&tab=` 渲染） |

## 5. 系统设置的分区设计（重要约定）

`lib/settings-sections.ts` 是**唯一事实来源**，同时被 `AppShell`（侧栏生成）与
`AdminSettingsPage`（内容渲染）import，避免两处各维护一份清单造成漂移。

```
brand        品牌信息
security     登录安全      tabs: policy / passkey / captcha
providers    登录提供商
apps         应用管理
messaging    消息服务      tabs: mail / sms / broadcast
proxy        出站代理
audit        数据与运维    tabs: audit / location / storage / cleanup / backup
```

旧地址通过 `SECTION_ALIASES` 归一化（`?section=passkey` → `security&tab=passkey` 等），
保证书签与外部文档链接不失效。新增分区**只改这一个文件**。

`SectionTabs` 用 `hidden` 容器而非 `TabsContent` 切换：后者会卸载子树，切页签就丢未保存的表单。

## 6. 构建与分包

`vite.config.ts`：

```ts
manualChunks: {
  charts: ['recharts'],                              // 占产物近四成，登录首屏用不到
  react:  ['react', 'react-dom', 'react-router-dom'],
  i18n:   ['./src/i18n/index.tsx'],
}
```

- `OverviewPage` / `AdminDashboardPage` 用 `React.lazy` + `Suspense`。
- i18n 字典**按需加载**：init 只加载当前语言 + `zh-CN` 回退，其余在切换时动态 import
  （否则任何语言都要下载约 312KB 的全部字典）。
- `cdnFonts()` 插件在构建期把 `index.html` 的 `<!-- cdn:fonts -->` 替换为字体样式表引用。
  `CDN_BASE_URL=-` 可完全关闭外部 CDN（私有化 / 离线部署，同时避免向第三方域发请求）。
- 产物输出 `web/dist`，由 `make embed` 复制到 `api/cmd/server/dist` 供 `go:embed`。

## 7. i18n 约定

- 语言优先级：`localStorage('openidp.lang')`（用户显式切换过）→ 站点默认语言（`/api/v1/site`）→ `zh-CN`。
  **不跟随 `navigator.language`**：未登录时必须落到站点默认语言。
- `t()` 直接读当前语言字典（同步），不走 `i18n.t()`：
  `setLang` 触发重渲染早于 `useEffect` 里的 `changeLanguage`，
  走 i18next 会读到旧语言，出现"选择的语言与显示不符"。
- 字典就绪前 `t()` 返回稳定占位值，避免 React bailout 复用旧文案节点导致"第一次切换没反应"。

## 8. 本地开发

```bash
make dev      # 单端口入口 http://127.0.0.1:6099
              # Go 处理 /api 与 /.well-known，其余反向代理到 Vite :5173（保留 HMR）
```

也可以只跑前端（`cd web && pnpm dev` 后访问 :5173），但需自行配置 Vite proxy；
`make dev` 是推荐路径，因为它与生产行为一致。

前端独立命令：

```bash
cd web && pnpm install
pnpm dev        # vite
pnpm build      # tsc -b && vite build
pnpm lint       # eslint src
```
