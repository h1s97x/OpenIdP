# 06 · HTTP 端点参考

路由唯一来源：`api/internal/handler/router.go`（管理端点在 `registerAdminRoutes`）。
响应统一由 `response.go` 封装：

- 成功：`{ "data": ..., "requestId": "..." }`
- 失败：`{ "error": { "code": "session.invalid_credentials", "message": "...", "fields": {...} }, "requestId": "..." }`

前端错误码映射见 `web/src/lib/api.ts` 的 `ApiError`。

## 1. 中间件与限流分组

| 分组 | 限额 | 端点示例 |
|------|------|---------|
| `loginLimiter` | 10/分/IP | `/session/login`、邮箱验证 |
| `codeLimiter` | 20/分/IP | 各类验证码请求/校验、passkey begin/finish |
| `accountLimiter` | 30/15分/账号 | 登录（叠加在 IP 限流之上） |
| `oauthLimiter` | 30/分/IP | `access_token`、`introspect`、`revoke`、`device_authorization` |
| `adminLimiter` | 60/分/IP | `/api/v1/admin/**` |
| `uploadLimiter` | 20/分/IP | `/files` 上传 |
| `avatarLimiter` | 20/分/IP | `/me/avatar` |
| `fileLimiter` | 600/分/IP | `/files/{publicId}` 读取 |
| `setupLimiter` | 10/分/IP | `/setup` |

**CSRF 分界**：
- 免 CSRF（公开入口）：`/setup/**`、`/v1/session/login`、`/v1/login-policy`、`/v1/site`、邮箱验证码、
  password-reset、passkey begin/finish、mfa/verify、`/v1/me/email/verify`、第三方回调
  `/api/oauth/callback/{type}`、`/api/login/provider/{type}/authorize`、`/v1/login/provider/{type}/bind`、
  文件读取 `/v1/files/{publicId}`
- 需要 CSRF（`X-OpenIdP-CSRF` 头）：`/api/v1/**` 的其余全部端点

> 文件读取放在 CSRF 组外是必需的：浏览器 `<img>` 直连不带自定义头，带 CSRF 会导致头像 403。

## 2. 开源端点（无鉴权）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查（Docker HEALTHCHECK 使用） |
| GET | `/api/version` | 版本 / Commit / 构建时间 |
| GET | `/.well-known/openid-configuration` | OIDC 发现文档 |
| GET | `/.well-known/jwks` | JWKS 公钥集 |
| GET | `/login/oauth/authorize` | 授权入口（未登录会 302 到 `/sign-in`） |
| POST | `/api/login/oauth/access_token` | 令牌端点（code / refresh / device_code） |
| GET | `/api/userinfo` | UserInfo（Bearer） |
| POST | `/api/login/oauth/introspect` | 令牌内省（RFC 7662） |
| POST | `/api/login/oauth/revoke` | 令牌撤销 |
| POST | `/api/login/oauth/device_authorization` | 设备码申请（RFC 8628） |
| GET | `/api/logout` | 结束会话（校验同源） |
| GET | `/api/v1/setup/status` | 是否已完成初始化 |
| POST | `/api/v1/setup` | 首次初始化（创建管理员，限流） |
| GET | `/api/v1/login-policy` | 登录策略（启用的方式、人机验证配置） |
| GET | `/api/v1/site` | 站点品牌 + 时区 + 语言 |
| GET | `/api/v1/login/providers` | 已启用的第三方提供商列表 |
| GET | `/api/v1/oauth/consent` | 同意页信息（`?request=ticket`） |
| GET | `/api/v1/session/ip` | 客户端 IP 与归属地 |
| GET | `/api/v1/files/{publicId}` | 文件读取（不可枚举 ID + ETag + Range） |

## 3. 登录/注册/找回（免 CSRF）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/session/login` | 密码登录；返回会话或 `mfaRequired`+`challengeId` |
| POST | `/api/v1/session/email-code/request` | 邮箱验证码登录：发送 |
| POST | `/api/v1/session/email-code/verify` | 邮箱验证码登录：校验并登录 |
| POST | `/api/v1/session/mfa/verify` | 二次验证（TOTP / 恢复码 / 邮箱回退） |
| POST | `/api/v1/session/passkey/begin` | 通行密钥登录 ceremony 开始 |
| POST | `/api/v1/session/passkey/finish` | 通行密钥登录 ceremony 完成 |
| POST | `/api/v1/signup/email-code/request` | 注册邮箱验证码 |
| POST | `/api/v1/signup` | 注册（受安全策略：注册开关、邮箱验证、域名白名单） |
| POST | `/api/v1/password-reset/request` | 找回密码：发码 |
| POST | `/api/v1/password-reset/confirm` | 找回密码：重置 |
| GET | `/api/oauth/callback/{type}` | 第三方回调（登录/绑定共用） |
| GET | `/api/login/provider/{type}/authorize` | 发起第三方授权 |
| GET | `/api/v1/login/provider/{type}/bind` | 已登录用户绑定第三方（整页跳转，免 CSRF） |
| POST | `/api/v1/me/email/verify` | 邮件链接验证（可能未登录，由页面引导登录） |

## 4. 用户自助（需会话 + CSRF）

### 4.1 会话与能力

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/session` | 当前会话（用户、站点、CSRF token） |
| DELETE | `/api/v1/session` | 退出登录 |
| GET | `/api/v1/capabilities` | 能力位（前端据此隐藏入口） |

`/capabilities` 的 `personal.*` / `admin.*` 是**枚举联合类型**（见 `web/src/hooks/useSession.tsx`），
不是宽松的 `Record<string, boolean>`——后端新增/下线能力位时前端漏消费会在编译期报错。

### 4.2 个人资料

| 方法 | 路径 |
|------|------|
| GET/PATCH | `/api/v1/me/profile` |
| POST | `/api/v1/me/password`（改密后其它会话全部下线） |
| POST | `/api/v1/me/email/verify/send` |
| POST | `/api/v1/me/email/code` |
| POST | `/api/v1/me/email` |
| POST | `/api/v1/me/phone/send-code` / `/me/phone/verify` |
| PATCH | `/api/v1/me/phone` |
| POST | `/api/v1/me/avatar` / `/me/avatar/reset` |
| GET | `/api/v1/me/export`（数据导出） |

### 4.3 安全中心

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/me/mfa` | MFA 状态 |
| GET | `/api/v1/me/mfa/begin` | 生成 TOTP 密钥与 otpauth URI |
| POST | `/api/v1/me/mfa/confirm` | 确认启用 |
| POST | `/api/v1/me/mfa/disable` | 关闭 |
| POST | `/api/v1/me/mfa/recovery-codes` | 重新生成恢复码 |
| GET/POST/DELETE | `/api/v1/me/passkeys`、`/me/passkeys/begin`、`/me/passkeys/finish`、`/me/passkeys/{id}` | 通行密钥管理 |
| GET/POST/DELETE | `/api/v1/me/trusted-devices`、`/me/trusted-devices/{id}` | 可信设备 |
| GET/DELETE | `/api/v1/me/identities`、`/me/identities/{id}` | 第三方身份绑定 |
| POST | `/api/v1/me/reauthenticate` / `/me/step-up` / `/me/step-up/email-code` | 敏感操作二次验证 |

### 4.4 会话 / 设备 / 授权 / 事件

| 方法 | 路径 |
|------|------|
| GET / DELETE | `/api/v1/me/sessions`（DELETE 清除其它会话） |
| DELETE | `/api/v1/me/sessions/{id}` |
| GET | `/api/v1/me/devices` |
| GET / DELETE | `/api/v1/me/grants`、`/me/grants/{id}` |
| GET | `/api/v1/me/dashboard?window=24h\|7d\|30d` |
| GET | `/api/v1/me/events?type=&category=&page=` |
| GET | `/api/v1/me/events/counts` |

> `category` 必须**在服务端过滤**：前端一次性取一页再本地 filter 时，
> 低频分类（如"应用授权"）会长期显示 0，用户误判为没有可疑活动。

### 4.5 通知 / 注销

| 方法 | 路径 |
|------|------|
| GET | `/api/v1/me/notifications`、`/me/notifications/unread-count` |
| PATCH | `/api/v1/me/notifications/{id}` |
| POST | `/api/v1/me/notifications/read-all` |
| DELETE | `/api/v1/me/notifications` |
| GET/PATCH | `/api/v1/me/notification-preferences` |
| GET/POST/DELETE | `/api/v1/me/account-deletion` |
| POST | `/api/v1/me/account-deletion/email-code` |

### 4.6 设备授权 / 同意

| 方法 | 路径 |
|------|------|
| POST | `/api/v1/oauth/consent`（同意/拒绝） |
| GET/POST | `/api/v1/oauth/device-authorizations` |
| GET/POST | `/api/v1/oauth/device-authorizations/{id}` |

### 4.7 文件

| 方法 | 路径 | 限制 |
|------|------|------|
| POST | `/api/v1/files` | 附件 10MB，扩展名白名单 + MIME 嗅探 |
| POST | `/api/v1/me/avatar` | 头像 2MB，仅图片类型 |

## 5. 管理后台（`/api/v1/admin/**`，需 `is_admin` + adminLimiter）

### 概览与审计

| 方法 | 路径 |
|------|------|
| GET | `/admin/dashboard`、`/admin/stats` |
| GET | `/admin/audit-events`（支持 `q/type/endpoint/outcome/userId`） |
| GET | `/admin/audit-stats` |
| GET/PUT | `/admin/audit-settings` |
| GET | `/admin/system-status` |

### 用户

`GET/POST /admin/users`、`PATCH/DELETE /admin/users/{id}`

### 站点与安全策略

`GET/PATCH /admin/site`、`GET/PATCH /admin/security-policy`

### OAuth 应用 / 提供商 / 授权 / scope

| 方法 | 路径 | 说明 |
|------|------|------|
| GET/POST | `/admin/oauth-clients` | 列表 / 创建 |
| PATCH/DELETE | `/admin/oauth-clients/{id}` | 更新 / 删除 |
| POST | `/admin/oauth-clients/{id}/secret` | **轮换密钥** |
| GET/POST | `/admin/oauth-providers` | 列表 / 创建（含自定义 OAuth2） |
| PATCH/DELETE | `/admin/oauth-providers/{id}` | 更新 / 删除 |
| POST | `/admin/oauth-providers/{id}/test` | 按真实出站配置（含代理）探测端点可达性 |
| GET | `/admin/oauth-grants` | 全部授权记录 |
| DELETE | `/admin/oauth-grants/{id}` | 管理员撤销任意用户授权 |
| GET/PUT | `/admin/oauth-scopes`、`/admin/oauth-scopes` | scope 元数据 |
| POST | `/admin/oauth-scopes/{id}/enable` / `/disable` | 启停 scope |

### 消息服务

| 方法 | 路径 |
|------|------|
| GET/PATCH | `/admin/mail`，POST `/admin/mail/test` |
| GET/PATCH | `/admin/sms`，POST `/admin/sms/test` |
| GET/PATCH | `/admin/captcha`，POST `/admin/captcha/test` |

### 存储 / 归属地 / 代理

| 方法 | 路径 |
|------|------|
| GET/PUT | `/admin/storage` |
| POST | `/admin/storage/test-and-save` |
| GET | `/admin/storage/stats` |
| GET/DELETE | `/admin/files`、`/admin/files/{publicId}` |
| GET/POST | `/admin/files/orphans`、`/admin/files/orphans/cleanup` |
| GET/PUT | `/admin/location`，POST `/admin/location/test` |
| GET/PATCH | `/admin/proxy`，POST `/admin/proxy/test` |

### 数据清理 / 备份

| 方法 | 路径 |
|------|------|
| GET/PUT | `/admin/data-cleanup` |
| GET | `/admin/data-cleanup/usage` |
| POST | `/admin/data-cleanup/run` |
| GET | `/admin/backup/export`（ZIP，分组可选） |
| POST | `/admin/backup/inspect`（解析备份内容） |
| POST | `/admin/backup/restore` |

### 注销审核 / 通知

| 方法 | 路径 |
|------|------|
| GET | `/admin/account-deletion-requests` |
| POST | `/admin/account-deletion-requests/{id}/approve` / `reject` |
| GET/POST | `/admin/notifications`（列表 / 广播） |
| GET | `/admin/notification-presets` |

## 6. 前端服务端约定的路径前缀（内嵌 SPA 必须放行）

`rootHandler` 只把下面这些前缀交给 chi，其余全部给 SPA：

```
/api/*        /.well-known/*        /login/oauth/*
```

反向代理配置（Nginx）里这些路径**必须用前缀匹配 `location ^~`**，
不要用正则 location——很多面板自带的隐藏文件拦截规则会误伤 `/.well-known/`。
详见 `nginx-separated.example.conf` 的说明与 [08-deployment.md](./08-deployment.md)。
