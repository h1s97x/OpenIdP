# 10 · 术语表与 FAQ

## 1. 术语表

| 术语 | 含义 | 代码位置 |
|------|------|---------|
| **IdP** | Identity Provider，身份提供方。负责认证用户并签发身份断言/令牌 | 整个项目 |
| **OP** | OpenID Provider，OIDC 语境下的 IdP | `internal/oidc` |
| **RP** | Relying Party，依赖方。即接入 OpenIdP 做登录的第三方应用 | `oauth_clients` 表 |
| **IAM** | Identity and Access Management，身份与访问管理（含权限治理） | 见 [01-overview](./01-overview.md#2-是-idp-还是-iam) |
| **sub / Subject** | OIDC 中用户的稳定唯一标识，永不变更 | `models.User.Subject` |
| **iss / Issuer** | 签发者标识，即站点 URL | `handler.issuer` |
| **JWKS** | JSON Web Key Set，公开的公钥集合，RP 用它验签 id_token | `/.well-known/jwks` |
| **PKCE** | Proof Key for Code Exchange，防授权码拦截。OpenIdP 只支持 `S256` | `HandleAuthorize` / `tokenByCode` |
| **Grant** | 用户对某应用的一笔授权记录（含 scope） | `models.Grant` |
| **Consent** | 同意页。首次授权或应用扩权时必须展示 | `oidc_consent.go` |
| **Device Code Flow** | RFC 8628，给无浏览器设备（TV/CLI）用的授权流程 | `device_auth.go` |
| **TokenStore** | 存储 CSRF / 一次性凭证 / OAuth state 的组件，绑定会话 | `middleware.TokenStore` |
| **Failover** | 缓存熔断降级：Redis 故障自动切内存，恢复后切回 | `cache/failover.go` |
| **可信设备** | 用户标记为可信的设备，登录时跳过 MFA | `trusted_devices` 表 |
| **Step-up** | 敏感操作前的二次验证（密码 / 邮箱码） | `reauth.go`、`me.go` |
| **孤儿文件** | 已解绑但仍存存储后端、超过宽限期的文件 | `files.detached_at` |
| **能力位 / Capability** | 后端下发给前端的开关集合，前端据此隐藏入口 | `/api/v1/capabilities` |
| **SetupGuard** | 前端守卫：系统未初始化时强制跳转初始化页 | `App.tsx` |
| **内嵌 SPA** | 前端产物通过 `go:embed` 打进二进制 | `cmd/server/main.go` |

## 2. FAQ

### Q1：这是 IdP 还是 IAM？

**核心是 IdP（OIDC Provider），带部分轻量 IAM 能力，但不是完整 IAM。**
完整论证见 [01-overview.md §2](./01-overview.md#2-是-idp-还是-iam)。

简单判断：
- 它给第三方应用签发 `id_token` 与 access_token → **这是 IdP 的核心职责**
- 它有用户目录、登录策略、审计、授权管理 → 属于 IAM 的**身份侧**
- 它没有 RBAC/ABAC 策略引擎、SAML/LDAP/SCIM 联邦 → 缺少 IAM 的**权限治理侧**

### Q2：怎么接入我的应用？

1. 管理后台 → 系统设置 → 应用管理 → 新建 OAuth 客户端
2. 登记回调地址（必须**完全一致**，含协议/端口/路径/是否带末尾斜杠）
3. 记录 `client_id` 与 `client_secret`，在应用侧配置：
   - 授权端点 `{SITE_URL}/login/oauth/authorize`
   - 令牌端点 `{SITE_URL}/api/login/oauth/access_token`
   - UserInfo `{SITE_URL}/api/userinfo`
   - JWKS `{SITE_URL}/.well-known/jwks`
4. 用 `openid profile email` 作为 scope；需要长期访问时加 `offline_access` 拿 refresh_token

绝大多数 OIDC 客户端库只需配 Discovery URL：`{SITE_URL}/.well-known/openid-configuration`。

### Q3：为什么我的应用拿不到 refresh_token？

refresh_token 只在 scope 含 `offline_access` 时签发（`offlineGranted`）。
且"我的授权"里必须有该应用对应的 grant 且 scope 覆盖。

### Q4：用户被"锁"在外边，怎么排查？

按顺序看：
1. `events` 表里该用户的 `login.failed` / `mfa.challenge_locked` 记录
2. 是否触发限流（`accountLimiter` 按账号 30 次/15 分钟）
3. 是否该账号 MFA 开启但用户丢了认证器 → 用恢复码，或管理员重置
4. 是否安全策略里关了密码登录（`PasswordLoginEnabled`）
5. 是否邮箱域名白名单把用户挡在外面

### Q5：改配置要重启吗？

**大多数不用。** 站点品牌、安全策略、邮件、短信、人机验证、存储、归属地、代理、
OAuth 提供商与客户端等都是数据库配置，后台保存即时生效。
需要重启的只有：环境变量类配置（`OPENIDP_*`）、`ENCRYPTION_KEY`、`JWT_KEY_DIR`、数据库连接。

### Q6：为什么后台改了 SMTP 但验证码还是只打日志？

检查「消息服务 → 邮件」的 `Enabled` 开关。未启用时 `mail.Sender` 会走日志输出路径
（验证码打到**终端**，不落盘，这是刻意的）。

### Q7：可以水平扩容吗？

可以，但**必须配置 Redis**（`OPENIDP_REDIS_ADDR`）。
否则限流计数、CSRF/一次性凭证、Passkey 仪式状态、consent ticket 都只在单实例内有效：
会出现"刷新到手另一个实例就 CSRF 失败 / Passkey 完成不了 / 限流被绕过"。

另外所有实例必须共享同一个 `OPENIDP_ENCRYPTION_KEY` 与 `OPENIDP_JWT_KEY_DIR`，
否则凭据解不开、令牌互相验不过。

### Q8：备份要备什么？

1. 数据库（或 SQLite 文件）
2. `<DATA_DIR>/encryption.key` ← **最容易漏，漏了之后所有凭据变成不可解密的密文**
3. `<DATA_DIR>/jwt/rsa.pem` ← 漏了之后所有已签发 token 失效
4. `<DATA_DIR>` 下的本地文件（若用 local 存储后端）
5. 日志（可选）

管理后台也提供 `/admin/backup/export`（ZIP，可按分组导出），
以及 `/admin/backup/inspect` + `/admin/backup/restore` 用于恢复校验。

### Q9：想要 SAML / LDAP / SCIM 怎么办？

当前版本都不支持。第三方登录只实现了 OAuth2/OIDC 协议族
（若要接 SAML IdP，需要自己实现并在 `oauth2.Registry` 之外新起一个 provider 体系）。

### Q10：怎么新增一个登录提供商？

两种方式：
- **自定义 OAuth2**（无需改代码）：管理后台 → 登录提供商 → 新建，填 authorize/token/userinfo 端点与 scope。
- **内置提供商**：在 `api/internal/oauth2/oauth2.go` 的 `init()` 里 `register(&Provider{...})`，
  实现 `ParseUserInfo` 把异构响应转成 `oauth2.Profile`；
  再在 `seed.builtinEndpoints` 里补默认端点。
  别忘在 `config.loadProviderSecrets` 的 provider 列表里加上它（支持通过 env 预填凭据）。

### Q11：`iss` 报错 / 回调地址不对？

几乎总是 `OPENIDP_SITE_URL` 没配（仍是占位值 `http://localhost:6099`）或与实际访问域名不一致。
`issuer()` / `requestBaseURL()` / Passkey RP 都优先用它。

### Q12：日志在哪？

默认 `<DATA_DIR>/log/openidp-YYYY-MM-DD.log`，按天 + 按大小（默认 64MB）切分，保留 7 天。
同时输出 stderr（容器日志采集依赖它）。
用 `grep '\[AUDIT\]'` / `[ACCESS]` / `[CONFIG]` 过滤三类分类日志。

### Q13：前端页面白屏？

1. 打开控制台看是否有 CSP 拦截（开发模式必须允许内联脚本，`rootHandler` 会自动放开）
2. 确认 `api/cmd/server/dist/index.html` 存在（`make embed` 后才有）
3. 检查 `SetupGuard` 是否把路由重定向到了 `/setup`

### Q14：代码里为什么这么多长注释？

项目约定：**注释解释"为什么"，而不是"是什么"**。
大部分注释是在说明"不这么写会出什么问题"，并且往往对应一个真实修复过的 Bug。
改代码前读注释能避免把已修的 Bug 改回去。
