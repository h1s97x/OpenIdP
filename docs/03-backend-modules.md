# 03 · 后端模块与关键函数

按依赖层次从底向上。每节给出：包职责 → 关键类型/函数 → 注意事项（源码注释里的坑）。

---

## 基础设施层

### `internal/config` — 运行时配置

`Config`（`config.go`）聚合全部配置项，`FromEnv()` 从 `OPENIDP_*` 环境变量组装。

关键函数：

| 函数 | 作用 |
|------|------|
| `FromEnv() *Config` | 唯一配置入口；组装数据库 DSN、解析密码默认值、注入 provider 凭据 |
| `assembleDatabaseURL(...)` | 由 `DATABASE_TYPE/HOST/USER/...` 拼 DSN；不支持的类型→返回空→降级 SQLite |
| `(*Config).SiteURLIsPlaceholder()` | 判断 `SITE_URL` 是否仍是占位值（默认 `http://localhost:6099`）；`issuer()` 等依赖它判断"是否显式配置了公网地址" |
| `resolveTrustProxy()` | `OPENIDP_TRUST_PROXY` 解析，默认 `true`（服务通常在 CDN/反代后） |
| `loadProviderSecrets(c)` | 读取 `OPENIDP_<PROVIDER>_CLIENT_ID/SECRET`（github/google/microsoft/qq/gitee/linuxdo） |

注意点：
- `DefaultDatabasePassword = "openidp123"` 与 `docker-compose.yml` 的 `POSTGRES_PASSWORD` 默认值保持一致，
  保证首次部署开箱即用；`main.go` 会在仍使用默认口令时打印警告。
- `CookieSecure` / `CookieSameSite` 支持 `auto`：**根据 `SiteURL` 推导，而不是根据客户端可控的 Host 头**（防降级劫持）。
- `DBFallback` 默认 `fail-fast`：PG 故障时直接退出，避免静默切到空 SQLite 造成"用户数据消失"。

### `internal/timezone` — 系统时区

| 函数 | 作用 |
|------|------|
| `Apply(name)` | 应用 IANA 时区（设置 `time.Local`），并在最早时机暴露错误 |
| `Now()` / `Location()` | 统一的当前时间与位置 |
| `StartOfDay(t)` / `StartOfNextDay(t)` | 按天统计的日界（避免 UTC 日界导致"今天"在本地 08:00 才重置） |
| `OffsetLabel()` | `UTC+8` 形式标签，用于启动日志 |

### `internal/logging` — 日志

三套分类日志共用同一份文件（便于按时间线对照），带各自标签便于 grep：

| 函数 | 标签 | 内容 |
|------|------|------|
| `Access(r, status, bytes, dur)` | `[ACCESS]` | 方法/路径/状态码/字节/耗时/真实 IP/UA。**查询串只保留键名不记值** |
| `Audit(result, category, action, userID, ip, detail)` | `[AUDIT]` | 安全审计；`detail` 禁止放凭据 |
| `ConfigChange(scope, action, userID, ip, fields)` | `[CONFIG]` | 配置变更，**只记字段名不记值**（值可能含 SMTP 密码） |
| `Sensitive(format, ...)` | 仅 stderr | 验证码一类内容**不落盘** |
| `Init(opts)` | - | 按天 + 按大小（`MaxSizeMB`）切分，启动清理超保留期文件 |

设计约束：文件日志是 stderr 的**附加**而非替代（容器依赖 stdout/stderr）；
日志初始化失败降级为仅终端，绝不阻断启动。

### `internal/appcrypto` — 应用层加密

`Encrypt/Decrypt`：AES-256-GCM，随机 nonce，密文格式 `enc:v1:<base64(nonce||ct)>`。

| 函数 | 说明 |
|------|------|
| `Init(encoded, keyFile)` | 优先用 `OPENIDP_ENCRYPTION_KEY`（32 字节 hex/base64）；未配置则读/生成 `<DATA_DIR>/encryption.key`（0600） |
| `Enabled()` | 是否启用加密 |
| `Decrypt(v)` | **无前缀的存量明文原样返回**（增量迁移友好）；解密失败返回密文原文，让调用方校验失败而不是静默放行 |

加密对象：OAuth 提供商 ClientSecret、SMTP 密码、验证码密钥、TOTP 密钥、
存储/短信/代理凭据等。见 `handler/admin_settings.go` 里的 `appcrypto.Encrypt/Decrypt` 调用点。

### `internal/cache` — 共享缓存（Redis / 内存）

`Cache` 接口（`cache.go`）：`Get / Set / GetDel / Del / Incr / IncrWithTTL / Expire / Kind / Close`。

关键实现：

| 类型/函数 | 说明 |
|-----------|------|
| `New(Options)` | Addr 为空或连通失败→`memory`；成功→`failover(redis, memory)` |
| `memory` | 进程内 map + TTL 惰性清理 |
| `redisCache` | go-redis 封装 |
| `failover` | **运行期熔断**：连续失败达阈值切内存，后台协程探测恢复后切回 |
| `IncrWithTTL` | 计数与设 TTL 在同一操作完成——`Incr`+`Expire` 在多实例并发下会反复重置窗口，使限流形同虚设 |
| `GetDel` | 一次性 token / consent ticket 的原子消费 |
| `StatsReporter` | 可选接口，供管理端展示缓存规模 |

承载：TokenStore、全部限流器、OAuth consent ticket、Passkey 仪式状态、GeoIP 结果缓存。

### `internal/db` — 数据库

| 函数 | 说明 |
|------|------|
| `Kind(databaseURL)` | 由 DSN 判定 `sqlite/postgres/mysql` |
| `Open(url, dataDir, fallback)` | 返回 `OpenResult{DB, Kind, Degraded}`；`Kind` 是**实际生效**类型（降级后为 sqlite），日志必须用它 |
| `Migrate(ctx, db)` | 建表 + 建索引 + 列补齐 + 存量数据回填（见下） |
| `Now()` | 统一当前时间（走 timezone） |
| `CleanupExpired(ctx, db, retentionDays)` | 清理过期 sessions/tokens/codes/device_authorizations 等 |
| `ArchiveEvents(ctx, db, dataDir, retentionDays)` | 把超保留期审计事件归档为 JSONL 文件 |

迁移机制（**本项目无版本化 migration 框架，用幂等 SQL 实现**）：

- `createIndexes` / `createIndexIfMissing` — `indexMigration` 表驱动，按 dialect 生成 DDL
- `addColumnIfMissing` — `columnMigration` 表驱动，先查 `listColumns` 再决定是否 ALTER
- `schemaMigrations` + `migrationApplied` / `recordMigration` — 一次性数据修复的幂等登记表
- 存量回填函数（**读它们的注释能理解很多历史 Bug**）：
  `backfillSessionHashes`、`scrubSessionIDs`、`backfillDeviceIDs`、`backfillClientTypes`、
  `ensureCaseSensitiveUsername`、`removeDeprecatedProviders`、`dropPortalLoginPolicies`

MySQL 注意：charset 必须通过 `cfg.Collation` 指定，**不能塞进 `Params`**
（每个 Params 项会以 `SET k = v` 下发，`charset` 不是系统变量，会让每条连接失败）。

### `internal/models` — 数据模型

`models.go`（766 行）定义全部 bun 实体，详见 [05-data-model.md](./05-data-model.md)。

### `internal/middleware` — HTTP 中间件

| 文件 | 导出 | 作用 |
|------|------|------|
| `middleware.go` | `Recover`（在 recover.go） / `WithRequestID` / `SecurityHeaders` | 请求 ID 注入、安全响应头（CSP/HSTS/nosniff/X-Frame-Options），支持 `AllowInlineScripts` |
| `recover.go` | `Recover` | panic → 500 + 堆栈落盘；`http.ErrAbortHandler` 重新抛出 |
| `clientip.go` | `ResolveClientIP` / `TrustedPeer` | 按「专用真实 IP 头 → XFF 从右往左 → TCP 对端」取值，且**仅 TCP 对端落在可信网段时才采信转发头** |
| `cors.go` | `CORS(allowedOrigins)` | 前后端分离部署时的跨域 |
| `csrf.go` | `CSRF(header, store, cookieName)` | 校验 `X-OpenIdP-CSRF`，绑定会话 |
| `body_limit.go` | `BodyLimit` / `MultipartMemoryLimit` | 请求体上限 |
| `ratelimit.go` | `NewRateLimiter` / `RateLimit` | 固定窗口计数；**取不到计数时 fail-closed** |
| `accesslog.go` | `AccessLog` | 访问日志 + `statusRecorder` |
| `tokenstore.go` | `NewTokenStore` | CSRF / 一次性凭证 / OAuth state 存储，绑定会话 |

### `internal/auth` — 密码与令牌原语

| 函数 | 说明 |
|------|------|
| `HashPassword` / `CheckPassword` | bcrypt；`passwordSem` 信号量限制并发哈希，防止 bcrypt 打满 CPU |
| `SessionIDHash(id)` | SHA-256 摘要（`handler.hashSessionID` 与 db 回填共用，避免两处漂移） |
| `RandomToken(n)` / `RandomHex(n)` | CSPRNG 随机串 |
| `NewSubject()` / `NewID()` | OIDC `sub` 与实体 ID |
| `FirstNonEmpty(...)` | 常用小工具 |

### `internal/version`、`internal/system`、`internal/netutil`

- `version.Get()`：`-ldflags -X` 注入 Version/Commit/BuildDate，`/api/version` 输出。
- `system.Collect(dataDir)`：读 `/proc` 与 `syscall.Statfs` 得 CPU/内存/磁盘占用（非 Linux 返回 `Available=false`），供管理端状态面板。刻意不引 gopsutil。
- `netutil.HTTPClient(proxyURL)` / `TestConnectivity`：给开启"使用代理"的登录提供商构造出站 client。

---

## 领域层

### `internal/oidc` — 令牌签发（核心）

```go
type Provider struct {
    signingKey *jose.JSONWebKey
    jwks       jose.JSONWebKeySet
}
func NewProvider(keyDir string) (*Provider, error)
func (p *Provider) JWKS() jose.JSONWebKeySet
func (p *Provider) SignIDToken(issuer, subject, audience, nonce string,
                               claims map[string]any, ttl time.Duration) (string, error)
```

- 固定 `kid = "cert-built-in"`，算法 RS256，`use = sig`。
- `keyDir` 为空则生成**内存临时密钥**（重启后所有 token 失效），生产必须给 `OPENIDP_JWT_KEY_DIR`。
- 默认 `main.go` 会把它设为 `<DATA_DIR>/jwt`。
- 私钥文件 `rsa.pem`（0600），支持 PKCS#1 与 PKCS#8 解析。

### `internal/oauth2` — 第三方登录提供商

```go
var Registry = map[string]*Provider{}       // 内置注册表，init() 填充
type Profile struct { Provider, ProviderUID, DisplayName, AvatarURL, Email string; EmailVerified bool }
type Credentials struct { ClientID, ClientSecret, RedirectURL string }

func Get(providerType string) (*Provider, bool)
func NewCustomProvider(type, name, authorizeURL, tokenURL, userInfoURL string, scopes []string) *Provider
func (p *Provider) BuildAuthorizeURL(cred, state, codeChallenge, returnURL string) string
func (p *Provider) ExchangeCode(ctx, cred, code) (string, url.Values, error)
func (p *Provider) FetchProfile(ctx, accessToken, extra) (*Profile, error)
```

内置 6 家：`github`、`google`、`microsoft`、`qq`、`gitee`、`linuxdo`。
每家的 `ParseUserInfo` 负责把异构响应归一化为 `Profile`。

注意事项：
- **GitHub 的 `/user` 邮箱不标记 `EmailVerified`**：公共邮箱不保证已验证，标记会导致伪造邮箱自动关联到他人账号。
- **QQ 需要额外调用 `/oauth2.0/me` 获取 openid**（令牌响应不含 openid），见 `fetchQQOpenID`。
- 端点以下以数据库为准（seed 把内置值写入 `oauth_providers`，管理员可改），`Provider` 只是默认值与解析逻辑的载体。

### `internal/passkey` — WebAuthn 通行密钥

```go
type Config struct { Enabled bool; RPID, Origin, RPName string; Origins []string }
type Service struct { db; cache; resolve func(originHint string) Config }

func New(db, resolve, c) *Service
func (s *Service) BeginLogin(userID, originHint)   (ceremonyID, optionsJSON, error)
func (s *Service) FinishLogin(ceremonyID, credJSON) (int64, error)
func (s *Service) BeginDiscoverableLogin(originHint) / FinishDiscoverableLogin(...)  // 免用户名登录
func (s *Service) BeginRegistration(userID, originHint) / FinishRegistration(...)
func (s *Service) List(userID) / Delete(userID, credentialHex)
```

关键设计：
- **仪式状态存共享缓存**（`ceremony` 结构，TTL 5 分钟），多实例部署下 begin 在 A、finish 在 B 也能完成。
- 仪式结构字段**必须导出并带 json tag**——否则 `json.Marshal` 得到 `{}`，取出后 `Kind` 恒空，finish 一律失败（历史上就是这个 Bug）。
- RP 配置**每次请求动态解析**（`handler.ResolvePasskeyConfig`）：优先系统设置站点 URL，其次当前访问域名兜底。
- `models.Passkey` 的 `Transport/Flags/Authenticator/Attestation` 必须是 `json.RawMessage`，
  用 `[]byte` 会被 bun 二次 base64 编码，导致标志位与签名计数退化为零值。

### `internal/mfa` — TOTP 双因素

| 函数 | 说明 |
|------|------|
| `GenerateSecret()` | Base32 密钥 |
| `ProvisioningURI(issuer, account, secret)` | `otpauth://` URI，前端渲染二维码 |
| `Verify(secret, code)` | 校验 6 位 TOTP |
| `GenerateRecoveryCodes(n)` | 一次性恢复码 |
| `VerifyRecoveryCode(codes, input)` | 校验并返回**移除已用码后的新列表** |

调用侧（`handler/admin_settings.go`）还有爆破保护：
`MFAChallenge.Attempts` 达上限即作废挑战并记 `mfa.challenge_locked`。

### `internal/captcha` — 人机验证

- `captcha.go`：极验 GeeTest v4（`Config` + `TestConnection`）
- `turnstile.go`：Cloudflare Turnstile（`TurnstileConfig`）
- `provider.go`：统一的构造/校验接口

优先级：**Turnstile 优先，未配置时回退 GeeTest**（`config.FromEnv` 的推导逻辑）。
两者都存储在 `Handler` 的 `atomic.Pointer` 中，管理后台保存后整体替换。

### `internal/sms` — 短信服务

```go
type Provider interface {
    Name() string; Enabled() bool
    Send(ctx, phone, code) (string, error)
    TestConnection(ctx) error
    ConfigPayload() map[string]any     // 下发给管理后台动态渲染表单
}
func NewProvider(c *Config) Provider   // 未启用返回 noopProvider
func NormalizePhone(phone) (string, bool)
func Providers() []map[string]string   // 供后台下拉
```

内置 7 家：`aliyun`、`tencent`、`volcengine`、`huawei`、`qimo`、`submail`、`custom`(自定义 HTTP)。
**只用于手机号归属验证，不用于短信登录**：验证码由 OpenIdP 生成、服务商只负责送达、校验在本地完成。

### `internal/mail` — 邮件

```go
func New(cfg Config) *Sender
func (s *Sender) Send(to, subject, html string) error   // 见 mail.go
func DefaultTemplate() string
func renderTemplate(d TemplateData, custom string) string
```

- 支持隐式 TLS（465）与 STARTTLS（其它端口）；`InsecureSkipVerify` 仅开发用。
- 模板可后台自定义（`SMTPTemplate`），为空用内置。
- `sanitizeHeaderValue` 防邮件头注入（CRLF）。
- 关键场景：登录验证码、注册验证、改邮箱、找回密码、新设备登录提醒、测试发送。
- 无 SMTP 配置时，验证码会通过 `logging.Sensitive` 打到**终端**（便于开发，且不落盘）。

### `internal/storage` — 对象存储

```go
type Provider interface {
    Put(ctx, key string, data io.Reader, contentType string) (Object, error)
    Get(ctx, key string) (io.ReadCloser, error)
    Delete(ctx, key string) error     // 幂等：删不存在的对象视为成功
}
func New(cfg Config) Provider        // s3 且 bucket 非空 → S3，否则 Local
```

- `local.go`：本地磁盘，`safePath`/`contains` 防路径穿越。
- `s3.go`：自实现 AWS SigV4 签名（不引 SDK），支持自定义 `PublicBaseURL`。
- 上层（`handler/files.go`）做内容寻址：随机 `publicId` + **不可变 URL** + 强 ETag + 一年 `immutable` 缓存。

### `internal/geolocation` — IP 归属地

- 内置 ip2region xdb + GeoCN 库（`go:embed`），可用管理后台配置自定义库路径。
- `Resolve(ip)` → 展示串；`ResolveDetailed(ip)` → `*Result`。
- `Configure(geoCNDBPath, ip2regionDBPath)` 支持运行期切换库；`isPrivate` 跳过内网。
- 结果在请求级缓存（`handler.requestRegion`），同一请求多处使用时只解析一次。

### `internal/event` + `internal/webhook`

- `event.Bus`：`New()`、`Subscribe(typ, fn) (stop)`、`Publish(ctx, Data)`；
  `typ` 以 `.*` 结尾为前缀通配。有界队列 4096 + 64 worker，满则丢弃并计数。
- `webhook.Sender`：`New(cfg)`、`Attach(bus)`（订阅 `security.*`）、`Deliver`、`SetTargets`。
  异步投递，可选 HMAC 签名（`X-OpenIdP-Signature`，HMAC-SHA256）。

### `internal/scheduler` — 周期任务调度

`New()`、`Every(name, interval, fn)`、`Start(ctx) (stop)`。每任务独立定时器，panic 不影响其它任务。

### `internal/metrics` / `internal/seed`

- `metrics.Compute(ctx, db) (Snapshot, error)`：管理仪表盘数据（总量、30 天登录方式分布、14 天用户增长、事件类型 Top）。
  日界按 `timezone.Now()` 切分。
- `seed.Run(ctx, db, cfg)`：写入内置提供商端点（`seedProviders`，含 `backfillProviderEndpoints`）、默认安全策略（`seedSecurityPolicy`）。

---

## 编排层：`internal/handler`

### `Handler` 结构（`session.go`）

```go
type Handler struct {
    db       *bun.DB
    cfg      *config.Config
    oidc     *oidcHolder              // 持有 oidc.Provider

    cache    cache.Cache
    tokens   *middleware.TokenStore   // CSRF / 一次性凭证 / OAuth state

    mailer   *mail.Sender
    captcha   atomic.Pointer[captcha.Config]        // 热点可替换组件
    turnstile atomic.Pointer[captcha.TurnstileConfig]
    sms       atomic.Pointer[sms.Config]
    passkeys  *passkey.Service
    store     atomic.Pointer[storeHolder]           // storage.Provider

    loginLimiter   *middleware.RateLimiter   // 登录：10/分/IP
    codeLimiter    *middleware.RateLimiter   // 验证码：20/分/IP
    accountLimiter *middleware.RateLimiter   // 按账号：30/15分
    oauthLimiter   *middleware.RateLimiter   // OAuth：30/分/IP
    adminLimiter   *middleware.RateLimiter   // 管理：60/分/IP
    uploadLimiter  *middleware.RateLimiter   // 附件：20/分/IP
    avatarLimiter  *middleware.RateLimiter   // 头像：20/分/IP
    fileLimiter    *middleware.RateLimiter   // 文件读取：600/分/IP
    setupLimiter   *middleware.RateLimiter   // 初始化：10/分/IP

    conf       *configCache      // 单行配置 5s TTL 进程内缓存
    setupOnce  sync.Mutex        // 串行化首次初始化
    events     *event.Bus
    webhooks   *webhook.Sender
}
```

**为什么用 `atomic.Pointer`**：captcha/turnstile/sms/store 都由管理后台在运行期改写，
同时有请求线程并发读取。原子指针保证读路径拿到的是**完整快照**，不会读到"改了一半"的配置。
访问器：`captchaCfg()`、`turnstileCfg()`、`smsCfg()`、`storageProvider()`、`setStorageProvider()`。

### 核心函数速查（`session.go`）

| 函数 | 说明 |
|------|------|
| `New(db, cfg, oidcProvider, cache)` | 构造 Handler：初始化限流器、存储、人机验证、短信、加载持久化配置 |
| `currentUser(r)` | 由 Cookie → `hashSessionID` → 查 `sessions` → 校验过期 → 返回 `(*User, *Session, error)` |
| `issueSession(w, r, u, method)` | 建会话 + 建/更新设备 + 下发 Cookie，返回会话 ID |
| `rotateSession(r)` | 登录前删除旧会话记录（防会话固定） |
| `completeLogin(w, r, u, method, summary)` | **四种登录方式共用的收尾流程**：签发会话 → 绑 CSRF → 刷新可信设备 → 记事件 |
| `handleSessionLogin` | 密码登录：账号限流 → 人机验证 → 恒定时间比对 → MFA 分支 → 收尾 |
| `checkPasswordConstantTime(found, hash, pw)` | 用户不存在时也比对 dummy 哈希，抹平时序差异防账号枚举 |
| `findUserByAccount(ctx, db, login)` | 用户名/邮箱双查；同名歧义时报 409 而非随机挑一个 |
| `logEvent(r, userID, e)` | 安全事件落库 + 事件总线发布；**用 context.Background()** 保证客户端断连也留痕 |
| `audit(r, result, category, action, userID, detail)` | 受 `OPENIDP_AUDIT_LOG_ENABLED` 控制的分类审计日志 |
| `withClientIP` | 解析可信客户端 IP + 注入请求级归属地缓存 |
| `ResolvePasskeyConfig(originHint)` | 动态解析 WebAuthn RP 配置（站点 URL 优先，访问域名兜底） |
| `cookieSecure()` / `cookieSameSite()` | 按 `SITE_URL` 与 CORS 配置推导，返回 `auto` 语义 |
| `csrfTokenForSession(sessionValue, userID)` | 复用会话已有令牌，避免每次 GET /session 增发令牌 |

### 其它 handler 文件职责

| 文件 | 职责 |
|------|------|
| `router.go` | 全部路由注册（含 60+ 管理端点拆到 `registerAdminRoutes`） |
| `response.go` | `writeJSON` / `ok` / `fail` / `internal` 统一响应（含 requestId） |
| `oidc.go` | Discovery、JWKS、Authorize、Introspect、Revoke、Logout、开放重定向防护 |
| `oidc_token.go` | `HandleToken` → `tokenByCode` / `tokenByRefresh` / `tokenByDeviceCode`、`issueTokens` |
| `oidc_userinfo.go` | UserInfo、`authenticateClient`、`clientConfidential` |
| `oidc_consent.go` | 同意页 ticket 缓存、`HandleConsentInfo` / `HandleConsentAction`、`recordGrant` |
| `device_auth.go` | RFC 8628 设备码流（`randomUserCode`、`intersectScopes`、`disabledOAuthScopes`） |
| `session.go` | 会话/登录核心 + Handler 构造 |
| `session_ext.go` | 邮箱验证码登录、`handleCapabilities`、密码策略校验 |
| `setup.go` | 首次部署初始化（`/api/v1/setup/status`、`/api/v1/setup`） |
| `policy.go` | 登录策略、站点信息、`/capabilities` 能力位下发 |
| `me.go` | 个人资料、改密、总览仪表盘、事件、会话、设备、授权、可信设备、数据导出、账号注销、step-up |
| `me_ext.go` | 邮箱验证、头像上传/重置、新邮箱验证码 |
| `me_phone.go` | 手机号发送/校验验证码、保存 |
| `reauth.go` | 敏感操作前的重新认证（`step_up` / `reauthenticate`） |
| `trusted_device.go` | `isTrustedDevice` / `touchTrustedDevice`（可信设备跳过 MFA） |
| `passkey_login.go` | 通行密钥登录/注册/删除/列表（含免用户名 discoverable 登录） |
| `provider_sso.go` | 第三方登录发起/回调/绑定、身份列表、验证码冷却与持久化、`requestBaseURL`、`parseReturnURL` |
| `provider_endpoints.go` | 提供商端点/文档链接与内置默认值 |
| `notifications.go` / `notification_prefs.go` | 站内通知中心与偏好开关 |
| `files.go` | 上传（白名单 + MIME 嗅探校验）、读取（公开 ID + ETag + Range）、孤儿回收 |
| `account_deletion.go` | 注销申请 + 冷静期 + 管理员审核 + `purgeUser` |
| `security/url_safety.go` | `safeInternalPath` 等 URL 安全工具 |
| `admin*.go` | 管理端点（见 [06-api-reference.md](./06-api-reference.md)） |

### 管理后台 handler 分工

| 文件 | 职责 |
|------|------|
| `admin.go` | `requireAdmin`、`adminCapabilities`（能力位）、仪表盘、统计 |
| `admin_users.go` | 用户增删改查 |
| `admin_settings.go` | 站点/安全策略/邮件/短信/人机验证的读写与应用（`applyPersistedSettings`、`applySmsSetting`、`applyCaptchaSetting`） |
| `admin_oauth.go` | OAuth 应用（client）与提供商（provider）管理、密钥轮换、连通性测试、授权撤销、scope 启停 |
| `admin_site.go` | 品牌信息（Logo/Favicon/语言/页脚/备案号/Passkey 配置） |
| `admin_proxy.go` | 出站代理配置与测试（仅对开启"使用代理"的提供商生效） |
| `admin_backup.go` / `admin_backup_data.go` | 数据备份导出（ZIP 分组）、解析检查、恢复 |
| `admin_ext.go` | 审计事件/统计/保留策略、数据清理策略、系统状态、定点通知（广播） |
| `storage_settings.go` | 存储配置读写 + 孤儿文件管理 |
| `config_cache.go` / `consent_cache.go` | 进程内配置缓存与 consent ticket 缓存 |
