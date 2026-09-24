# 05 · 数据模型与迁移

全部实体定义在 `api/internal/models/models.go`（766 行），使用 bun ORM 标签。
数据库类型：SQLite（默认）/ PostgreSQL 17 / MySQL / MariaDB，由 `db.Kind` 判定、`db.Open` 连接。

## 1. 表清单

### 身份与凭据

| 表 | 结构体 | 关键字段 | 说明 |
|----|--------|---------|------|
| `users` | `User` | `subject`(唯一, OIDC sub)、`username`(唯一)、`email`(唯一,nullzero)、`email_verified`、`password_hash`、`password_set`、`is_admin`、`phone`/`phone_verified`、`avatar_url` | 用户主体，承载认证+资料 |
| `sessions` | `Session` | `id`(pk, 内部)、`session_hash`(对外 ID)、`user_id`、`device_id`、`expires_at`、`last_seen_at` | **库内只存 `sha256(sessionID)`**；`id` 绝不序列化（历史遗留：老数据就是原始会话 ID，由 `scrubSessionIDs` 改写） |
| `devices` | `Device` | `id`(pk, 随机)、`device_id`(Cookie 值)、`user_id`、首次/最近 IP 与归属地 | 唯一约束为 `(user_id, device_id)`：同一浏览器可被多个账号各自建记录（历史 Bug：id 直接复用 Cookie 值导致第二账号登录 500） |
| `trusted_devices` | `TrustedDevice` | `device_id`、`expires_at` | `device_id` 为空表示历史数据，无法跳过 MFA |
| `mfas` | `MFA` | `user_id`(唯一)、`secret`(加密)、`enabled`、`recovery_codes`(json) | TOTP 配置 |
| `mfa_challenges` | `MFAChallenge` | `id`、`method`、`attempts`、`expires_at`、`used` | 登录期的一次性二次验证挑战；`attempts` 上限防 TOTP 爆破 |
| `passkeys` | `Passkey` | `credential_id`(唯一)、`public_key`、`sign_count`、`transport/flags/authenticator/attestation`(`json.RawMessage`) | WebAuthn 凭据；JSON 列**必须**用 `json.RawMessage`（`[]byte` 会被 bun 二次 base64 编码，导致标志位/签名计数归零） |
| `identities` | `Identity` | `user_id`、`provider`、`provider_uid`、`display_name`、`avatar_url`、`email` | 已绑定的第三方身份 |
| `verification_codes` | `VerificationCode` | `email`、`purpose`(login/signup/reset/change_email)、`code`(json:"-")、`expires_at`、`used`、`attempts` | 落库以便重启后仍有效 |

### OAuth / OIDC

| 表 | 结构体 | 说明 |
|----|--------|------|
| `oauth_clients` | `OAuthClient` | 接入的应用。`secret_hash` 空 = public client（强制 PKCE）；`client_type` 显式区分 `confidential`/`public`（缺省按是否有密钥推导）；`redirect_uris`、`scopes`、`homepage_url` |
| `oauth_providers` | `OAuthProvider` | 登录提供商（6 内置 + 自定义）。端点字段对内置与自定义**都有效**，以内置注册表的值 seed 入库后**以数据库为准**；`client_secret` 加密存储；`use_proxy` 控制该提供商是否走出站代理 |
| `authorization_codes` | `AuthorizationCode` | `code`(pk, 32 字节随机)、`client_id`、`user_id`、`redirect_uri`、`scope`、`nonce`、`code_challenge`、`expires_at`(10 分钟)、`used` |
| `tokens` | `Token` | `type` = `access`/`refresh`；`revoked`；`replaced_by` 记录轮换后继（refresh 重用检测的墓碑指针） |
| `grants` | `Grant` | `user_id` + `client_id` + `scopes`(json)；同意页记录，用于"我的授权"与跳过重复同意 |
| `oauth_scopes` | `OAuthScope` | scope 元数据与启停控制（`disabledOAuthScopes` 消费） |
| `device_authorizations` | `DeviceAuthorization` | 设备码流：`device_code`、`user_code`、状态、客户端、scope |

### 配置（单行表）

| 表 | 结构体 | 内容 |
|----|--------|------|
| `site_settings` | `SiteSetting` | 站点名/显示名/Logo/Favicon/语言与默认语言/头像上传开关/站点 URL/页脚与备案号/Passkey 配置 |
| `security_policies` | `SecurityPolicy` | 密码策略、会话 TTL、注册开关、注册邮箱验证、密码登录开关、邮箱域名白名单、别名邮箱禁止、可信设备 TTL、账号注销开关与冷静期、手机号自助添加开关 |
| `mail_settings` | `MailSetting` | SMTP 主机/端口/账号/密码(加密)/发件人/UseTLS/SkipVerify/自定义模板 |
| `sms_settings` | `SmsSetting` | 短信服务商与各厂商凭据、站点签名、验证码 TTL、冷却 |
| `captcha_settings` | `CaptchaSetting` | 极验 / Turnstile 凭据与"登录/注册/找回密码是否强制" |
| `storage_settings` | `StorageSetting` | local / s3 及连接参数 |
| `location_settings` | `LocationSetting` | IP 库路径、客户端 IP 请求头、可信代理网段 |
| `audit_settings` | `AuditSetting` | 审计保留天数、归档开关、是否仅记录登录/安全事件 |
| `data_cleanup_settings` | `DataCleanupSetting` | 各类数据的清理策略 |
| `proxy_settings` | `ProxySetting` | 出站代理（`ProxyURL(plainPassword)` 组装，密码解密后拼接） |

### 业务与审计

| 表 | 结构体 | 说明 |
|----|--------|------|
| `events` | `Event` | 安全/登录事件。`type` 形如 `login.success`、`password.changed`；`metadata` json 存 `method`/`clientName` 等；审计与个人总览、管理统计的数据源 |
| `notifications` | `Notification` | 站内通知（`new_device_login` / `system` / `admin`），含 `read` 标记 |
| `notification_preferences` | `NotificationPreference` | 站内/邮件通知开关（user_id 为主键） |
| `files` | `File` | 内容寻址：`public_id`(18 字节随机→24 字符 Base64URL)、`backend`、`key`、`purpose`(avatar/attachment)、`mime_type`(服务端嗅探)、`content_hash`(SHA-256, 强 ETag)、`owner_user_id`、`detached_at`(孤儿回收) |
| `account_deletion_requests` | `AccountDeletionRequest` | 注销申请：`status`(pending/approved/rejected/cancelled/completed)、`scheduled_at`(冷静期结束)、审核人与备注 |

## 2. 索引

`db.go` 的 `indexMigration` 表列出全部索引，按 dialect 生成 DDL：

```go
func createIndexes(ctx, db) error
func createIndexIfMissing(ctx, db, m indexMigration) error
func indexDDL(dialectName, m indexMigration) string
```

新增索引**只需在表中追加一项**，不要手写 `CREATE INDEX`。

## 3. 迁移策略

### 3.1 三种机制

| 机制 | 用途 | 实现 |
|------|------|------|
| 建表 | 新表 | bun 的 `CreateTable().IfNotExists()`（`Migrate`） |
| 加列 | 新字段 | `columnMigration` 表 + `addColumnIfMissing`（先 `listColumns` 再 ALTER） |
| 加索引 | 新索引 | `indexMigration` 表 + `createIndexIfMissing` |
| 一次性数据修复 | 存量数据 | `schemaMigrations` + `migrationApplied`/`recordMigration` 幂等登记 |

**没有版本号框架**，全靠幂等 SQL + 登记表。好处是"升级直接换二进制"，坏处是不能回滚。

### 3.2 存量回填函数（读注释即历史 Bug 清单）

| 函数 | 做什么 | 为什么 |
|------|--------|--------|
| `scrubSessionIDs` | 把 `sessions.id` 从原始会话 ID 改写为不可逆摘要 | 老数据里 `id` 就是 Cookie 值，一旦泄露即可接管账号 |
| `backfillSessionHashes` | 回填 `session_hash` 列 | 支持"只存摘要"的新模型 |
| `backfillDeviceIDs` | 回填 `devices.device_id` | 老数据主键复用 Cookie 值，导致多账号登录冲突 |
| `backfillClientTypes` | 回填 `oauth_clients.client_type` | 缺省时"无密钥也通过认证"会被静默放行 |
| `ensureCaseSensitiveUsername` | 用户名大小写处理 | 避免仅大小写不同的账号互相覆盖 |
| `removeDeprecatedProviders` / `dropPortalLoginPolicies` | 清理废弃数据 | 历史功能下线 |

### 3.3 数据清理与归档

```go
func CleanupExpired(ctx, db, retentionDays) error   // 过期 sessions/tokens/codes/device_authorizations
func ArchiveEvents(ctx, db, dataDir, retentionDays) error  // 超保留期事件 → JSONL 文件
const DefaultEventRetentionDays = 90
```

由 `main.go` 注册到 `scheduler.Scheduler`：
- `cleanup-expired` 每小时一次，保留天数取管理后台审计保留策略（0 = 永久保留）
- `audit-archive` 每 24 小时一次，受 `AuditSetting.ArchiveEnabled` 控制

## 4. 敏感字段的存储方式

| 数据 | 存储方式 | 位置 |
|------|---------|------|
| 用户密码 | bcrypt 哈希 | `users.password_hash` |
| OAuth 客户端密钥 | bcrypt 哈希 | `oauth_clients.secret_hash` |
| 会话标识 | SHA-256 摘要 | `sessions.session_hash`（Cookie 携带原值） |
| OAuth/SMTP/短信/代理/TOTP 凭据 | AES-256-GCM（`enc:v1:` 前缀） | 各配置表对应列 |
| 邮箱验证码 | 明文（`json:"-"` 不外泄，带 attempts 限制） | `verification_codes.code` |
| 文件内容 | 存存储后端，库内只存元数据 + SHA-256 | `files` |

加密密钥来源：`OPENIDP_ENCRYPTION_KEY`（32 字节 hex/base64）或
`<DATA_DIR>/encryption.key`（首次自动生成，权限 0600）。

> **备份时必须同时备份 `encryption.key` 与 `jwt/rsa.pem`**，否则恢复后无法解密凭据、且签发的 token 全部失效。

## 5. 多数据库差异

- SQLite：默认，纯 Go 驱动（`modernc.org/sqlite`），无 CGO，文件位于 `DB 文件` 由 `OPENIDP_DATA_DIR` 决定。
- PostgreSQL：`OPENIDP_DATABASE_TYPE=postgres`，`sslmode` 默认 `disable`。
- MySQL/MariaDB：字符集通过 `cfg.Collation = "utf8mb4_general_ci"` 指定，**不能放进 DSN 的 Params**。
- 连接池：`MaxOpenConns=10`、`MaxIdleConns=5`、`ConnMaxLifetime=1h`。
- 降级：`OPENIDP_DB_FALLBACK=sqlite` 才允许外部库不可达时切 SQLite，默认 `fail-fast`。

## 6. 常用查询

```sql
-- 当前在线会话
SELECT s.session_hash, u.username, s.ip_address, s.last_seen_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.expires_at > now() ORDER BY s.last_seen_at DESC;

-- 某用户最近的登录记录
SELECT type, summary, ip_address, ip_region, created_at
FROM events WHERE user_id = ? AND type = 'login.success'
ORDER BY created_at DESC LIMIT 20;

-- 令牌家族（排查 refresh 重用）
SELECT id, type, client_id, revoked, replaced_by, created_at
FROM tokens WHERE user_id = ? AND client_id = ? ORDER BY created_at;

-- 孤儿文件（detached 且超宽限期）
SELECT public_id, backend, purpose, byte_size, detached_at
FROM files WHERE detached_at IS NOT NULL
  AND detached_at < now() - interval '7 days';
```
