# 09 · 安全设计要点

本文件汇总散落在源码注释中的安全决策。**修改相关代码前请先读对应注释**——
很多"看起来多余的校验"都是在补已知漏洞。

## 1. 会话安全

| 措施 | 实现位置 | 说明 |
|------|---------|------|
| Cookie 只带原始 ID，库内只存摘要 | `currentUser` / `hashSessionID` | `sha256(sessionID)`；库/备份泄露 ≠ 会话可被劫持 |
| 会话 ID 轮换 | `rotateSession` | 登录成功前删除旧会话记录，防会话固定攻击 |
| 改密后踢出其它会话 | `handleChangePassword` | "已被攻陷/泄露的旧会话从此全部失效" |
| CSRF 令牌绑定会话 | `csrfTokenForSession` + `middleware.CSRF` | 令牌与会话同源同生命周期，无法跨会话使用 |
| 会话哈希回填 | `db.backfillSessionHashes` / `scrubSessionIDs` | 存量数据把原始 ID 改写为不可逆摘要 |
| Cookie 属性按 SITE_URL 推导 | `cookieSecure` / `cookieSameSite` | 不依据客户端可控的 Host 判断，防降级劫持 |

## 2. OIDC / OAuth 协议安全

| 措施 | 位置 | 说明 |
|------|------|------|
| `redirect_uri` 白名单失败**不重定向** | `HandleAuthorize` | 返回 JSON 错误，防开放重定向（RFC 6749 §4.1.2.1） |
| 仅支持 `response_type=code` | 同上 | 不支持 implicit |
| 仅支持 `S256` PKCE | 同上 + `tokenByCode` | 拒绝 `plain`，防降级 |
| public client 强制 PKCE | 同上 | 无密钥 + 无 PKCE = 零认证换 token，一律拒绝 |
| scope 收敛到客户端登记范围 | `intersectScopes` | 防止应用在用户同意后静默扩权 |
| 同意记录完整性校验 | `grantCoversScope` | 只有已有 grant **完整覆盖**本次 scope 才跳过同意页 |
| consent ticket 绑定会话 | `h.tokens.Set("consent:"+ticket, u.ID, sessionID)` | 防 CSRF 与 ticket 盗用，一次性消费（`GetDel`） |
| 授权码绑定 client_id + redirect_uri | `tokenByCode` | 防授权码混淆 / code swapping |
| 授权码原子消费 | `UPDATE ... WHERE code=? AND used=false` | 防并发重复兑换 |
| refresh token 轮换 + 重用检测 | `tokenByRefresh` | 检测到重用则吊销整个令牌家族（RFC 6819 §5.2.2.3） |
| 内省/撤销需客户端认证 | `authenticateClient` | 防匿名枚举他人令牌 |
| 设备码 user_code 用 CSPRNG | `cryptRandInt` / `randomUserCode` | 防可预测 |
| 注销校验同源 | `sameSiteRequest` | 防跨站 `<img>` 触发注销 CSRF |
| `iss` 用清洗后的 Host | `issuer` / `sanitizeHost` / `requestHost` | 防 Host 头注入影响 id_token |

## 3. 认证与防爆破

| 措施 | 说明 |
|------|------|
| 恒定时间密码比对 | `checkPasswordConstantTime`：用户不存在时也比对 dummy 哈希，抹平时序差异防账号枚举 |
| 多维度限流 | IP（`loginLimiter`）+ 账号（`accountLimiter`，防分布式爆破绕过单 IP 限制） |
| 限流 fail-closed | `RateLimiter` 取不到计数时**拒绝**而非放行（Redis 挂了不能让防爆破失效） |
| `IncrWithTTL` 单操作 | `Incr`+`Expire` 在多实例并发下会反复重置窗口 |
| 验证码尝试次数上限 | `VerificationCode.Attempts` / `MFAChallenge.Attempts`（6 位码只有 10^6 空间） |
| 验证码重发冷却 | `cooldownCheck` + `codeLimiter` |
| 密码哈希并发信号量 | `auth.passwordSem`，防止 bcrypt 打满 CPU |
| 密码策略校验 | `validatePassword(securityPolicy, pw)`（长度/大小写/数字/符号） |
| 邮箱域名白名单 / 禁止别名邮箱 | `SecurityPolicy.EmailDomainWhitelist*` / `DisableAliasEmail` |
| 可信设备跳过 MFA | `isTrustedDevice`（TTL 可配；`device_id` 为空的旧记录**不能**跳过） |
| 敏感操作 step-up | `handleReauthenticate` / `handleStepUp` + 邮箱验证码 |

## 4. 输入与输出

| 措施 | 位置 |
|------|------|
| 请求体大小上限 | `middleware.BodyLimit`（头像 2MB、附件 10MB） |
| 上传扩展名白名单 + MIME 嗅探 | `files.go` 的 `allowedImageExt` / `allowedAttachmentExt` / `mimeMatches` |
| SVG 沙箱渲染 | `serveFile` 输出 `CSP: default-src 'none'; sandbox` + `X-Content-Type-Options: nosniff` |
| 文件 URL 不可枚举 | 18 字节随机 `public_id`，内容与 ID 绑定、永不原地覆盖 |
| 本地存储路径穿越防护 | `storage/local.go` 的 `safePath` / `contains` |
| 站内跳转白名单 | `safeInternalPath` / `parseReturnURL`（只放行单斜杠站内路径） |
| 安全响应头 | `middleware.SecurityHeaders`：CSP、HSTS、nosniff、X-Frame-Options |
| 邮件头注入防护 | `mail.sanitizeHeaderValue`（剥离 CRLF） |
| 日志脱敏 | 访问日志不记请求体、查询串只留键名；`ConfigChange` 只记字段名 |

## 5. 数据保护

| 数据 | 保护方式 |
|------|---------|
| 用户密码 | bcrypt |
| OAuth 客户端密钥 | bcrypt（`oauth_clients.secret_hash`） |
| 会话标识 | SHA-256 摘要落库 |
| OAuth/SMTP/短信/代理/TOTP 凭据 | AES-256-GCM（`internal/appcrypto`，`enc:v1:` 前缀，随机 nonce） |
| 数据库备份 | 加密字段不可解 —— **必须同时备份 `encryption.key`** |
| 敏感日志 | 验证码等只打 stderr（`logging.Sensitive`），不落盘 |

密钥生成：`OPENIDP_ENCRYPTION_KEY` 未配置时自动生成 32 字节随机密钥写入
`<DATA_DIR>/encryption.key`（0600），重启复用保证已加密数据始终可解密。

## 6. 客户端 IP 可信链

```
优先级 ① 专用 CDN 真实 IP 头（EO-Client-IP → EO-Connecting-IP → CF-Connecting-IP
                              → ali-real-client-ip → True-Client-IP，可显式指定）
      ② X-Forwarded-For（从右往左跳过可信跳与内网地址）
      ③ TCP 对端地址

采信条件：TCP 对端必须落在可信网段
  = 回环 + RFC1918 私网 + IPv6 ULA（默认）∪ OPENIDP_TRUSTED_PROXIES
不满足 → 一律回退 TCP 对端地址
```

这条机制的作用：公网直连伪造 `X-Forwarded-For` 无效（对端不在可信网段）；
而 CDN/反代场景能拿到真实用户 IP，保证限流、审计、归属地都作用在正确的对象上。

## 7. 事件与审计

| 机制 | 说明 |
|------|------|
| `logEvent` 用 `context.Background()` | 审计必须落库即使客户端中途断开——否则攻击者断开连接就能让自己的失败尝试不留痕迹 |
| 失败的登录也记录 `user_id = 0` | 匿名/未识别主体，保证失败尝试可追溯 |
| `audit()` 分类审计日志 | `OPENIDP_AUDIT_LOG_ENABLED` 控制；`detail` 禁止放凭据 |
| `auditConfigChange()` | 只记被改字段名，不记值（值可能含密钥） |
| 审计保留与归档 | `AuditSetting` 配置，`cleanup-expired` / `audit-archive` 周期任务执行 |
| Webhook 外发 | `security.*` 事件异步投递，HMAC-SHA256 签名（`X-OpenIdP-Signature`） |
| 事件总线背压保护 | 有界队列 4096 + 64 worker，满则丢弃并计数——**绝不无限堆积** |

## 8. 运行时健壮性

| 措施 | 说明 |
|------|------|
| `Recover` 在最外层 | 任何 panic → 可解析 500 + 堆栈落盘，而非连接被断开 |
| HTTP 超时全设 | ReadHeader 10s / Read 5m / Write 5m / Idle 2m / MaxHeaderBytes 64KB（防 Slowloris） |
| 外链数据库 fail-fast | 默认不静默降级 SQLite，避免"用户数据消失"与双库分裂 |
| 缓存熔断 | Redis 运行期故障自动切内存，恢复后切回 |
| 热更新用原子指针 | 读路径拿到完整配置快照，不会读到"改了一半"的配置 |
| 周期任务隔离 | 单任务 panic 不影响调度器与其它任务 |

## 9. 已知取舍与边界（不算漏洞，但需知晓）

1. **不支持 SAML / LDAP / SCIM**：无法接管企业既有目录。
2. **无 RBAC / 权限策略引擎**：只有 `User.IsAdmin` 布尔位，没有细粒度授权模型。
3. **`oauth_providers.client_secret` 注释称"明文存储"**，
   但实际写库路径经过 `appcrypto.Encrypt`；以代码为准（见 `admin_oauth.go` 的写入逻辑）。
4. **无版本化迁移框架**：升级不能回滚，只有幂等 SQL + 登记表。
5. **单进程内嵌前端**：无法把前端单独部署为多份不同主题（但支持前后端分离模式）。
6. **多实例部署必须配 Redis**：否则限流、CSRF、Passkey 仪式、consent ticket 各自为政。

## 10. 上线前检查清单

- [ ] `OPENIDP_SITE_URL` 已设为真实公网地址（含 https）
- [ ] `OPENIDP_DATABASE_PASSWORD` 已改为强口令（默认是 `openidp123`）
- [ ] `OPENIDP_ENCRYPTION_KEY` 已显式配置并妥善备份（或确认 `encryption.key` 在备份范围内）
- [ ] `OPENIDP_JWT_KEY_DIR` 指向持久化目录（默认已在 `DATA_DIR`）
- [ ] `OPENIDP_REDIS_ADDR` 已配置（多实例必须）
- [ ] `OPENIDP_TRUST_PROXY` 与 `OPENIDP_TRUSTED_PROXIES` 按实际网络拓扑配置
- [ ] 管理后台「登录安全」中注册开关、密码策略、邮箱域名白名单已按需收紧
- [ ] SMTP 已配置（否则验证码只打日志，用户收不到）
- [ ] 人机验证已开启（防自动化爆破）
- [ ] 审计保留策略与备份策略已配置
- [ ] 反向代理对 `/.well-known/` 使用前缀匹配 `^~`
- [ ] 备份包含 `DATA_DIR`（含 `encryption.key`、`jwt/`）与数据库
