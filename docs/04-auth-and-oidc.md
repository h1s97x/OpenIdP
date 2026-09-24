# 04 · 认证链路与 OIDC/OAuth2 实现

本文件是排查登录/授权问题的主要依据。

## 1. OIDC 端点一览（由代码生成，非文档抄写）

`HandleDiscovery`（`api/internal/handler/oidc.go`）实际下发的发现文档：

| 字段 | 值 |
|------|-----|
| `issuer` | `SITE_URL`（未配置时按请求域推导，见 §5） |
| `authorization_endpoint` | `{issuer}/login/oauth/authorize` |
| `token_endpoint` | `{issuer}/api/login/oauth/access_token` |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`、`client_secret_post`、`none` |
| `userinfo_endpoint` | `{issuer}/api/userinfo` |
| `jwks_uri` | `{issuer}/.well-known/jwks` |
| `introspection_endpoint` | `{issuer}/api/login/oauth/introspect` |
| `revocation_endpoint` | `{issuer}/api/login/oauth/revoke` |
| `device_authorization_endpoint` | `{issuer}/api/login/oauth/device_authorization` |
| `end_session_endpoint` | `{issuer}/api/logout` |
| `response_types_supported` | `code` |
| `grant_types_supported` | `authorization_code`、`refresh_token`、`urn:ietf:params:oauth:grant-type:device_code` |
| `id_token_signing_alg_values_supported` | `RS256` |
| `code_challenge_methods_supported` | `S256` |
| `scopes_supported` | `openid`、`email`、`profile`、`phone`、`offline_access` |
| `claims_supported` | `iss`、`sub`、`aud`、`iat`、`exp`、`nonce`、`preferred_username`、`name`、`picture`、`email`、`email_verified`、`phone`、`phone_number_verified` |
| `request_parameter_supported` | `false` |
| `backchannel_logout_supported` | `false` |

> ⚠️ 端点是**硬编码**在 `HandleDiscovery` 里的。新增/改路径时必须同步改这里，
> 否则客户端按发现文档调用会 404。

## 2. 授权码流程（Authorization Code + PKCE）

### 2.1 时序

```
RP(Browser)                OpenIdP                                  说明
    │                         │
    │ GET /login/oauth/authorize?client_id&redirect_uri&response_type=code
    │                        &scope&state&nonce&code_challenge&code_challenge_method=S256
    ├────────────────────────▶│
    │                         │ ① response_type 必须为 code（否则 JSON 错误，不重定向）
    │                         │ ② 查 oauth_clients；无效 → JSON 错误（不重定向）
    │                         │ ③ redirect_uri 必须精确命中白名单
    │                         │    ✗ 不命中 → JSON 错误，绝不重定向（防开放重定向）
    │                         │ ④ 未登录 → 302 /sign-in?returnUrl=完整授权 URI
    │                         │ ⑤ code_challenge_method 必须为 S256（拒绝 plain）
    │                         │ ⑥ public client 必须有 code_challenge
    │                         │ ⑦ scope = intersectScopes(请求, client.Scopes)  ← 收敛
    │                         │ ⑧ grantCoversScope(user, client, scope)?
    │                         │     ├─ 否 → 生成 ticket，302 /oauth/consent?request=ticket
    │                         │     └─ 是 → 直接签发授权码
    │ ◀───────────────────────┤ 302 /oauth/consent?request=...  或
    │                         │     redirect_uri?code=...&state=...
    │ 用户在同意页点击"允许"   │
    │ POST /api/v1/oauth/consent  { ticket, decision: "allow" }
    ├────────────────────────▶│ ⑨ 消费 ticket → 重建授权请求 → 记录 Grant → 签发授权码
    │ ◀───────────────────────┤ 返回需要前端跳转的 redirect URL
    │ GET redirect_uri?code=...&state=...
    ├────────────────────────▶│
    │ POST /api/login/oauth/access_token  grant_type=authorization_code&code&client_id
    │                                    &client_secret&code_verifier&redirect_uri
    ├────────────────────────▶│ ⑩ 见 §2.2 的校验链
    │ ◀───────────────────────┤ { access_token, token_type, expires_in:3600, id_token, refresh_token?, scope }
```

### 2.2 兑换授权码的校验链（`tokenByCode`）

顺序不可随意调整，前一项失败即返回 400：

1. 查 `authorization_codes`，校验 **未使用 + 未过期**（TTL 10 分钟 = `authorizationCodeTTL`）；
   已过期则顺手删除该行。
2. `ac.ClientID != client_id` → `invalid_grant`（防授权码混淆 / code swapping）。
3. `ac.RedirectURI != redirect_uri` → `invalid_grant`。
4. 查 `oauth_clients`，不存在 → `invalid_client`。
5. **PKCE**：`ac.CodeChallenge != ""` 时校验 `BASE64URL(SHA256(verifier)) == challenge`；
   若授权码没带 challenge，则仅 confidential client 允许放行。
6. **客户端认证**：`clientConfidential(client)` 时必须 `bcrypt` 匹配 `client_secret`。
7. **原子消费授权码**：
   ```sql
   UPDATE authorization_codes SET used = true WHERE code = ? AND used = false
   ```
   `RowsAffected == 0` → 说明并发下已被兑换 → `invalid_grant`。
   （先查后改的写法在并发下会重复签发令牌。）
8. `issueTokens(...)` 签发三个令牌。

### 2.3 `issueTokens`

- `access` = `auth.RandomToken(32)`，落 `tokens` 表，`expires_in = 3600`
- `refresh` 仅在 scope 含 `offline_access` 时签发（`offlineGranted(scope)`）
- `id_token` = `oidc.Provider.SignIDToken(issuer, subject, audience=clientID, nonce, claims, ttl)`
- **用户查不到时返回 `ok=false` 并已写出 400**，绝不签发无身份的令牌

### 2.4 refresh_token 轮换与重用检测（RFC 6819 §5.2.2.3）

`tokenByRefresh` 的顺序很关键：

```
① tok.ClientID != client_id           → invalid_grant
② confidential client 校验 secret
③ ★ tok.ReplacedBy != ""  ← 必须先于 revoked 判定！
     命中 → 判定为令牌重用（合法用户与攻击者各持一份）
           → 吊销该 user + client 的**全部**未吊销令牌（令牌家族）
           → 记 oauth.token_reuse 事件
           → invalid_grant
④ tok.Revoked || expired              → invalid_grant
⑤ 签发新 access/refresh/id_token
⑥ 旧 token 保留为墓碑：revoked=true, replaced_by=<新 refresh id>
```

> 注释明确指出：第 ③ 步若放在 ④ 之后就是**死代码**——轮换后的墓碑本身 `revoked=true`，
> 先判 revoked 会让家族吊销永远不可达，攻击者拿旧令牌只会拿到 `invalid_grant`，家族却依旧有效。

### 2.5 设备码流（RFC 8628）

`device_auth.go`：

| 端点 | 函数 | 说明 |
|------|------|------|
| `POST /api/login/oauth/device_authorization` | `HandleDeviceAuthorization` | 生成 `device_code` + 8 位 `user_code`（`randomUserCode`），scope 走 `intersectScopes` 收敛，禁用 scope 由 `disabledOAuthScopes` 排除 |
| `POST .../access_token` `grant_type=device_code` | `tokenByDeviceCode` | 未确认返回 `authorization_pending`，拒绝返回 `access_denied` |
| `GET /api/v1/oauth/device-authorizations` | `handleDeviceAuthList` | 用户门户查看待确认设备 |
| `POST /api/v1/oauth/device-authorizations` | `handleDeviceAuthVerify` | 输入 `user_code` |
| `GET/POST /api/v1/oauth/device-authorizations/{id}` | `handleDeviceAuthGet` / `handleDeviceAuthDecide` | 查看详情 / 同意或拒绝 |

`cryptRandInt` 用 CSPRNG 生成 `user_code` 数字部分，避免可预测。

### 2.6 Introspect / Revoke / Logout

- **Introspect**（RFC 7662）：先 `authenticateClient`；令牌不存在或**不属于该客户端**一律返回 `{"active": false}`，
  不泄露令牌是否存在。返回 `active/client_id/scope/token_type/exp`。
- **Revoke**：同样先认证客户端；令牌不属于该客户端 → 400 `invalid_grant`；否则置 `revoked = true`（幂等）。
- **Logout**（`/api/logout`，即 `end_session_endpoint`）：
  `sameSiteRequest(h, r)` 校验 Origin/Referer 与本站同源，**阻止跨站 `<img>` 触发的注销 CSRF**，
  不同源直接 403。

## 3. 同意页与 Grant

`oidc_consent.go`：

- 未覆盖全部 scope 时生成一次性 ticket（`auth.RandomToken(32)`），
  通过 `h.tokens.Set("consent:"+ticket, userID, sessionID)` **绑定当前会话**——
  同意页必须携带同一 Cookie 才能查看/操作，防止 CSRF 与 ticket 盗用。
- 完整授权参数（client_id / redirect_uri / scope / nonce / code_challenge / state / user_id）
  存为 `consentReq`（JSON 序列化进缓存），消费时据此**重建**授权请求，避免篡改与重放。
- `HandleConsentInfo`（`GET /api/v1/oauth/consent?request=ticket`）返回应用名、Logo、scope 中文说明。
- `HandleConsentAction`：`allow` → `recordGrant` + 签发授权码；`deny` → 记 `oauth.denied` 并带 `error=access_denied` 回跳。
- `grantCoversScope`：已有授权完整覆盖本次 scope 时才跳过同意页，**应用扩大权限范围必须重新征求同意**。

## 4. 登录方式实现

所有方式最终都汇到 `completeLogin(w, r, u, method, summary)`。

| 方式 | 端点 | 实现要点 |
|------|------|---------|
| 密码 | `POST /api/v1/session/login` | 账号维度限流 → 人机验证 → `checkPasswordConstantTime` → MFA 分支 → `completeLogin` |
| 邮箱验证码 | `POST .../session/email-code/request` + `/verify` | 验证码落库（`verification_codes`），带 `Attempts` 上限防 6 位爆破，`cooldownCheck` 限制重发 |
| 通行密钥 | `POST .../session/passkey/begin` + `/finish` | 两种：指定用户名（`BeginLogin`）与 **discoverable/免用户名**（`BeginDiscoverableLogin`）；`method = "passkey"`，不下发设备 Cookie |
| 第三方 | `GET /api/login/provider/{type}/authorize` → `/api/oauth/callback/{type}` | 见 §4.1 |

### 4.1 第三方登录（`provider_sso.go`）

- 登录与绑定**共用同一个回调路径** `/api/oauth/callback/{type}`（基于访问域名动态拼接），
  三方平台只需登记一个回调地址；通过 **state 前缀**区分登录/绑定流程。
- state 绑定 Cookie `openidp_oauth_state`，回调必须携带同一 Cookie 才能消费 →
  防"攻击者在自己浏览器发起登录、截获回调 URL 后诱导受害者点击"造成的登录 CSRF / 会话注入。
- `resolveProvider` 把数据库配置（可被管理员改过的端点）与内置 `oauth2.Provider` 的解析逻辑结合；
  开启"使用代理"的提供商走 `netutil.HTTPClient`。
- `loginOrSignupWithProvider`：按 `(provider, provider_uid)` 找 `identities` → 命中则登录；
  未命中时按邮箱/注册策略决定新建用户或要求先登录再绑定（`bindIdentity`）。
- `safeUsername(provider, uid)` 生成不会撞车的用户名。
- `parseReturnURL` 只放行站内单斜杠路径。

### 4.2 二次验证（MFA）

```
密码通过 → userMFAEnabled(u.ID)?
            ├─ 否 → completeLogin
            └─ 是 → isTrustedDevice(r, u.ID)?
                     ├─ 是 → completeLogin（metadata.mfaSkipped = "trustedDevice"）
                     └─ 否 → createMFAChallenge(userID, "password")
                              → 返回 { mfaRequired:true, challengeId, method:"totp" }
                              → POST /api/v1/session/mfa/verify { challengeId, code }
```

- `MFAChallenge.Attempts` 达上限即作废挑战并记 `mfa.challenge_locked`。
- 恢复码走 `mfa.VerifyRecoveryCode`，用掉后写回剩余列表。
- 邮箱作为二次验证回退（`mfa.email_fallback_sent`）。

### 4.3 可信设备

`trusted_device.go`：

- `isTrustedDevice(r, userID)`：用 `openidp_device_id` Cookie 值匹配 `trusted_devices.device_id` 且未过期。
- `touchTrustedDevice(ctx, userID, devID)`：登录成功后刷新 `last_seen_at`。
- TTL 取 `security_policy.trusted_device_ttl_days`，为 0 时回退 `OPENIDP_DEVICE_TTL_DAYS`。
- `DeviceID` 为空的存量记录**无法跳过 MFA**（安全默认）。

### 4.4 敏感操作二次验证

`reauth.go` + `me.go` 的 step-up：

- `POST /api/v1/me/reauthenticate`：重新输入密码验证身份。
- `POST /api/v1/me/step-up` + `/step-up/email-code`：邮箱验证码方式的 step-up。
- 用于改密码、改邮箱、解绑第三方、注销账号等敏感动作。

## 5. issuer 与 URL 推导（易踩坑）

```go
func (h *Handler) issuer(r *http.Request) string {
    // ① 显式配置了 SITE_URL → 直接用它（受信任）
    if u := strings.TrimRight(h.cfg.SiteURL, "/"); !h.cfg.SiteURLIsPlaceholder() {
        return u
    }
    // ② 回退：按请求推导，用「清洗过的 Host」防 Host 头注入影响 id_token 的 iss
    scheme := "https"; if isLocal(r) { scheme = "http" }
    host := requestHost(r); if host == "" { host = "localhost" }
    return scheme + "://" + host
}
```

**生产必须显式设置 `OPENIDP_SITE_URL`**，否则 `iss` 依赖请求 Host：
一旦 Host 头被污染或经过多层代理，RP 侧校验 `iss` 会失败。

`requestBaseURL(r)`（`provider_sso.go`）与 `sanitizeHost` 做同样的清洗，用于拼接 OAuth 回调地址。

## 6. 手动验证 OIDC 是否正常（运维/排障用）

```bash
# 1. 发现文档
curl -s https://auth.example.com/.well-known/openid-configuration | jq

# 2. JWKS（客户端会拉这个验签）
curl -s https://auth.example.com/.well-known/jwks | jq '.keys[0] | {kid, alg, use}'

# 3. 授权码流程（浏览器）
open 'https://auth.example.com/login/oauth/authorize?client_id=<id>&redirect_uri=<uri>&response_type=code&scope=openid+profile+email&state=xyz'
#  → 同意后回调带 code，再用 curl 兑换：
curl -s -X POST https://auth.example.com/api/login/oauth/access_token \
  -d grant_type=authorization_code -d code=<code> \
  -d client_id=<id> -d client_secret=<secret> -d redirect_uri=<uri>

# 4. UserInfo
curl -s https://auth.example.com/api/userinfo -H 'Authorization: Bearer <access_token>'
```

常见失败与原因：

| 现象 | 原因 |
|------|------|
| `unsupported_response_type` | 应用用了 implicit/`id_token` 流程。OpenIdP 只支持 `code` |
| `redirect_uri 不在白名单` | 后台登记的回调地址与请求不完全一致（含末尾斜杠、端口、http/https） |
| `public 客户端必须使用 PKCE` | 应用类别是 public（无 secret）但未带 `code_challenge` |
| `仅支持 S256 的 PKCE 挑战` | 应用用了 `plain` 或未声明 `code_challenge_method` |
| `授权码不属于该客户端` / `redirect_uri 与授权码绑定不一致` | 兑换时参数与授权时不一致 |
| `invalid_client`（token 端点） | confidential 客户端未传或传错 secret |
| UserInfo 401 | access_token 过期（1 小时）或已被撤销 |
| RP 报 `iss mismatch` | 未配置 `OPENIDP_SITE_URL`，或反代未透传正确 Host |
