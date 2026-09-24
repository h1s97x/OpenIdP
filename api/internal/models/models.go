package models

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// User 是系统的用户主体，承载认证、资料与授权相关字段。
type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID            int64  `bun:"id,pk,autoincrement" json:"id"`
	Subject       string `bun:"subject,unique,notnull" json:"subject"`
	Username      string `bun:"username,unique,notnull" json:"username"`
	DisplayName   string `bun:"display_name" json:"displayName"`
	Email         string `bun:"email,unique,nullzero" json:"email"`
	EmailVerified bool   `bun:"email_verified,default:false" json:"emailVerified"`
	PasswordHash  string `bun:"password_hash" json:"-"`
	PasswordSet   bool   `bun:"password_set,default:false" json:"passwordSet"`
	AvatarURL     string `bun:"avatar_url" json:"avatarUrl"`
	Phone         string `bun:"phone" json:"phone,omitempty"`
	// PhoneVerified 表示手机号已通过短信验证码确认归属。手机号允许用户自行填写，
	// 未验证的手机号不可信（尤其对第三方应用），OIDC 会据此下发
	// phone_number_verified=false。更换手机号后必须重新置为未验证。
	PhoneVerified bool      `bun:"phone_verified,default:false" json:"phoneVerified"`
	Address       string    `bun:"address" json:"address,omitempty"`
	IsAdmin       bool      `bun:"is_admin,default:false" json:"isAdmin"`
	CreatedAt     time.Time `bun:"created_at," json:"createdAt"`
	UpdatedAt     time.Time `bun:"updated_at," json:"updatedAt"`
}

// Session is a logged-in browser session.
type Session struct {
	bun.BaseModel `bun:"table:sessions,alias:s"`

	// ID 是会话主键。历史上它就是 Cookie 里的原始会话 ID，因此绝不能对外
	// 序列化：一旦下发即可被直接用于接管账号（Cookie 原样可用）。
	// 存量行由 Migrate 的 scrubSessionIDs 改写为不可逆摘要，之后 id 与
	// session_hash 同源，对外只暴露 session_hash。
	ID string `bun:"id,pk" json:"-"`
	// SessionHash 是会话 ID 的 SHA-256 摘要，也是对外唯一可见的会话标识。
	// 数据库只存摘要、Cookie 携带原始值，因此数据库/备份泄露不会直接导致
	// 所有在线会话被劫持；校验时对 Cookie 值取摘要后按该列查询。
	// 提交摘要而非原始值：拿到摘要也无法反推出可用的 Cookie。
	SessionHash string    `bun:"session_hash" json:"id"`
	UserID      int64     `bun:"user_id,notnull" json:"userId"`
	DeviceID    string    `bun:"device_id" json:"deviceId"`
	UserAgent   string    `bun:"user_agent" json:"userAgent"`
	IPAddress   string    `bun:"ip_address" json:"ipAddress"`
	IPRegion    string    `bun:"ip_region" json:"ipRegion"`
	ExpiresAt   time.Time `bun:"expires_at" json:"expiresAt"`
	LastSeenAt  time.Time `bun:"last_seen_at," json:"lastSeenAt"`
	CreatedAt   time.Time `bun:"created_at," json:"createdAt"`
	Current     bool      `bun:"-" json:"current"`
}

// Device groups sessions by device.
type Device struct {
	bun.BaseModel `bun:"table:devices,alias:d"`

	// ID 是设备行的主键，取随机值，与浏览器携带的 device cookie 解耦。
	// 历史上它直接复用 device cookie 值，导致同一浏览器登录第二个账号时
	// 主键冲突（id 相同但 user_id 不同），登录直接 500。
	ID string `bun:"id,pk" json:"id"`
	// DeviceID 是设备标识（浏览器 device cookie 的值），唯一性约束为
	// (user_id, device_id)：同一浏览器可供多个账号分别建立自己的设备记录。
	DeviceID         string    `bun:"device_id" json:"deviceId"`
	UserID           int64     `bun:"user_id,notnull" json:"userId"`
	UserAgent        string    `bun:"user_agent" json:"userAgent"`
	FirstIPAddress   string    `bun:"first_ip" json:"firstIpAddress"`
	FirstIPRegion    string    `bun:"first_ip_region" json:"firstIpRegion"`
	LastIPAddress    string    `bun:"last_ip" json:"lastIpAddress"`
	LastIPRegion     string    `bun:"last_ip_region" json:"lastIpRegion"`
	FirstSeenAt      time.Time `bun:"first_seen_at," json:"firstSeenAt"`
	LastSeenAt       time.Time `bun:"last_seen_at," json:"lastSeenAt"`
	SessionCount     int       `bun:"-" json:"sessionCount"`
	ActiveSessionCnt int       `bun:"-" json:"activeSessionCount"`
	Current          bool      `bun:"-" json:"current"`
}

// TrustedDevice is a device the user marked as trusted.
// 可信设备在登录时用于跳过二次验证：DeviceID 记录标记时所用浏览器携带的
// 设备 Cookie，登录链路据此匹配当前设备；为空表示历史数据（无法跳过 MFA）。
type TrustedDevice struct {
	bun.BaseModel `bun:"table:trusted_devices,alias:td"`

	ID         string    `bun:"id,pk" json:"id"`
	UserID     int64     `bun:"user_id,notnull" json:"userId"`
	DeviceID   string    `bun:"device_id" json:"deviceId"`
	Name       string    `bun:"name" json:"name"`
	UserAgent  string    `bun:"user_agent" json:"userAgent"`
	IPAddress  string    `bun:"ip_address" json:"ipAddress"`
	IPRegion   string    `bun:"ip_region" json:"ipRegion"`
	ExpiresAt  time.Time `bun:"expires_at" json:"expiresAt"`
	LastSeenAt time.Time `bun:"last_seen_at," json:"lastSeenAt"`
	CreatedAt  time.Time `bun:"created_at," json:"createdAt"`
	Current    bool      `bun:"-" json:"current"`
}

// Event is a sign-in / security event.
type Event struct {
	bun.BaseModel `bun:"table:events,alias:e"`

	ID        int64             `bun:"id,pk,autoincrement" json:"id"`
	UserID    int64             `bun:"user_id,notnull" json:"userId"`
	Type      string            `bun:"type,notnull" json:"type"`
	Summary   string            `bun:"summary" json:"summary"`
	IPAddress string            `bun:"ip_address" json:"ipAddress"`
	IPRegion  string            `bun:"ip_region" json:"ipRegion"`
	UserAgent string            `bun:"user_agent" json:"userAgent"`
	Metadata  map[string]string `bun:"metadata,type:json" json:"metadata,omitempty"`
	CreatedAt time.Time         `bun:"created_at," json:"createdAt"`
}

// Grant is an authorized third-party application grant.
type Grant struct {
	bun.BaseModel `bun:"table:grants,alias:g"`

	ID        string    `bun:"id,pk" json:"id"`
	UserID    int64     `bun:"user_id,notnull" json:"userId"`
	ClientID  string    `bun:"client_id" json:"clientId"`
	Scopes    []string  `bun:"scopes,type:json" json:"scopes"`
	CreatedAt time.Time `bun:"created_at," json:"createdAt"`
}

// OAuthClient is a registered OAuth application.
type OAuthClient struct {
	bun.BaseModel `bun:"table:oauth_clients,alias:oc"`

	ID string `bun:"id,pk" json:"id"`
	// SecretHash 是客户端密钥的哈希；为空表示 public client（只能搭配 PKCE 使用）。
	SecretHash string `bun:"secret_hash" json:"-"`
	// ClientType 明确区分 "confidential"（有密钥，必须在令牌/内省/撤销端点校验密钥）
	// 与 "public"（无密钥，强制 PKCE）。缺省时按是否有密钥推导，
	// 避免历史数据里「无密钥也能通过客户端认证」被静默放行。
	ClientType  string `bun:"client_type" json:"clientType"`
	Name        string `bun:"name" json:"name"`
	Description string `bun:"description" json:"description"`
	LogoURL     string `bun:"logo_url" json:"logoUrl"`
	// HomepageURL 是应用主页，供「我的授权」页面的「访问应用」入口使用；
	// 非必填，留空则前端不渲染访问按钮。
	HomepageURL  string    `bun:"homepage_url" json:"homepageUrl"`
	RedirectURIs []string  `bun:"redirect_uris,type:json" json:"redirectUris"`
	Scopes       []string  `bun:"scopes,type:json" json:"scopes"`
	CreatedAt    time.Time `bun:"created_at," json:"createdAt"`
}

// AuthorizationCode is a short-lived OIDC authorization code.
type AuthorizationCode struct {
	bun.BaseModel `bun:"table:authorization_codes,alias:ac"`

	Code          string    `bun:"code,pk" json:"code"`
	ClientID      string    `bun:"client_id" json:"clientId"`
	UserID        int64     `bun:"user_id" json:"userId"`
	RedirectURI   string    `bun:"redirect_uri" json:"redirectUri"`
	Scope         string    `bun:"scope" json:"scope"`
	Nonce         string    `bun:"nonce" json:"nonce"`
	CodeChallenge string    `bun:"code_challenge" json:"codeChallenge"`
	ExpiresAt     time.Time `bun:"expires_at" json:"expiresAt"`
	Used          bool      `bun:"used,default:false" json:"used"`
	CreatedAt     time.Time `bun:"created_at," json:"createdAt"`
}

// Token is an OIDC access/refresh token.
type Token struct {
	bun.BaseModel `bun:"table:tokens,alias:t"`

	ID        string    `bun:"id,pk" json:"id"`
	UserID    int64     `bun:"user_id" json:"userId"`
	ClientID  string    `bun:"client_id" json:"clientId"`
	Type      string    `bun:"type" json:"type"` // access | refresh
	Scope     string    `bun:"scope" json:"scope"`
	ExpiresAt time.Time `bun:"expires_at" json:"expiresAt"`
	Revoked   bool      `bun:"revoked,default:false" json:"revoked"`
	CreatedAt time.Time `bun:"created_at," json:"createdAt"`

	// ReplacedBy 记录轮换后的后继 refresh token ID（RFC 6819 §5.2.2.3 重用检测）。
	// 空串表示尚未轮换；非空但再次被使用即判定为令牌重用攻击。
	ReplacedBy string `bun:"replaced_by,default:''" json:"replacedBy,omitempty"`
}

// NotificationPreference stores per-user notification switches.
type NotificationPreference struct {
	bun.BaseModel `bun:"table:notification_preferences,alias:np"`

	UserID               int64 `bun:"user_id,pk" json:"userId"`
	NewDeviceInApp       bool  `bun:"new_device_in_app,default:true" json:"newDeviceInApp"`
	NewDeviceEmail       bool  `bun:"new_device_email,default:false" json:"newDeviceEmail"`
	PrivacyEmailReminder bool  `bun:"privacy_email_reminder,default:true" json:"privacyEmailReminder"`
}

// Notification is an in-app notification (notification center).
type Notification struct {
	bun.BaseModel `bun:"table:notifications,alias:nt"`

	ID        int64             `bun:"id,pk,autoincrement" json:"id"`
	UserID    int64             `bun:"user_id,notnull" json:"userId"`
	Type      string            `bun:"type,notnull" json:"type"` // new_device_login | system | admin
	Title     string            `bun:"title" json:"title"`
	Summary   string            `bun:"summary" json:"summary"`
	Metadata  map[string]string `bun:"metadata,type:json" json:"metadata,omitempty"`
	Read      bool              `bun:"read,default:false" json:"read"`
	CreatedAt time.Time         `bun:"created_at," json:"createdAt"`
}

// SiteSetting is the single-row site configuration used by the admin console.
type SiteSetting struct {
	bun.BaseModel `bun:"table:site_settings,alias:ss"`

	ID          int64    `bun:"id,pk,autoincrement" json:"id"`
	SiteName    string   `bun:"site_name" json:"siteName"`
	DisplayName string   `bun:"display_name" json:"displayName"`
	LogoURL     string   `bun:"logo_url" json:"logoUrl"`
	FaviconURL  string   `bun:"favicon_url" json:"faviconUrl"`
	Languages   []string `bun:"languages,type:json" json:"languages"`
	// DefaultLanguage 站点默认语言（未登录时的界面语言），取值 zh-CN / zh-TW / ja / en。
	DefaultLanguage string `bun:"default_language" json:"defaultLanguage"`
	// AvatarUploadEnabled 控制用户个人资料页是否允许上传自定义头像（默认关闭）。
	AvatarUploadEnabled bool `bun:"avatar_upload_enabled,default:false" json:"avatarUploadEnabled"`
	// SiteURL 站点公网地址（OAuth 回调 / 邮件链接 / 通行密钥依赖方 URL 用）。
	// 留空时按当前访问域名动态推导；不配置站点 URL 则通行密钥不启用。
	SiteURL string `bun:"site_url" json:"siteUrl"`
	// PasskeyEnabled 是否启用通行密钥（默认关闭；未显式开启则通行密钥不可用）。
	PasskeyEnabled bool `bun:"passkey_enabled,default:false" json:"passkeyEnabled"`
	// FooterText 底部页脚自定义文本（系统信息配置）。
	FooterText string `bun:"footer_text" json:"footerText"`
	// ICPBeian ICP 备案号（系统信息配置）。
	ICPBeian string `bun:"icp_beian" json:"icpBeian"`
	// PublicSecurityBeian 公安联网备案号（系统信息配置）。
	PublicSecurityBeian string `bun:"public_security_beian" json:"publicSecurityBeian"`
	// PasskeyDisplayName 通行密钥显示名称。
	PasskeyDisplayName string `bun:"passkey_display_name" json:"passkeyDisplayName"`
	// PasskeyRPID 通行密钥依赖方 ID（RPID，域名）。留空时按站点 URL / 访问域名推导。
	PasskeyRPID string `bun:"passkey_rpid" json:"passkeyRPID"`
	// PasskeyAllowInsecure 是否允许不安全来源（http 非 localhost 环境）。
	PasskeyAllowInsecure bool `bun:"passkey_allow_insecure,default:false" json:"passkeyAllowInsecure"`
	// PasskeyOrigins 允许的通行密钥 origins（JSON 数组）。
	PasskeyOrigins []string  `bun:"passkey_origins,type:json" json:"passkeyOrigins"`
	UpdatedAt      time.Time `bun:"updated_at," json:"updatedAt"`
}

// SecurityPolicy is the single-row password/security policy used by the admin console.
type SecurityPolicy struct {
	bun.BaseModel `bun:"table:security_policies,alias:sp"`

	ID                      int64 `bun:"id,pk,autoincrement" json:"id"`
	MinPasswordLength       int   `bun:"min_password_length" json:"minPasswordLength"`
	RequireUppercase        bool  `bun:"require_uppercase" json:"requireUppercase"`
	RequireLowercase        bool  `bun:"require_lowercase" json:"requireLowercase"`
	RequireNumber           bool  `bun:"require_number" json:"requireNumber"`
	RequireSymbol           bool  `bun:"require_symbol" json:"requireSymbol"`
	SessionTTLDays          int   `bun:"session_ttl_days" json:"sessionTTLDays"`
	PasswordResetEnabled    bool  `bun:"password_reset_enabled" json:"passwordResetEnabled"`
	SignupEnabled           bool  `bun:"signup_enabled" json:"signupEnabled"`
	SignupEmailVerification bool  `bun:"signup_email_verification" json:"signupEmailVerification"`
	// PasswordLoginEnabled 是否允许密码登录（默认开启）。
	// 该开关不在管理后台暴露（安全策略页已隐藏），初始化后即为开启状态。
	PasswordLoginEnabled bool `bun:"password_login_enabled,default:true" json:"passwordLoginEnabled"`
	// EmailDomainWhitelist 允许注册/登录的邮箱域名白名单（逗号分隔，留空表示不限制）。
	EmailDomainWhitelist string `bun:"email_domain_whitelist" json:"emailDomainWhitelist"`
	// EmailDomainWhitelistEnabled 是否启用邮箱域名白名单（默认关闭，关闭时不校验白名单）。
	EmailDomainWhitelistEnabled bool `bun:"email_domain_whitelist_enabled,default:false" json:"emailDomainWhitelistEnabled"`
	// DisableAliasEmail 是否禁止别名邮箱（如 +tag 形式）。
	DisableAliasEmail bool `bun:"disable_alias_email,default:false" json:"disableAliasEmail"`
	// TrustedDeviceTTLDays 可信设备有效期（天）。0 表示回退环境变量 DEVICE_TTL_DAYS。
	// 可信设备在有效期内登录可跳过二次验证。
	TrustedDeviceTTLDays int `bun:"trusted_device_ttl_days,default:0" json:"trustedDeviceTTLDays"`
	// AccountDeletionEnabled 是否开放用户自助注销账号（默认关闭）。
	AccountDeletionEnabled bool `bun:"account_deletion_enabled,default:false" json:"accountDeletionEnabled"`
	// AccountDeletionCooldownHours 注销账号的冷静期（小时）：发起申请后需等待该时长才允许执行。
	// 0 表示不设冷静期（申请可立即由管理员审核通过）。
	AccountDeletionCooldownHours int `bun:"account_deletion_cooldown_hours,default:0" json:"accountDeletionCooldownHours"`
	// PhoneAddEnabled 是否允许用户自助添加/更换手机号（默认开启）。
	// 关闭后用户侧安全中心不再展示手机号相关入口，写手机号的三个端点也会拒绝，
	// 已保存的手机号数据保持不变（便于管理员重新开启后继续使用）。
	PhoneAddEnabled bool      `bun:"phone_add_enabled,default:true" json:"phoneAddEnabled"`
	UpdatedAt       time.Time `bun:"updated_at," json:"updatedAt"`
}

// OAuthProvider is a login provider configuration (admin-editable).
// ClientSecret 始终以明文存储（同 MailSetting.Password 一致），用于换取 access_token。
//
// 端点字段（AuthorizeURL / TokenURL / UserInfoURL / OpenIDURL / Scopes / DocsURL）
// 对内置与自定义提供商都有效：内置提供商的端点由初始化流程把内置注册表的值写入
// 数据库，之后一律以数据库为准（管理员可在后台修改）；字段为空时回落到内置默认值，
// 因此「清空 = 恢复内置默认」也成立。
type OAuthProvider struct {
	bun.BaseModel `bun:"table:oauth_providers,alias:op"`

	ID           string `bun:"id,pk" json:"id"`
	Name         string `bun:"name" json:"name"`
	DisplayName  string `bun:"display_name" json:"displayName"`
	ProviderType string `bun:"provider_type" json:"providerType"`
	LogoURL      string `bun:"logo_url" json:"logoUrl"`
	ClientID     string `bun:"client_id" json:"clientId"`
	ClientSecret string `bun:"client_secret" json:"-"`
	Enabled      bool   `bun:"enabled,default:false" json:"enabled"`
	// Custom 标记用户自定义的 OAuth2 提供商（端点由管理员配置）。
	Custom bool `bun:"custom,default:false" json:"custom"`
	// UseProxy 该提供商的出站请求（令牌 / 用户信息）是否走系统设置中配置的代理。
	// 仅对开启此项的提供商生效，不改变其它出站请求。
	UseProxy bool `bun:"use_proxy,default:false" json:"useProxy"`
	// 端点配置：内置与自定义提供商共用（内置值由初始化写入，可被管理员修改）。
	AuthorizeURL string   `bun:"authorize_url" json:"authorizeUrl"`
	TokenURL     string   `bun:"token_url" json:"tokenUrl"`
	UserInfoURL  string   `bun:"user_info_url" json:"userInfoUrl"`
	Scopes       []string `bun:"scopes,type:json" json:"scopes"`
	DocsURL      string   `bun:"docs_url" json:"docsUrl"`
	// OpenIDURL 是换取唯一 openid 的额外端点，仅部分平台需要（如 QQ 的
	// /oauth2.0/me：其令牌响应不含 openid，必须单独调用）。内置提供商可修改，
	// 自定义提供商不使用该字段。
	OpenIDURL string    `bun:"open_id_url" json:"openIdUrl"`
	CreatedAt time.Time `bun:"created_at," json:"createdAt"`
}

// Passkey is a WebAuthn credential bound to a user (通行密钥).
//
// Transport/Flags/Authenticator/Attestation 存的是序列化后的 JSON，字段类型必须
// 是 json.RawMessage 而不是 []byte：
// bun 对 type:json 列会再对字段做一次 json.Marshal，[]byte 会被编成 base64
// 字符串，落库结果是 "<base64(JSON)>"；读回时按对象解析必然失败，凭据的标志位
// （BackupEligible 等）与签名计数全部退化成零值，进而让登录校验以
// 「Backup Eligible flag inconsistency」失败。json.RawMessage 自带
// json.Marshaler/Unmarshaler，bun 会把 JSON 原样写入与读出。
type Passkey struct {
	bun.BaseModel `bun:"table:passkeys,alias:pk"`

	ID              int64           `bun:"id,pk,autoincrement" json:"id"`
	UserID          int64           `bun:"user_id,notnull" json:"userId"`
	CredentialID    []byte          `bun:"credential_id,unique" json:"credentialId"`
	Name            string          `bun:"name" json:"name"`
	PublicKey       []byte          `bun:"public_key" json:"-"`
	AttestationType string          `bun:"attestation_type" json:"attestationType"`
	Transport       json.RawMessage `bun:"transport,type:json" json:"transport"`
	Flags           json.RawMessage `bun:"flags,type:json" json:"-"`
	Authenticator   json.RawMessage `bun:"authenticator,type:json" json:"-"`
	Attestation     json.RawMessage `bun:"attestation,type:json" json:"-"`
	SignCount       uint32          `bun:"sign_count" json:"-"`
	CreatedAt       time.Time       `bun:"created_at," json:"createdAt"`
	LastUsedAt      time.Time       `bun:"last_used_at," json:"lastUsedAt"`
}

// Identity is a linked third-party identity (社交登录绑定).
type Identity struct {
	bun.BaseModel `bun:"table:identities,alias:ident"`

	ID          string    `bun:"id,pk" json:"id"`
	UserID      int64     `bun:"user_id,notnull" json:"userId"`
	Provider    string    `bun:"provider,notnull" json:"provider"` // github/google/microsoft/qq/gitee/linuxdo/custom
	ProviderUID string    `bun:"provider_uid,notnull" json:"providerUid"`
	DisplayName string    `bun:"display_name" json:"displayName"`
	AvatarURL   string    `bun:"avatar_url" json:"avatarUrl"`
	Email       string    `bun:"email" json:"email"`
	CreatedAt   time.Time `bun:"created_at," json:"createdAt"`
}

// VerificationCode persists email verification codes (so they survive restarts).
type VerificationCode struct {
	bun.BaseModel `bun:"table:verification_codes,alias:vc"`

	ID        int64     `bun:"id,pk,autoincrement" json:"id"`
	Email     string    `bun:"email,notnull" json:"email"`
	Purpose   string    `bun:"purpose,notnull" json:"purpose"` // login|signup|reset|change_email
	Code      string    `bun:"code,notnull" json:"-"`
	ExpiresAt time.Time `bun:"expires_at" json:"expiresAt"`
	Used      bool      `bun:"used,default:false" json:"used"`
	// Attempts 记录错误尝试次数，超过上限即作废该验证码（防 6 位验证码爆破）。
	Attempts  int       `bun:"attempts,default:0" json:"-"`
	CreatedAt time.Time `bun:"created_at," json:"createdAt"`
}

// MailSetting stores the SMTP / mail configuration (single row) used by the
// admin console and applied at runtime.
type MailSetting struct {
	bun.BaseModel `bun:"table:mail_settings,alias:ms"`

	ID         int64     `bun:"id,pk,autoincrement" json:"id"`
	Enabled    bool      `bun:"enabled,default:false" json:"enabled"`
	Host       string    `bun:"host" json:"host"`
	Port       int       `bun:"port" json:"port"`
	User       string    `bun:"user" json:"user"`
	Password   string    `bun:"password" json:"-"`
	From       string    `bun:"from" json:"from"`
	FromName   string    `bun:"from_name" json:"fromName"`
	UseTLS     bool      `bun:"use_tls" json:"useTLS"`
	SkipVerify bool      `bun:"skip_verify" json:"skipVerify"`
	Template   string    `bun:"template" json:"template"`
	UpdatedAt  time.Time `bun:"updated_at," json:"updatedAt"`
}

// CaptchaSetting stores captcha (GeeTest / Turnstile) configuration (single row).
type CaptchaSetting struct {
	bun.BaseModel `bun:"table:captcha_settings,alias:cs"`

	ID                 int64  `bun:"id,pk,autoincrement" json:"id"`
	Provider           string `bun:"provider" json:"provider"` // turnstile | geetest | none
	GeetestCaptchaID   string `bun:"geetest_captcha_id" json:"geetestCaptchaId"`
	GeetestCaptchaKey  string `bun:"geetest_captcha_key" json:"-"`
	GeetestAPIDomain   string `bun:"geetest_api_domain" json:"geetestApiDomain"`
	GeetestBindMode    string `bun:"geetest_bind_mode" json:"geetestBindMode"` // slide | bind | click
	TurnstileSiteKey   string `bun:"turnstile_site_key" json:"turnstileSiteKey"`
	TurnstileSecretKey string `bun:"turnstile_secret_key" json:"-"`
	// TurnstileVerifyURL 自定义 Turnstile 校验端点（留空使用内置默认）。
	TurnstileVerifyURL       string    `bun:"turnstile_verify_url" json:"turnstileVerifyUrl"`
	RequiredForLogin         bool      `bun:"required_for_login" json:"requiredForLogin"`
	RequiredForSignup        bool      `bun:"required_for_signup" json:"requiredForSignup"`
	RequiredForPasswordReset bool      `bun:"required_for_password_reset,default:false" json:"requiredForPasswordReset"`
	UpdatedAt                time.Time `bun:"updated_at," json:"updatedAt"`
}

// MFA is a user's two-factor (TOTP) configuration.
type MFA struct {
	bun.BaseModel `bun:"table:mfas,alias:mfa"`

	ID            int64     `bun:"id,pk,autoincrement" json:"id"`
	UserID        int64     `bun:"user_id,unique,notnull" json:"userId"`
	Secret        string    `bun:"secret" json:"-"`
	Enabled       bool      `bun:"enabled,default:false" json:"enabled"`
	RecoveryCodes []byte    `bun:"recovery_codes,type:json" json:"-"`
	CreatedAt     time.Time `bun:"created_at," json:"createdAt"`
	UpdatedAt     time.Time `bun:"updated_at," json:"updatedAt"`
}

// AccountDeletionRequest 是用户自助注销账号的申请单。
//
// 注销是不可逆操作：线上采用「两步走」——先发起申请（进入二次验证 + 冷静期），
// 冷静期内可随时撤回；冷静期结束后由管理员在系统设置中审核通过才真正删除账号。
// 这样即使会话被盗用或误点，用户仍有挽回窗口，且管理员对删号有最终确认权。
type AccountDeletionRequest struct {
	bun.BaseModel `bun:"table:account_deletion_requests,alias:adr"`

	ID string `bun:"id,pk" json:"id"`
	// UserID 发起申请的用户；同一用户同时只保留一条 pending 申请。
	UserID int64 `bun:"user_id,notnull" json:"userId"`
	// Status 申请状态：pending（等待冷静期结束/管理员审核）| approved（已通过待清理）
	// | rejected（管理员驳回）| cancelled（用户撤回）| completed（账号已删除）。
	Status string `bun:"status,notnull" json:"status"`
	// Reason 用户填写的注销原因（可选）。
	Reason string `bun:"reason" json:"reason"`
	// ScheduledAt 冷静期结束时间（早于该时间不允许管理员通过审核）。
	ScheduledAt time.Time `bun:"scheduled_at,notnull" json:"scheduledAt"`
	// RequestIP / RequestUA 记录发起申请时的来源，便于事后追溯。
	RequestIP     string     `bun:"request_ip" json:"requestIp"`
	RequestRegion string     `bun:"request_region" json:"requestRegion"`
	RequestUA     string     `bun:"request_ua" json:"requestUserAgent"`
	ReviewedBy    int64      `bun:"reviewed_by" json:"reviewedBy"`
	ReviewedAt    *time.Time `bun:"reviewed_at" json:"reviewedAt,omitempty"`
	// ReviewNote 管理员审核备注（驳回原因等）。
	ReviewNote string    `bun:"review_note" json:"reviewNote"`
	CreatedAt  time.Time `bun:"created_at," json:"createdAt"`
	UpdatedAt  time.Time `bun:"updated_at," json:"updatedAt"`
	// 前端展示用：剩余冷静期秒数（仅 pending 时有意义）。
	RemainingSeconds int `bun:"-" json:"remainingSeconds"`
}

// 账号注销申请的状态常量。
const (
	DeletionStatusPending   = "pending"
	DeletionStatusApproved  = "approved"
	DeletionStatusRejected  = "rejected"
	DeletionStatusCancelled = "cancelled"
	DeletionStatusCompleted = "completed"
)

// MFAChallenge is a pending two-factor challenge issued at login.
type MFAChallenge struct {
	bun.BaseModel `bun:"table:mfa_challenges,alias:mch"`

	ID     string `bun:"id,pk" json:"id"`
	UserID int64  `bun:"user_id,notnull" json:"userId"`
	Method string `bun:"method" json:"method"` // password | emailCode
	// Attempts 记录该挑战已被错误校验的次数，达到上限即作废挑战
	// （6 位 TOTP 只有 10^6 空间，必须限制爆破次数）。
	Attempts  int       `bun:"attempts,default:0" json:"-"`
	ExpiresAt time.Time `bun:"expires_at" json:"expiresAt"`
	Used      bool      `bun:"used,default:false" json:"used"`
	CreatedAt time.Time `bun:"created_at," json:"createdAt"`
}

// 文件的业务用途。读取端点按 purpose 决定是否免鉴权：
// avatar 属于公开资料可免鉴权直出，attachment 等后续用途需要登录态校验。
const (
	FilePurposeAvatar     = "avatar"
	FilePurposeAttachment = "attachment"
)

// File 是上传文件的元数据记录（内容寻址 + 不可变 URL）。
//
// 对外只暴露随机 publicId（18 字节随机数 → 24 字符 Base64URL），
// 内部 storage key 与后端类型对调用方不可见，因此 URL 不可枚举、不可猜测。
// 内容与 ID 一一绑定、永不原地覆盖，从而可以安全地设置一年 immutable 缓存。
type File struct {
	bun.BaseModel `bun:"table:files,alias:f"`

	ID int64 `bun:"id,pk,autoincrement" json:"id"`
	// PublicID 是 URL 中使用的公开标识（随机、不可猜测）。
	PublicID string `bun:"public_id,unique,notnull" json:"publicId"`
	// Backend 记录落盘时使用的存储后端（local / s3）。
	// 读取与删除必须回到同一个后端，切换后端后旧文件仍可定位。
	Backend string `bun:"backend,notnull" json:"backend"`
	// Key 是对象在后端内的标识。
	Key string `bun:"key,notnull" json:"-"`
	// Purpose 用途分类（avatar / attachment）。
	Purpose string `bun:"purpose,notnull" json:"purpose"`
	// MimeType 由服务端嗅探得出，响应时按此输出 Content-Type，不跟随请求路径。
	MimeType string `bun:"mime_type,notnull" json:"mimeType"`
	// ByteSize 文件字节数。
	ByteSize int64 `bun:"byte_size,notnull" json:"byteSize"`
	// ContentHash 是内容的 SHA-256 摘要，用作强 ETag，并可用于存储去重分析。
	ContentHash string `bun:"content_hash,notnull" json:"contentHash"`
	// OriginalFilename 用户上传时的原始文件名（仅用于展示，不参与路径拼接）。
	OriginalFilename string `bun:"original_filename" json:"originalFilename,omitempty"`
	// OwnerUserID 上传者；为空表示系统文件或用户已注销。
	OwnerUserID int64 `bun:"owner_user_id" json:"ownerUserId,omitempty"`
	// DetachedAt 标记该文件已不再被业务引用（如用户换头像/删工单附件），
	// 孤儿回收任务在此时间 + 宽限期之后才真正删除，避免并发回退导致误删。
	DetachedAt *time.Time `bun:"detached_at" json:"detachedAt,omitempty"`
	CreatedAt  time.Time  `bun:"created_at," json:"createdAt"`
}

// URL 返回该文件的对外访问路径。
func (f *File) URL() string {
	if f == nil || f.PublicID == "" {
		return ""
	}
	return "/api/v1/files/" + f.PublicID
}

// StorageSetting 是对象存储的运行期配置（单行，id=1）。
// 由管理后台「存储管理」维护，变更即时生效，无需重启。
type StorageSetting struct {
	bun.BaseModel `bun:"table:storage_settings,alias:sts"`

	ID int64 `bun:"id,pk,autoincrement" json:"id"`
	// IsEnabled 未开启时禁止任何上传（头像上传等按不可用处理）。
	IsEnabled bool   `bun:"is_enabled,default:false" json:"isEnabled"`
	Backend   string `bun:"backend" json:"backend"` // local | s3
	// LocalPath 本地存储的根目录（留空回退 DATA_DIR）。
	LocalPath string `bun:"local_path" json:"localPath"`
	// S3 兼容存储连接参数。
	S3Endpoint      string `bun:"s3_endpoint" json:"s3Endpoint"`
	S3Bucket        string `bun:"s3_bucket" json:"s3Bucket"`
	S3Region        string `bun:"s3_region" json:"s3Region"`
	S3Prefix        string `bun:"s3_prefix" json:"s3Prefix"`
	S3PublicBaseURL string `bun:"s3_public_base_url" json:"s3PublicBaseUrl"`
	S3AccessKey     string `bun:"s3_access_key" json:"s3AccessKey"`
	// S3SecretKey 加密存储（与 MailSetting.Password 一致）。
	S3SecretKey string    `bun:"s3_secret_key" json:"-"`
	UpdatedAt   time.Time `bun:"updated_at," json:"updatedAt"`
}

// LocationSetting 是 IP 归属地解析的运行期配置（单行，id=1）。
type LocationSetting struct {
	bun.BaseModel `bun:"table:location_settings,alias:ls"`

	ID int64 `bun:"id,pk,autoincrement" json:"id"`
	// Enabled 关闭后不再解析 IP 归属地，事件/会话的地区字段留空。
	Enabled bool `bun:"enabled,default:true" json:"enabled"`
	// DBPath 自定义 GeoCN.mmdb 库路径（留空使用内置库）。
	DBPath string `bun:"db_path" json:"dbPath"`
	// V6DBPath 自定义 IPv6 库路径（留空使用内置库）。
	V6DBPath string `bun:"v6_db_path" json:"v6DbPath"`
	// RealIPHeader 优先读取的客户端 IP 请求头（如 CF-Connecting-IP）。
	RealIPHeader string `bun:"real_ip_header" json:"realIpHeader"`
	// TrustedProxies 额外可信的代理网段（逗号分隔），与默认的内网可信网段合并；
	// 仅当 TCP 对端落在可信网段内时才采信转发头。
	TrustedProxies string    `bun:"trusted_proxies" json:"trustedProxies"`
	UpdatedAt      time.Time `bun:"updated_at," json:"updatedAt"`
}

// AuditSetting 是审计日志保留策略（单行，id=1）。
type AuditSetting struct {
	bun.BaseModel `bun:"table:audit_settings,alias:as"`

	ID int64 `bun:"id,pk,autoincrement" json:"id"`
	// RetentionDays 事件保留天数（0 表示不自动清理）。
	RetentionDays int `bun:"retention_days,default:90" json:"retentionDays"`
	// ArchiveEnabled 超过保留期时先归档为 JSONL 再删除。
	ArchiveEnabled bool `bun:"archive_enabled,default:true" json:"archiveEnabled"`
	// LoginEventsOnly 仅记录登录/安全类事件，降低写放大。
	LoginEventsOnly bool      `bun:"login_events_only,default:false" json:"loginEventsOnly"`
	UpdatedAt       time.Time `bun:"updated_at," json:"updatedAt"`
}

// DataCleanupSetting 是分类数据清理策略（单行，id=1）。
// 各字段为对应数据的保留天数，0 表示不清理。
type DataCleanupSetting struct {
	bun.BaseModel `bun:"table:data_cleanup_settings,alias:dcs"`

	ID int64 `bun:"id,pk,autoincrement" json:"id"`
	// SessionRetentionDays 过期会话保留天数。
	SessionRetentionDays int `bun:"session_retention_days,default:30" json:"sessionRetentionDays"`
	// TokenRetentionDays 失效令牌保留天数。
	TokenRetentionDays int `bun:"token_retention_days,default:30" json:"tokenRetentionDays"`
	// NotificationRetentionDays 已读通知保留天数。
	NotificationRetentionDays int `bun:"notification_retention_days,default:90" json:"notificationRetentionDays"`
	// DeletionRequestRetentionDays 已完结的注销申请保留天数。
	DeletionRequestRetentionDays int       `bun:"deletion_request_retention_days,default:180" json:"deletionRequestRetentionDays"`
	UpdatedAt                    time.Time `bun:"updated_at," json:"updatedAt"`
}

// DeviceAuthorization 是 RFC 8628 设备授权流的待确认授权请求。
//
// 流程：客户端先申请 device_code + user_code，引导用户在浏览器上输入
// user_code 完成确认，客户端在此期间按 interval 轮询令牌端点，
// 直到拿到令牌或授权被拒绝/过期。
type DeviceAuthorization struct {
	bun.BaseModel `bun:"table:device_authorizations,alias:da"`

	// DeviceCode 客户端轮询用的凭据（不展示给用户）。
	DeviceCode string `bun:"device_code,pk" json:"-"`
	// UserCode 展示给用户的短码（大写字母数字，便于输入）。
	UserCode string `bun:"user_code,unique,notnull" json:"userCode"`
	// ClientID 发起授权的 OAuth 客户端。
	ClientID string `bun:"client_id,notnull" json:"clientId"`
	// Scope 请求的权限范围。
	Scope string `bun:"scope" json:"scope"`
	// Status: pending | approved | denied | expired。
	Status string `bun:"status,notnull" json:"status"`
	// UserID 确认授权的用户（pending 时为 0）。
	UserID int64 `bun:"user_id" json:"userId"`
	// Interval 建议轮询间隔（秒）。
	Interval   int        `bun:"interval,notnull" json:"interval"`
	ExpiresAt  time.Time  `bun:"expires_at,notnull" json:"expiresAt"`
	ApprovedAt *time.Time `bun:"approved_at" json:"approvedAt,omitempty"`
	CreatedAt  time.Time  `bun:"created_at," json:"createdAt"`
}

// 设备授权状态常量。
const (
	DeviceAuthPending  = "pending"
	DeviceAuthApproved = "approved"
	DeviceAuthDenied   = "denied"
	DeviceAuthExpired  = "expired"
)

// OAuthScope 是可选的 OAuth 权限项，管理后台可逐项启停。
type OAuthScope struct {
	bun.BaseModel `bun:"table:oauth_scopes,alias:os"`

	// Name 权限标识（如 openid / email / profile）。
	Name string `bun:"name,pk" json:"name"`
	// DisplayName 展示名称。
	DisplayName string `bun:"display_name" json:"displayName"`
	// Description 权限说明。
	Description string `bun:"description" json:"description"`
	// Enabled 关闭后授权请求中的该 scope 会被剔除。
	Enabled bool `bun:"enabled,default:true" json:"enabled"`
	// Required 标记基础权限（如 openid），不允许关闭。
	Required  bool      `bun:"required,default:false" json:"required"`
	UpdatedAt time.Time `bun:"updated_at," json:"updatedAt"`
}

// ProxySetting 是单行出站代理配置（管理后台「系统设置 → 系统设置」维护）。
//
// 注意：这里的配置只是「可用配置项」，不全局生效——仅对在登录提供商中
// 显式开启「使用代理」的第三方提供商生效（见 OAuthProvider.UseProxy）。
type ProxySetting struct {
	bun.BaseModel `bun:"table:proxy_settings,alias:ps"`

	ID int64 `bun:"id,pk,autoincrement" json:"id"`
	// Protocol 代理协议：http / https / socks5。
	Protocol string `bun:"protocol" json:"protocol"`
	// Host 代理服务器地址（IP 或域名）。
	Host string `bun:"host" json:"host"`
	// Port 代理端口。
	Port int `bun:"port" json:"port"`
	// Username / Password 代理认证信息（Password 密文落库）。
	Username string `bun:"username" json:"username"`
	Password string `bun:"password" json:"-"`
	// Enabled 是否启用该代理配置（总开关，便于临时停用而不清空配置）。
	Enabled   bool      `bun:"enabled,default:false" json:"enabled"`
	UpdatedAt time.Time `bun:"updated_at," json:"updatedAt"`
}

// ProxyURL 渲染代理的连接 URL（password 需调用方解密后传入）。
func (p *ProxySetting) ProxyURL(plainPassword string) string {
	if p == nil || p.Host == "" || p.Port == 0 {
		return ""
	}
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	if proto == "" {
		proto = "http"
	}
	if p.Username != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", proto, url.QueryEscape(p.Username), url.QueryEscape(plainPassword), p.Host, p.Port)
	}
	return fmt.Sprintf("%s://%s:%d", proto, p.Host, p.Port)
}

// SmsSetting stores SMS verification-code service configuration (single row).
//
// 短信验证码用于确认用户手机号的归属。配置做成多服务商可切换的单行配置，
// 与人机验证（CaptchaSetting）保持同一套交互：切换服务商后只展示该服务商
// 需要的字段。凭据经 secretpkg 加密后落库。
type SmsSetting struct {
	bun.BaseModel `bun:"table:sms_settings,alias:ss"`

	ID int64 `bun:"id,pk,autoincrement" json:"id"`
	// Enabled 总开关：关闭时不允许发送验证码，用户仍可填写手机号但恒为未验证。
	Enabled bool `bun:"enabled,default:false" json:"enabled"`
	// Provider 当前启用的服务商：aliyun | tencent | volcengine | huawei |
	// qimo | submail | custom | none。
	Provider string `bun:"provider" json:"provider"`
	// SiteName 短信签名/应用名（各服务商通用）。
	SiteName string `bun:"site_name" json:"siteName"`
	// CodeTTL / Cooldown 验证码有效期（分钟）与发送冷却（秒）。
	CodeTTL  int `bun:"code_ttl" json:"codeTtl"`
	Cooldown int `bun:"cooldown" json:"cooldown"`

	// 阿里云号码认证服务（dypnsapi）。密钥加密存储。
	AliyunAccessKeyID     string `bun:"aliyun_access_key_id" json:"aliyunAccessKeyId"`
	AliyunAccessKeySecret string `bun:"aliyun_access_key_secret" json:"-"`
	AliyunSignName        string `bun:"aliyun_sign_name" json:"aliyunSignName"`
	AliyunTemplateCode    string `bun:"aliyun_template_code" json:"aliyunTemplateCode"`
	AliyunEndpoint        string `bun:"aliyun_endpoint" json:"aliyunEndpoint"`

	// 腾讯云短信。
	TencentSecretID  string `bun:"tencent_secret_id" json:"tencentSecretId"`
	TencentSecretKey string `bun:"tencent_secret_key" json:"-"`
	TencentSdkAppID  string `bun:"tencent_sdk_app_id" json:"tencentSdkAppId"`
	TencentSignName  string `bun:"tencent_sign_name" json:"tencentSignName"`
	TencentTemplate  string `bun:"tencent_template_id" json:"tencentTemplateId"`
	TencentRegion    string `bun:"tencent_region" json:"tencentRegion"`

	// 火山引擎短信。
	VolcAccessKeyID     string `bun:"volc_access_key_id" json:"volcAccessKeyId"`
	VolcAccessKeySecret string `bun:"volc_access_key_secret" json:"-"`
	VolcSmsAccount      string `bun:"volc_sms_account" json:"volcSmsAccount"`
	VolcSign            string `bun:"volc_sign" json:"volcSign"`
	VolcTemplateID      string `bun:"volc_template_id" json:"volcTemplateId"`
	VolcRegion          string `bun:"volc_region" json:"volcRegion"`

	// 华为云短信。
	HuaweiAppKey    string `bun:"huawei_app_key" json:"huaweiAppKey"`
	HuaweiAppSecret string `bun:"huawei_app_secret" json:"-"`
	HuaweiSender    string `bun:"huawei_sender" json:"huaweiSender"`
	HuaweiTemplate  string `bun:"huawei_template_id" json:"huaweiTemplateId"`
	HuaweiEndpoint  string `bun:"huawei_endpoint" json:"huaweiEndpoint"`

	// 容联七陌。
	QimoAccountSID string `bun:"qimo_account_sid" json:"qimoAccountSid"`
	QimoAuthToken  string `bun:"qimo_auth_token" json:"-"`
	QimoAppID      string `bun:"qimo_app_id" json:"qimoAppId"`
	QimoTemplate   string `bun:"qimo_template_id" json:"qimoTemplateId"`

	// SUBMAIL。
	SubmailAppID    string `bun:"submail_app_id" json:"submailAppId"`
	SubmailAppKey   string `bun:"submail_app_key" json:"-"`
	SubmailSign     string `bun:"submail_sign" json:"submailSign"`
	SubmailTemplate string `bun:"submail_template_id" json:"submailTemplateId"`

	// 自定义 HTTP 网关：以通用协议对接任意厂商。
	CustomURL     string `bun:"custom_url" json:"customUrl"`
	CustomMethod  string `bun:"custom_method" json:"customMethod"`
	CustomHeaders string `bun:"custom_headers" json:"customHeaders"`
	CustomBody    string `bun:"custom_body" json:"customBody"`
	CustomSecret  string `bun:"custom_secret" json:"-"`

	UpdatedAt time.Time `bun:"updated_at," json:"updatedAt"`
}
