package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/h1s97x/openidp/api/internal/timezone"
)

// DefaultDatabasePassword 是 PostgreSQL 的内置默认口令，
// 与 docker-compose 的 POSTGRES_PASSWORD 默认值保持一致，保证首次部署开箱即用。
// 生产环境务必覆盖为强口令。
const DefaultDatabasePassword = "openidp123"

// EnvPrefix 是环境变量统一前缀。所有配置项统一使用 `OPENIDP_*` 前缀写法。
const EnvPrefix = "OPENIDP_"

// Config holds all runtime configuration.
type Config struct {
	// Addr is the listen address for the HTTP server.
	Addr string
	// DatabaseURL empty => SQLite (default dev); non-empty => PostgreSQL 17.
	// 由 FromEnv 组装：优先使用显式 DATABASE_URL，其次根据 DATABASE_TYPE/HOST/...
	// 结构化变量组装，均未配置时为空（SQLite 自动降级）。
	DatabaseURL string
	// ---- 结构化数据库变量（用于组装 DatabaseURL）----
	// DatabaseType: "postgres" 表示使用 PostgreSQL；空/其他则降级 SQLite。
	DatabaseType     string
	DatabasePassword string
	// DataDir is where SQLite file lives when DatabaseURL is empty.
	DataDir string
	// ---- 运行日志 ----
	// LogDir 是运行日志目录，默认 <DataDir>/log。
	// 置为 "-" 可关闭文件日志（仅输出到 stderr）。
	LogDir string
	// LogFileEnabled 控制是否写日志文件。容器化部署若已有日志采集，
	// 可关闭以避免重复落盘。
	LogFileEnabled bool
	// LogRetentionDays 是日志保留天数，启动时清理更早的文件。
	LogRetentionDays int
	// LogMaxSizeMB 是单个日志文件上限，超出后自动切分。
	LogMaxSizeMB int
	// LogLevel 是日志级别：debug / info / warn / error / off，默认 info。
	LogLevel string
	// Timezone 是系统时区（IANA 名称，如 Asia/Shanghai / UTC）。
	// 后端与前端日志、界面展示的时间以及按天统计的日界都以它为准。
	Timezone string
	// ---- 分类日志开关 ----
	// AccessLogEnabled 控制是否记录 HTTP 访问日志。
	// 高流量站点可关闭以减少 I/O，排障时再开启。
	AccessLogEnabled bool
	// AuditLogEnabled 控制是否记录安全审计日志（登录、改密、MFA 等）。
	AuditLogEnabled bool
	// ConfigLogEnabled 控制是否记录配置变更日志。
	ConfigLogEnabled bool
	// AccessLogSkipHealth 控制访问日志是否跳过健康检查端点。
	// 健康检查由容器/编排频繁调用，记录价值低却会显著放大日志量。
	AccessLogSkipHealth bool
	// ---- Redis（共享缓存，可选；未配置或不可用时自动降级为内存缓存）----
	// RedisAddr 为空或连接失败 => 使用进程内内存缓存。
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	// SessionCookieName, DeviceCookieName
	SessionCookieName string
	DeviceCookieName  string
	// OAuthStateCookieName 是第三方登录发起授权时下发的 state 绑定 cookie。
	// 授权回调必须携带同一 cookie 值才能消费 state，防止"攻击者在自己浏览器发起
	// 三方登录、截获回调 URL 后诱导受害者点击"造成的登录 CSRF / 会话注入。
	OAuthStateCookieName string
	// CSRFHeader is the header used to verify CSRF tokens.
	CSRFHeader string
	// Site branding
	SiteName       string
	SiteDisplay    string
	SiteLogo       string
	SiteFavicon    string
	SessionTTLDays int
	DeviceTTLDays  int
	// JWT RSA key persistence dir (empty => generate in-memory)
	JWTKeyDir string
	// DBFallback 控制 PostgreSQL 不可用时是否降级到 SQLite。
	// 默认 "fail-fast"：生产环境 PG 故障时应立即失败，避免静默切到空的 SQLite
	// 造成用户数据"消失"与双库数据分裂；显式设为 "sqlite" 才允许降级。
	DBFallback string

	// ---- Extended: SMTP 邮件 ----
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPFromName string
	// SMTPUseTLS enables explicit STARTTLS (for ports other than 465).
	SMTPUseTLS bool
	// SMTPInsecureSkipVerify disables TLS certificate verification (dev/testing).
	SMTPInsecureSkipVerify bool
	// SMTPTemplate is a customizable HTML email template (empty = built-in default).
	SMTPTemplate string

	// ---- Extended: 人机验证（管理后台可配置，env 为默认值）----
	// CaptchaProvider: turnstile | geetest | none（空 = none/自动）
	CaptchaProvider string

	// ---- Extended: 站点 URL（验证码/邮件链接用） ----
	SiteURL string

	// ---- Extended: WebAuthn RP ----
	// WebAuthnOrigin 是通行密钥允许的来源（仅用于启动日志告警与 RPID 推导）。
	WebAuthnOrigin string
	// WebAuthnRPName 是通行密钥依赖方显示名称。
	WebAuthnRPName string

	// ---- Extended: GeeTest（见 internal/captcha）----
	GeetestCaptchaID         string
	GeetestCaptchaKey        string
	GeetestRequiredForLogin  bool
	GeetestRequiredForSignup bool
	GeetestAPIDomain         string
	GeetestBindMode          string // bind（滑动验证·绑定）/ popup / float

	// ---- Extended: Cloudflare Turnstile（见 internal/captcha）----
	// 与极验并存：优先 Turnstile，未配置时回退到 GeeTest。
	TurnstileSiteKey           string
	TurnstileSecretKey         string
	TurnstileRequiredForLogin  bool
	TurnstileRequiredForSignup bool
	TurnstileVerifyURL         string

	// ---- Extended: 前后端分离部署 ----
	// CORSAllowedOrigins: 允许跨域访问 API 的前端源（逗号分隔，如 https://auth.example.com）。
	// 空则同源部署，不输出 CORS 头。
	CORSAllowedOrigins []string
	// DevFrontendURL 是开发模式下前端 Vite dev server 的地址（如 http://localhost:5173）。
	// 仅当非空时启用：rootHandler 会把所有非 API/OIDC 的页面请求反向代理到该地址，
	// 实现「Go 单端口统一入口」（:6099）驱动前端热更新，与生产内嵌模式行为一致。
	// 生产环境保持为空（内嵌 SPA），不启用代理。
	DevFrontendURL string
	// TrustProxy: 是否解析反向代理/CDN 传递的客户端 IP（X-Forwarded-For / CDN 专用头）。
	//
	// 默认 true：OpenIdP 的典型部署形态是「用户 → CDN（EdgeOne/ESA/Cloudflare）
	// → 反向代理（Nginx）→ OpenIdP」，服务几乎总是位于代理之后，若不解析转发头，
	// 限流、审计、归属地都会退化成反代/网关的 IP，因此默认开启以拿到真实客户端 IP。
	//
	// 安全性由「可信对端」保证，而非由开关保证：开启后仍要求 TCP 对端落在可信
	// 网段（默认为回环 + RFC1918 私网 + IPv6 ULA，可用 OPENIDP_TRUSTED_PROXIES 扩充）
	// 内才采信转发头；不满足时一律回退到 TCP 对端地址，公网直连伪造转发头无效。
	//
	// 若部署环境可能被任意内网主机（同 VPC、K8s 同集群、内网跳板）直连应用端口，
	// 应显式设为 none/0/false/off 关闭，避免攻击者从内网跳板伪造 CF-Connecting-IP
	// 绕过按 IP 限流的端点（验证码、上传、OAuth、设备码等）。
	TrustProxy bool
	// ClientIPHeader: 优先使用的客户端 IP 请求头（如 EO-Client-IP / CF-Connecting-IP / ali-real-client-ip）。
	// 留空使用默认值 CF-Connecting-IP；除本头外还会按固定顺序嗅探常见 CDN 专用头。
	ClientIPHeader string
	// TrustedProxies: 额外可信的代理网段（CIDR 或裸 IP，逗号分隔），
	// 与默认的「回环 + 内网网段」合并。例如填入 CDN 官方公布的回源网段，
	// 用于 CDN 节点直连应用（无第二层反代）的部署形态。
	TrustedProxies []string
	// CookieSecure 控制会话/设备 Cookie 的 Secure 标志。
	// true/false 显式指定；auto（默认）根据 SiteURL 是否 https 推导，
	// 避免依据客户端可控的 Host 头判断（防降级劫持）。
	CookieSecure string
	// CookieSameSite 控制会话/设备 Cookie 的 SameSite 属性（auto/lax/strict/none）。
	//
	// auto（默认）：配置了 CORS_ALLOWED_ORIGINS（前后端分离的跨源部署）时为 none，
	// 否则为 lax。跨**站**部署下浏览器不会在 fetch 中携带 Lax Cookie，
	// 表现为「接口能调通但始终是未登录」。
	CookieSameSite string
	// SetupAllowRemote 允许从非本机 IP 执行首次初始化（setup）。
	// 默认 true：允许从任意 IP 访问初始化端点，便于远程/云环境部署时初始化。
	SetupAllowRemote bool
	// CDNBaseURL 是前端静态资源（字体 CSS / 字体文件）的 CDN 基址。
	//
	// 默认留空：OpenIdP 不绑定任何第三方 CDN，开箱即用时不下发该域（CSP 仅保留
	// 'self'），因此不会产生任何外部请求，可直接用于内网 / 离线环境。
	// 需要自建字体 CDN 时显式配置；置为 "-" 与留空等价（不输出该域）。
	CDNBaseURL string

	// EncryptionKey 是应用层加密密钥（32 字节，hex/base64），用于加密数据库中
	// 的敏感字段（OAuth ClientSecret、SMTP 密码、验证码密钥、TOTP 密钥）。
	// 为空则回退为明文存储（仅建议开发环境）。
	EncryptionKey string

	// ---- Extended: OAuth providers ----
	// 内置社交登录默认关闭（需在管理后台配置 ClientID/Secret 后启用）。
	// 以下变量用于给 seed 填充默认 ClientID/Secret（便于一键接入）。
	ProviderClientIDs     map[string]string // providerType -> clientID
	ProviderClientSecrets map[string]string // providerType -> clientSecret

	// ---- Extended: 对象存储（头像/上传文件）----
	// StorageBackend: local（默认）| s3。
	StorageBackend string
	// Local 存储：基础目录与 URL 前缀。
	StorageLocalDir string
	// S3 兼容存储连接参数。
	StorageS3Endpoint string
	StorageS3Bucket   string
	StorageS3Region   string
	// StorageS3Prefix 是对象 key 的统一前缀（可选，便于多站点共用同一存储桶）。
	StorageS3Prefix        string
	StorageS3KeyID         string
	StorageS3Secret        string
	StorageS3PublicBaseURL string

	// ---- Extended: Webhook 通知 - WebhookURLs 逗号分隔的接收端点；WebhookSecret 用于签名。 ----
	WebhookURLs   []string
	WebhookSecret string
}

// FromEnv builds a Config from the environment.
// 所有配置项统一使用 `OPENIDP_*` 前缀写法。
func FromEnv() *Config {
	// 数据库连接：显式 DATABASE_URL 优先级最高；否则由结构化变量组装。
	// 两者均未配置 => 自动降级 SQLite（空 DatabaseURL）。
	dbURL := env("DATABASE_URL")
	if dbURL == "" {
		dbURL = assembleDatabaseURL(
			env("DATABASE_TYPE"),
			env("DATABASE_HOST"),
			env("DATABASE_USER"),
			env("DATABASE_NAME"),
			env("DATABASE_PORT"),
			env("DATABASE_PASSWORD"),
			envOr("DATABASE_SSL_MODE", "disable"),
		)
	}
	c := &Config{
		Addr:         envOr("ADDR", ":6099"),
		DatabaseURL:  dbURL,
		DatabaseType: env("DATABASE_TYPE"),
		// 密码默认值 DefaultDatabasePassword 与 docker-compose 的 POSTGRES_PASSWORD 默认值保持一致，
		// 保证启用 PostgreSQL 时应用端与 pgsql 容器初始化密码始终匹配，无需额外设置。
		DatabasePassword: envOr("DATABASE_PASSWORD", DefaultDatabasePassword),
		DataDir:          envOr("DATA_DIR", "./data"),
		// 日志目录默认落在数据目录下，便于统一挂载与备份；
		// 设为 "-" 表示不写文件（只输出到 stderr，适合已有日志采集的环境）。
		LogDir:           envOr("LOG_DIR", ""),
		LogFileEnabled:   envBool("LOG_FILE_ENABLED", true),
		LogRetentionDays: envInt("LOG_RETENTION_DAYS", 7),
		LogMaxSizeMB:     envInt("LOG_MAX_SIZE_MB", 64),
		LogLevel:         envOr("LOG_LEVEL", "info"),
		// 系统时区默认 UTC+8（Asia/Shanghai），可用 OPENIDP_TIMEZONE 指定任意 IANA 时区。
		Timezone:             envOr("TIMEZONE", timezone.DefaultName),
		AccessLogEnabled:     envBool("ACCESS_LOG_ENABLED", true),
		AuditLogEnabled:      envBool("AUDIT_LOG_ENABLED", true),
		ConfigLogEnabled:     envBool("CONFIG_LOG_ENABLED", true),
		AccessLogSkipHealth:  envBool("ACCESS_LOG_SKIP_HEALTH", true),
		RedisAddr:            env("REDIS_ADDR"),
		RedisPassword:        env("REDIS_PASSWORD"),
		RedisDB:              envInt("REDIS_DB", 0),
		SessionCookieName:    envOr("SESSION_COOKIE", "openidp_session"),
		DeviceCookieName:     envOr("DEVICE_COOKIE", "openidp_device_id"),
		OAuthStateCookieName: envOr("OAUTH_STATE_COOKIE", "openidp_oauth_state"),
		CSRFHeader:           envOr("CSRF_HEADER", "X-OpenIdP-CSRF"),
		SiteName:             envOr("SITE_NAME", "openidp"),
		SiteDisplay:          envOr("SITE_DISPLAY", "OpenIdP"),
		// 内置品牌资源：站点 Logo 与 Favicon 共用同一份矢量图（public/images/logo.svg），
		// 未配置时回落到它，保证开箱即用。
		SiteLogo:       envOr("SITE_LOGO", "/images/logo.svg"),
		SiteFavicon:    envOr("SITE_FAVICON", "/images/logo.svg"),
		SessionTTLDays: envInt("SESSION_TTL_DAYS", 14),
		DeviceTTLDays:  envInt("DEVICE_TTL_DAYS", 365),
		JWTKeyDir:      env("JWT_KEY_DIR"),
		DBFallback:     envOr("DB_FALLBACK", "fail-fast"),

		SMTPHost:               env("SMTP_HOST"),
		SMTPPort:               envInt("SMTP_PORT", 465),
		SMTPUser:               env("SMTP_USER"),
		SMTPPassword:           env("SMTP_PASSWORD"),
		SMTPFrom:               envOr("SMTP_FROM", "noreply@example.com"),
		SMTPFromName:           envOr("SMTP_FROM_NAME", "OpenIdP"),
		SMTPUseTLS:             envBool("SMTP_USE_TLS", false),
		SMTPInsecureSkipVerify: envBool("SMTP_INSECURE_SKIP_VERIFY", false),
		SMTPTemplate:           env("SMTP_TEMPLATE"),
		SiteURL:                envOr("SITE_URL", "http://localhost:6099"),

		CaptchaProvider: envOr("CAPTCHA_PROVIDER", ""),

		WebAuthnOrigin: envOr("WEBAUTHN_ORIGIN", "http://localhost:6099"),
		WebAuthnRPName: envOr("WEBAUTHN_RP_NAME", "OpenIdP"),

		GeetestCaptchaID:         env("GEETEST_CAPTCHA_ID"),
		GeetestCaptchaKey:        env("GEETEST_CAPTCHA_KEY"),
		GeetestRequiredForLogin:  envBool("GEETEST_REQUIRED_FOR_LOGIN", false),
		GeetestRequiredForSignup: envBool("GEETEST_REQUIRED_FOR_SIGNUP", false),
		GeetestAPIDomain:         env("GEETEST_API_DOMAIN"),
		GeetestBindMode:          envOr("GEETEST_BIND_MODE", "bind"),

		TurnstileSiteKey:           env("TURNSTILE_SITE_KEY"),
		TurnstileSecretKey:         env("TURNSTILE_SECRET_KEY"),
		TurnstileRequiredForLogin:  envBool("TURNSTILE_REQUIRED_FOR_LOGIN", false),
		TurnstileRequiredForSignup: envBool("TURNSTILE_REQUIRED_FOR_SIGNUP", false),
		TurnstileVerifyURL:         env("TURNSTILE_VERIFY_URL"),

		CORSAllowedOrigins: splitCSV(env("CORS_ALLOWED_ORIGINS")),
		DevFrontendURL:     env("DEV_FRONTEND_URL"),
		TrustProxy:         resolveTrustProxy(),
		ClientIPHeader:     envOr("CLIENT_IP_HEADER", "CF-Connecting-IP"),
		TrustedProxies:     splitCSV(env("TRUSTED_PROXIES")),
		CookieSecure:       envOr("COOKIE_SECURE", "auto"),
		CookieSameSite:     envOr("COOKIE_SAME_SITE", "auto"),
		SetupAllowRemote:   envBool("SETUP_ALLOW_REMOTE", true),
		// 默认留空 => 不引入任何外部 CDN 依赖；设为 "-" 与留空等价。
		CDNBaseURL: envOr("CDN_BASE_URL", ""),

		ProviderClientIDs:     map[string]string{},
		ProviderClientSecrets: map[string]string{},
		EncryptionKey:         env("ENCRYPTION_KEY"),

		StorageBackend:         envOr("STORAGE_BACKEND", "local"),
		StorageLocalDir:        envOr("STORAGE_LOCAL_DIR", ""),
		StorageS3Endpoint:      env("STORAGE_S3_ENDPOINT"),
		StorageS3Bucket:        env("STORAGE_S3_BUCKET"),
		StorageS3Region:        envOr("STORAGE_S3_REGION", "us-east-1"),
		StorageS3Prefix:        env("STORAGE_S3_PREFIX"),
		StorageS3KeyID:         env("STORAGE_S3_KEY_ID"),
		StorageS3Secret:        env("STORAGE_S3_SECRET"),
		StorageS3PublicBaseURL: env("STORAGE_S3_PUBLIC_BASE_URL"),

		WebhookURLs:   splitCSV(env("WEBHOOK_URLS")),
		WebhookSecret: env("WEBHOOK_SECRET"),
	}
	// CaptchaProvider 未显式指定时：两者都配置优先 turnstile，仅其一则用其本身。
	if c.CaptchaProvider == "" {
		switch {
		case c.TurnstileSiteKey != "" && c.TurnstileSecretKey != "":
			c.CaptchaProvider = "turnstile"
		case c.GeetestCaptchaID != "" && c.GeetestCaptchaKey != "":
			c.CaptchaProvider = "geetest"
		default:
			c.CaptchaProvider = "none"
		}
	}
	loadProviderSecrets(c)
	return c
}

// assembleDatabaseURL builds a DSN from structured env vars.
// Returns "" (=> SQLite 降级) when type is not supported or host is missing.
// Supported types: postgres, mysql, mariadb.
func assembleDatabaseURL(dbType, host, user, name, port, password, sslMode string) string {
	lower := strings.ToLower(dbType)
	switch lower {
	case "postgres":
		if host == "" || user == "" || name == "" {
			return ""
		}
		if port == "" {
			port = "5432"
		}
		if sslMode == "" {
			sslMode = "disable"
		}
		return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
			urlQueryEscape(user), urlQueryEscape(password), host, port, name, sslMode)
	case "mysql", "mariadb":
		if host == "" || user == "" || name == "" {
			return ""
		}
		if port == "" {
			port = "3306"
		}
		// MySQL DSN (go-sql-driver): user:pass@tcp(host:port)/dbname?parseTime=true
		return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4",
			urlQueryEscape(user), urlQueryEscape(password), host, port, name)
	default:
		// 未配置或指定非支持类型（如 sqlite）=> 自动降级 SQLite
		return ""
	}
}

// urlQueryEscape 对连接串中需要转义的片段做 URL 编码（避免特殊字符破坏 DSN）。
func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

// Getenv 读取带统一前缀的环境变量（OPENIDP_<key>），未设置时返回空串。
//
// 供无法持有完整 Config 的包使用：geo 在包初始化阶段读取自身的缓存 TTL 与
// 外部数据源开关，db 的集成测试读取 DSN。这些场景拿不到 Config 实例，
// 但前缀必须与主配置保持一致——若各自硬编码字符串，一旦改名就会出现
// 「主配置读新前缀、个别包仍读旧前缀」的静默失配。
func Getenv(key string) string {
	return os.Getenv(EnvPrefix + key)
}

// env returns the value of the prefixed `OPENIDP_<k>` variable.
// Empty if not set.
func env(k string) string {
	return Getenv(k)
}

// envOr returns the resolved env value, or def when unset/empty.
// siteURLPlaceholderDefault 与 FromEnv 中 SITE_URL 的默认值保持一致。
const siteURLPlaceholderDefault = "http://localhost:6099"

// SiteURLIsPlaceholder 判断 SiteURL 是否仍为未配置的占位值（默认值或空）。
// issuer() 与 requestBaseURL() 等需要"是否显式配置了公网地址"判定的地方
// 统一使用本函数，避免各处前缀判断逻辑漂移不一致。
func (c *Config) SiteURLIsPlaceholder() bool {
	u := strings.TrimRight(c.SiteURL, "/")
	return u == "" || u == siteURLPlaceholderDefault
}

func envOr(k, def string) string {
	if v := env(k); v != "" {
		return v
	}
	return def
}

// envInt resolves the prefixed `OPENIDP_<k>` env variable to an int.
func envInt(k string, def int) int {
	if v := env(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envBool resolves the prefixed `OPENIDP_<k>` env variable to a bool.
// resolveTrustProxy 解析 TRUST_PROXY 配置。
//
// 默认开启（true）：OpenIdP 通常部署在 CDN / 反向代理之后，需要解析转发头
// 才能拿到真实客户端 IP，否则限流、审计、归属地会全部退化为代理自身 IP。
//
// 默认值取 true 并不等于「无条件信任转发头」——是否采信仍由 TCP 对端是否落在
// 可信网段决定（见 middleware 包的 defaultTrustedProxyCIDRs），因此直接公网
// 暴露时伪造转发头不会生效。
//
// 仅在「服务可能被任意内网主机直连」的场景下才需要显式关闭：
// OPENIDP_TRUST_PROXY=none / 0 / false / off。
func resolveTrustProxy() bool {
	v := env("TRUST_PROXY")
	if v == "none" || v == "NONE" || v == "None" {
		return false
	}
	return envBool("TRUST_PROXY", true)
}

func envBool(k string, def bool) bool {
	switch v := env(k); v {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	case "0", "false", "FALSE", "False", "no", "off":
		return false
	}
	return def
}

// splitCSV splits a comma-separated env value into trimmed non-empty items.
func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// loadProviderSecrets reads per-provider OAuth credentials from env vars:
//
//	GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
//	GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
//	MICROSOFT_CLIENT_ID / MICROSOFT_CLIENT_SECRET
//	QQ_CLIENT_ID / QQ_CLIENT_SECRET
//	GITEE_CLIENT_ID / GITEE_CLIENT_SECRET
//	LINUXDO_CLIENT_ID / LINUXDO_CLIENT_SECRET
//
// 统一使用 `OPENIDP_` 前缀写法。
func loadProviderSecrets(c *Config) {
	providers := []string{"github", "google", "microsoft", "qq", "gitee", "linuxdo"}
	for _, p := range providers {
		upper := strings.ToUpper(p)
		cid := env(upper + "_CLIENT_ID")
		csec := env(upper + "_CLIENT_SECRET")
		if cid != "" {
			c.ProviderClientIDs[p] = cid
		}
		if csec != "" {
			c.ProviderClientSecrets[p] = csec
		}
	}
}
