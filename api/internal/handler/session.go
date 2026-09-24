package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uptrace/bun"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/cache"
	"github.com/h1s97x/openidp/api/internal/captcha"
	"github.com/h1s97x/openidp/api/internal/config"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/event"
	"github.com/h1s97x/openidp/api/internal/geolocation"
	"github.com/h1s97x/openidp/api/internal/logging"
	"github.com/h1s97x/openidp/api/internal/mail"
	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oidc"
	"github.com/h1s97x/openidp/api/internal/passkey"
	"github.com/h1s97x/openidp/api/internal/sms"
	"github.com/h1s97x/openidp/api/internal/storage"
	"github.com/h1s97x/openidp/api/internal/timezone"
	"github.com/h1s97x/openidp/api/internal/webhook"
)

// defaultAvatarURL 是系统内置默认头像（web/public/images/avatar.svg）。
//
// 用户未上传头像、或主动重置头像时回落到它。此前这个字面量散落在
// setup.go / session_ext.go / me_ext.go / admin.go 共 5 处，
// 一旦改名或换路径极易漏改，故收敛为单一常量。
const defaultAvatarURL = "/images/avatar.svg"

// Handler bundles dependencies for HTTP handlers.
type Handler struct {
	db   *bun.DB
	cfg  *config.Config
	oidc *oidcHolder

	// cache 是共享缓存（Redis 可用时使用，否则自动降级为内存实现）。
	// 它支撑 tokens、限流器、consent 缓存与 GeoIP 结果缓存。
	cache cache.Cache
	// tokens is a concurrency-safe store for CSRF tokens, one-time provider
	// proofs and OAuth state tokens (TTL-bounded, backed by cache).
	tokens *middleware.TokenStore

	// mailer sends emails (dev mode when no SMTP configured)
	mailer *mail.Sender
	// captcha verifies GeeTest v4 proofs (no-op when unconfigured).
	// 用原子指针持有：管理员保存配置与并发登录会同时读写，普通字段会构成数据竞争。
	captcha atomic.Pointer[captcha.Config]
	// turnstile verifies Cloudflare Turnstile tokens (preferred when configured).
	turnstile atomic.Pointer[captcha.TurnstileConfig]
	// sms 是短信验证码服务（用于手机号归属验证；未配置时为空实现）。
	sms atomic.Pointer[sms.Config]
	// smsSendHookForTest 仅供测试注入，用于拦截真实短信发送。
	smsSendHookForTest func(phone, code string) (string, error)
	// passkeys runs WebAuthn ceremonies
	passkeys *passkey.Service

	// loginLimiter 与 codeLimiter 是限流器，保护登录/验证码端点防爆破（Redis 共享计数，降级为内存）。
	loginLimiter *middleware.RateLimiter
	codeLimiter  *middleware.RateLimiter
	// accountLimiter 按账号（用户名/邮箱）维度限流登录，防止分布式爆破绕过单 IP 限制。
	accountLimiter *middleware.RateLimiter
	// oauthLimiter 限流 OAuth 令牌端点（access_token / introspect / revoke），
	// 防止无限爆破 client_secret / refresh token。
	oauthLimiter *middleware.RateLimiter
	// adminLimiter 是管理端点的独立限流器（创建用户、改邮件/安全策略、读审计日志等
	// 高危操作）。
	adminLimiter *middleware.RateLimiter
	// uploadLimiter 限流附件上传：这类端点会写磁盘与对象存储，
	// 缺少限流时可被刷爆存储配额。
	uploadLimiter *middleware.RateLimiter
	// avatarLimiter 限流头像上传：与附件上传分开计数，两个场景的合理频次不同，
	// 共用配额时批量传附件会把头像上传顶掉（反之亦然）。
	avatarLimiter *middleware.RateLimiter
	// fileLimiter 限流文件读取：读取端点免鉴权，需防止被当作免费图床刷流量。
	fileLimiter *middleware.RateLimiter
	// setupLimiter 限流首次部署初始化端点，防止被反复调用抢占管理员账号创建。
	setupLimiter *middleware.RateLimiter

	// conf 是单行配置（站点设置 / 安全策略 / 邮件 / 人机验证）的进程内短 TTL 缓存，
	// 避免每个请求重复查库。管理后台写操作后主动失效。
	conf *configCache

	// setupOnce 串行化首次部署初始化，防止并发请求重复创建管理员。
	setupOnce sync.Mutex

	// events 是进程内事件总线，用于解耦认证/安全事件与邮件通知、审计、Webhook 等消费方。
	events *event.Bus

	// store 是对象存储抽象（头像/上传文件），支持本地磁盘与 S3 兼容后端。
	// 与 captcha 同理：管理后台切换存储后端时会整体替换它，读取路径必须无竞争。
	// 用一层 holder 包住接口值：atomic.Pointer 的泛型参数必须是具体类型，
	// 不能直接是接口（会退化成「指向接口的指针」）。
	store atomic.Pointer[storeHolder]

	// webhooks 将安全事件投递给外部系统（自定义 HTTP / 企业微信 / 飞书）。
	webhooks *webhook.Sender
}

// storeHolder 包装一个 storage.Provider，供原子指针持有。
type storeHolder struct{ p storage.Provider }

// ---- 运行期可热替换的组件读取入口 ----
//
// captcha / turnstile / sms / store 都由管理后台在运行期改写（保存配置、
// 切换存储后端），同时又有请求线程在并发读取。统一用原子指针持有的**不可变配置**
// 并通过下面几个访问器读取：
//   - 读路径只取一次指针，之后使用的始终是同一份快照，不会读到「改了一半」的配置；
//   - 写路径构造一份完整副本后整体替换，不原地改字段。
// 这几个访问器在未初始化时返回空的零值配置，调用方无需到处判空。

// captchaCfg 返回当前极验配置快照。
func (h *Handler) captchaCfg() *captcha.Config {
	if c := h.captcha.Load(); c != nil {
		return c
	}
	return &captcha.Config{}
}

// turnstileCfg 返回当前 Turnstile 配置快照。
func (h *Handler) turnstileCfg() *captcha.TurnstileConfig {
	if c := h.turnstile.Load(); c != nil {
		return c
	}
	return &captcha.TurnstileConfig{}
}

// smsCfg 返回当前短信配置快照；未配置时返回零值配置（Enabled=false）。
func (h *Handler) smsCfg() *sms.Config {
	if c := h.sms.Load(); c != nil {
		return c
	}
	return &sms.Config{}
}

// storageProvider 返回当前对象存储 Provider（未初始化时返回 nil）。
func (h *Handler) storageProvider() storage.Provider {
	if hd := h.store.Load(); hd != nil {
		return hd.p
	}
	return nil
}

// setStorageProvider 原子替换对象存储 Provider。
func (h *Handler) setStorageProvider(p storage.Provider) {
	h.store.Store(&storeHolder{p: p})
}

// consentReq 缓存一次尚未确认的 OIDC 授权请求参数，绑定到一次性 ticket。
type consentReq struct {
	ClientID      string    `json:"clientID"`
	RedirectURI   string    `json:"redirectURI"`
	Scope         string    `json:"scope"`
	Nonce         string    `json:"nonce"`
	CodeChallenge string    `json:"codeChallenge"`
	State         string    `json:"state"`
	UserID        int64     `json:"userID"`
	CreatedAt     time.Time `json:"createdAt"`
}

// New creates a Handler. c is the shared cache (Redis or in-memory fallback).
func New(db *bun.DB, cfg *config.Config, oidcProvider *oidc.Provider, c cache.Cache) *Handler {
	h := &Handler{
		db: db, cfg: cfg, cache: c, conf: &configCache{},
		// 事件总线：认证/安全事件在此发布，由邮件通知/审计/Webhook 等 Listener 消费。
		events: event.New(),
		oidc:   &oidcHolder{provider: oidcProvider},
		tokens: middleware.NewTokenStore(c, 30*time.Minute),
		// Webhook 通知：将安全事件异步投递给外部系统。
		webhooks: webhook.New(webhook.Config{URLs: cfg.WebhookURLs, Secret: cfg.WebhookSecret}),
		mailer: mail.New(mail.Config{
			Host: cfg.SMTPHost, Port: cfg.SMTPPort,
			User: cfg.SMTPUser, Password: cfg.SMTPPassword,
			From: cfg.SMTPFrom, FromName: cfg.SMTPFromName,
			SiteName: cfg.SiteDisplay, SiteURL: cfg.SiteURL,
			UseTLS: cfg.SMTPUseTLS, InsecureSkipVerify: cfg.SMTPInsecureSkipVerify,
			Template: cfg.SMTPTemplate,
		}),
		loginLimiter: middleware.NewRateLimiter(c, "login", time.Minute, 10), // 登录尝试：每 IP 每分钟最多 10 次
		codeLimiter:  middleware.NewRateLimiter(c, "code", time.Minute, 20),  // 验证码请求/校验：每 IP 每分钟最多 20 次
		// 每个账号每 15 分钟最多 30 次登录/验证码/二次验证尝试。
		accountLimiter: middleware.NewRateLimiter(c, "account", 15*time.Minute, 30),
		// OAuth 令牌端点：每 IP 每分钟最多 30 次（缩小窗口配额，减缓 client_secret 爆破）。
		oauthLimiter: middleware.NewRateLimiter(c, "oauth", time.Minute, 30),
		// 管理端点：每 IP 每分钟最多 60 次（覆盖高频列表请求，同时限制批量创建用户等）。
		adminLimiter: middleware.NewRateLimiter(c, "admin", time.Minute, 60),
		// 初始化端点：每 IP 每分钟最多 10 次。
		setupLimiter: middleware.NewRateLimiter(c, "setup", time.Minute, 10),
		// 附件上传：每 IP 每分钟最多 20 次（写入磁盘或对象存储）。
		uploadLimiter: middleware.NewRateLimiter(c, "upload", time.Minute, 20),
		// 头像上传：每 IP 每分钟最多 20 次（与附件上传分开计数）。
		avatarLimiter: middleware.NewRateLimiter(c, "avatar", time.Minute, 20),
		// 文件读取：每 IP 每分钟最多 600 次（图片可能一页多张，配额放宽但仍有上限）。
		fileLimiter: middleware.NewRateLimiter(c, "file", time.Minute, 600),
	}
	// 对象存储：默认本地磁盘（DATA_DIR），可切换 S3 兼容后端；
	// 管理后台改动经 InitStorage / applyStorageSetting 热替换。
	h.setStorageProvider(storage.New(storage.Config{
		Backend:         cfg.StorageBackend,
		LocalDir:        auth.FirstNonEmpty(cfg.StorageLocalDir, cfg.DataDir),
		S3Endpoint:      cfg.StorageS3Endpoint,
		S3Bucket:        cfg.StorageS3Bucket,
		S3Region:        cfg.StorageS3Region,
		S3KeyID:         cfg.StorageS3KeyID,
		S3Secret:        cfg.StorageS3Secret,
		S3PublicBaseURL: cfg.StorageS3PublicBaseURL,
	}))
	geetest := &captcha.Config{
		CaptchaID: cfg.GeetestCaptchaID, CaptchaKey: cfg.GeetestCaptchaKey,
		RequiredForLogin: cfg.GeetestRequiredForLogin, RequiredForSignup: cfg.GeetestRequiredForSignup,
		APIDomain: cfg.GeetestAPIDomain,
		BindMode:  cfg.GeetestBindMode,
	}
	geetest.Enabled = geetest.CaptchaID != "" && geetest.CaptchaKey != ""
	h.captcha.Store(geetest)
	ts := &captcha.TurnstileConfig{
		SiteKey: cfg.TurnstileSiteKey, SecretKey: cfg.TurnstileSecretKey,
		RequiredForLogin: cfg.TurnstileRequiredForLogin, RequiredForSignup: cfg.TurnstileRequiredForSignup,
		VerifyURL: cfg.TurnstileVerifyURL,
	}
	ts.Enabled = ts.SiteKey != "" && ts.SecretKey != ""
	h.turnstile.Store(ts)
	// 短信服务：默认未配置（空实现），由管理后台持久化配置后经
	// applySmsSetting 注入实际服务商。
	h.sms.Store(&sms.Config{})
	h.applyPersistedSettings()
	// 归属地解析：应用管理后台配置的自定义库路径（未配置则用内置库）。
	// 该配置此前只被持久化、从不参与解析，填了不会生效。
	if ls := h.loadLocationSetting(); ls != nil {
		geolocation.Configure(ls.DBPath, ls.V6DBPath)
	}
	h.webhooks.Attach(h.events)
	return h
}

// InitPasskeys attaches the WebAuthn service (called after New).
func (h *Handler) InitPasskeys(pk *passkey.Service) {
	h.passkeys = pk
}

// currentUser resolves the authenticated user from the session cookie.
func (h *Handler) currentUser(r *http.Request) (*models.User, *models.Session, error) {
	c, err := r.Cookie(h.cfg.SessionCookieName)
	if err != nil || c.Value == "" {
		return nil, nil, sql.ErrNoRows
	}
	var s models.Session
	// 用摘要查库：数据库只保存 sha256(会话ID)，Cookie 携带原始值，
	// 避免库/备份泄露即可直接劫持所有在线会话。
	err = h.db.NewSelect().Model(&s).Where("session_hash = ?", hashSessionID(c.Value)).Scan(r.Context())
	if err != nil {
		return nil, nil, err
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, nil, sql.ErrNoRows
	}
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", s.UserID).Scan(r.Context()); err != nil {
		return nil, nil, err
	}
	return &u, &s, nil
}

// hashSessionID 返回会话 ID 的 SHA-256 摘要（十六进制）。
// 会话表只存摘要，Cookie 里放原始值：数据库泄露不再等价于会话劫持。
// 算法统一实现在 auth.SessionIDHash，db 包的存量回填复用同一份，避免两处漂移。
func hashSessionID(id string) string {
	return auth.SessionIDHash(id)
}

// rotateSession 在登录成功后轮换会话 ID（防会话固定）：
// 删除请求携带的旧会话记录并清除 Cookie，随后由 issueSession 签发全新会话。
func (h *Handler) rotateSession(r *http.Request) {
	if c, err := r.Cookie(h.cfg.SessionCookieName); err == nil && c.Value != "" {
		_, _ = h.db.NewDelete().Model((*models.Session)(nil)).
			Where("session_hash = ?", hashSessionID(c.Value)).Exec(r.Context())
	}
}

// issueSession creates a session + device and sets cookies.
// method 用于新设备登录通知中展示实际登录方式（password/emailCode/passkey/thirdParty）。
// It returns the created session ID so callers can bind CSRF tokens to it.
func (h *Handler) issueSession(w http.ResponseWriter, r *http.Request, u *models.User, method string) (string, error) {
	now := db.Now()
	devID := ""
	if c, err := r.Cookie(h.cfg.DeviceCookieName); err == nil && c.Value != "" {
		devID = c.Value
	}
	if devID == "" {
		devID = auth.NewID()
	}
	ua := r.UserAgent()
	ip := clientIP(r)
	region := requestRegion(r)
	// 登录成功后轮换会话 ID，防止会话固定攻击（旧会话立即失效）。
	h.rotateSession(r)
	isNewDevice := false
	var dev models.Device
	// 按 (user_id, device_id) 定位设备行：设备标识来自浏览器 cookie，主键是独立的随机值。
	// 历史上主键直接复用了 cookie 值，导致同一浏览器登录第二个账号时
	// 命中「主键相同但归属不同用户」→ 插入冲突 → 登录 500。
	err := h.db.NewSelect().Model(&dev).Where("user_id = ? AND device_id = ?", u.ID, devID).Scan(r.Context())
	if errors.Is(err, sql.ErrNoRows) {
		isNewDevice = true
		dev = models.Device{
			ID:             auth.NewID(),
			DeviceID:       devID,
			UserID:         u.ID,
			UserAgent:      ua,
			FirstIPAddress: ip,
			FirstIPRegion:  region,
			LastIPAddress:  ip,
			LastIPRegion:   region,
			FirstSeenAt:    now,
			LastSeenAt:     now,
		}
		if _, err := h.db.NewInsert().Model(&dev).Exec(r.Context()); err != nil {
			return "", err
		}
	} else if err != nil {
		// 查询出错时不能直接返回：返回 error 会让登录整体失败，而设备记录
		// 只影响「新设备识别」，缺一条记录不该阻断登录。
		logging.Warn("⚠️ [Device] 查询设备记录失败（user=%d, device=%s）: %v", u.ID, devID, err)
	} else {
		dev.LastIPAddress = ip
		dev.LastIPRegion = region
		dev.LastSeenAt = now
		if _, err := h.db.NewUpdate().Model(&dev).WherePK().Exec(r.Context()); err != nil {
			return "", err
		}
	}

	sessID := auth.NewID()
	// 主键直接存摘要，避免原始会话 ID（等价于可用凭据）落库；
	// Cookie 仍携带原始值，校验时对 Cookie 取摘要后按 session_hash / id 查询。
	hash := hashSessionID(sessID)
	s := models.Session{
		ID:          hash,
		SessionHash: hash,
		UserID:      u.ID,
		DeviceID:    devID,
		UserAgent:   ua,
		IPAddress:   ip,
		IPRegion:    region,
		ExpiresAt:   now.AddDate(0, 0, h.effectiveSessionTTLDays()),
		LastSeenAt:  now,
		CreatedAt:   now,
	}
	if _, err := h.db.NewInsert().Model(&s).Exec(r.Context()); err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.SessionCookieName,
		Value:    sessID,
		Path:     "/",
		Expires:  s.ExpiresAt,
		MaxAge:   h.effectiveSessionTTLDays() * 86400,
		HttpOnly: true,
		Secure:   h.cookieSecure(),
		SameSite: h.cookieSameSite(),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.DeviceCookieName,
		Value:    devID,
		Path:     "/",
		Expires:  now.AddDate(0, 0, h.cfg.DeviceTTLDays),
		MaxAge:   h.cfg.DeviceTTLDays * 86400,
		HttpOnly: true,
		Secure:   h.cookieSecure(),
		SameSite: h.cookieSameSite(),
	})

	// 新设备登录通知：站内与邮件是两个独立开关，各自按偏好下发。
	if isNewDevice {
		np := h.loadNotificationPrefs(u.ID)
		summary := fmt.Sprintf("检测到新设备登录（%s · %s）", region, shortUA(ua))
		if np.NewDeviceInApp {
			h.notify(u.ID, "new_device_login", "新设备登录", summary,
				map[string]string{"ipAddress": ip, "ipRegion": region, "method": method})
		}
		// 邮件提醒此前只在偏好里有开关、登录链路从不读取，导致「开了也收不到」。
		// 现在按开关注册异步任务发送：发信是网络操作，不能拖慢登录响应。
		if np.NewDeviceEmail && u.Email != "" && h.mailer.Enabled() {
			go h.sendNewDeviceLoginMail(u, summary, region, ip, ua)
		}
	}
	return sessID, nil
}

// sendNewDeviceLoginMail 异步发送「新设备登录」邮件提醒。
//
// 独立 goroutine + context.Background()：发信耗时不可预测，登录响应不该等它；
// 同时也不能继承请求上下文——请求结束即取消会让邮件永远发不出去。
func (h *Handler) sendNewDeviceLoginMail(u *models.User, summary, region, ip, ua string) {
	siteName := h.cfg.SiteDisplay
	if ss := h.loadSiteSetting(); ss != nil && ss.DisplayName != "" {
		siteName = ss.DisplayName
	}
	body := fmt.Sprintf(
		`<p>您好，%s：</p><p>%s</p><p>IP：%s（%s）<br/>浏览器：%s</p><p>若非本人操作，请立即修改密码并下线其他设备。</p>`,
		htmlEsc(auth.FirstNonEmpty(u.DisplayName, u.Username)), htmlEsc(summary), htmlEsc(ip), htmlEsc(region), htmlEsc(shortUA(ua)))
	if err := h.mailer.Send(u.Email, fmt.Sprintf("【%s】新设备登录提醒", siteName), body); err != nil {
		logging.Warn("⚠️ [Mail] 新设备登录提醒发送失败（user=%d）: %v", u.ID, err)
		return
	}
	h.logEvent(nil, u.ID, &models.Event{Type: "login.new_device_notified", Summary: "已发送新设备登录邮件提醒"})
}

// siteInfo returns branding.
func (h *Handler) siteInfo() map[string]any {
	ss := h.loadSiteSetting()
	logo := ss.LogoURL
	if logo == "" {
		logo = h.cfg.SiteLogo
	}
	favicon := ss.FaviconURL
	if favicon == "" {
		favicon = h.cfg.SiteFavicon
	}
	display := ss.DisplayName
	if display == "" {
		display = h.cfg.SiteDisplay
	}
	langs := ss.Languages
	if len(langs) == 0 {
		langs = []string{"zh-CN", "zh-TW", "ja", "en"}
	}
	// 站点默认语言：未配置时回退简体中文。
	defaultLang := ss.DefaultLanguage
	if !validLanguage(defaultLang) {
		defaultLang = "zh-CN"
	}
	// 系统时区：前端据此渲染所有时间，保证与后端日志/统计日界口径一致。
	z := timezone.ResolveOrDefault(h.cfg.Timezone)
	// 品牌资源会下发给所有访客（favicon 还会写进 <link rel=icon>），
	// 出库前再过滤一次地址协议，防历史数据/直接改库留下奇怪取值。
	logo, _ = sanitizeAssetURL(logo)
	favicon, _ = sanitizeAssetURL(favicon)
	return map[string]any{
		"name":                ss.SiteName,
		"displayName":         display,
		"logo":                logo,
		"logoDark":            logo,
		"favicon":             favicon,
		"languages":           langs,
		"defaultLanguage":     defaultLang,
		"timezone":            z.Name,
		"timezoneLabel":       z.Label,
		"utcOffsetMinutes":    z.OffsetMinutes,
		"avatarUploadEnabled": ss.AvatarUploadEnabled,
		// 页脚三件套：自定义文本 / ICP 备案号 / 公安联网备案号。
		// 此前未下发，导致后台「品牌信息」填了页脚也不生效（只存不显）。
		"footerText":          ss.FooterText,
		"icpBeian":            ss.ICPBeian,
		"publicSecurityBeian": ss.PublicSecurityBeian,
	}
}

// sessionPayload builds the login/session response.
func (h *Handler) sessionPayload(u *models.User, csrf string) map[string]any {
	return map[string]any{
		"csrfToken": csrf,
		"site":      h.siteInfo(),
		"user":      u,
	}
}

// sessionPayloadWithIP includes the current login IP/region so the UI can
// display them (new-device login banner, sessions page, etc).
func (h *Handler) sessionPayloadWithIP(r *http.Request, u *models.User, csrf string) map[string]any {
	payload := h.sessionPayload(u, csrf)
	// 用请求级缓存的归属地，避免同一请求里重复解析（clientIP + regionOf 各算一遍）。
	payload["ipAddress"] = clientIP(r)
	payload["ipRegion"] = requestRegion(r)
	return payload
}

type loginReq struct {
	Login     string          `json:"login"`
	Password  string          `json:"password"`
	ReturnURL string          `json:"returnUrl"`
	Captcha   *unifiedCaptcha `json:"captcha"`
}

// dummyPasswordHash 是一个真实生成的合法 bcrypt 哈希（cost 12），用于在“用户不存在”
// 时也执行一次完整的 bcrypt 比较，抹平与“用户存在但密码错误”之间的响应时间差异，
// 防止通过时序侧信道枚举已注册账号（见 handleSessionLogin）。
//
// 它必须由 bcrypt.GenerateFromPassword 生成：bcrypt.CompareHashAndPassword 遇到
// 非法哈希会立刻返回错误（微秒级），用虚构哈希达不到抹平时序的效果。
const dummyPasswordHash = "$2a$12$LQpe8bgXX/hkLhN6J0dtNuIGkubhtV5zDfx2kILnCAq08jvq8SnAO"

// checkPasswordConstantTime 在用户不存在时对 dummy 哈希做一次 bcrypt 比较，
// 使成功/失败路径耗时基本一致，规避登录用户枚举。
// 用户存在但库中密码哈希为空/非法时同样走 dummy 比较，避免该分支提前返回造成时序差异。
func checkPasswordConstantTime(userFound bool, hash, password string) bool {
	if !userFound || !isBcryptHash(hash) {
		// 走 auth 包而非直接调用 bcrypt：占位比较同样要经过全局并发闸门，
		// 否则「用户不存在」这条路径能绕过闸门把 CPU 打满（成本与真实比较一致）。
		_ = auth.CheckPassword(dummyPasswordHash, password)
		return false
	}
	return auth.CheckPassword(hash, password)
}

// isBcryptHash 报告哈希是否是合法的 bcrypt 串（$2a/$2b/$2y + cost + 53 字符摘要）。
func isBcryptHash(hash string) bool {
	prefix := hash
	if len(hash) > 4 {
		prefix = hash[:4]
	}
	switch prefix {
	case "$2a$", "$2b$", "$2y$":
	default:
		return false
	}
	return len(hash) == 60
}

// findUserByAccount 按账号定位用户：先按用户名精确匹配（区分大小写），
// 未命中再按邮箱小写归一化匹配。用户名精确查询命中多行时返回错误而不是
// 随机取一行，避免账号归属不可预期。
func findUserByAccount(ctx context.Context, db *bun.DB, login string) (models.User, error) {
	var u models.User
	n, err := db.NewSelect().Model(&u).Where("username = ?", login).Count(ctx)
	if err != nil {
		return u, err
	}
	if n > 1 {
		return u, errors.New("账号存在歧义，请联系管理员处理")
	}
	if n == 1 {
		if err := db.NewSelect().Model(&u).Where("username = ?", login).Scan(ctx); err != nil {
			return u, err
		}
		return u, nil
	}
	if err := db.NewSelect().Model(&u).Where("lower(email) = lower(?)", login).Scan(ctx); err != nil {
		return u, err
	}
	return u, nil
}

// POST /api/v1/session/login
func (h *Handler) handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	login := strings.TrimSpace(req.Login)
	if login == "" || req.Password == "" {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请输入账号和密码")
		return
	}
	// 是否允许密码登录（管理员可在「系统设置 → 身份验证」关闭）
	if !h.loadSecurityPolicy().PasswordLoginEnabled {
		fail(w, r, http.StatusForbidden, "login.password_disabled", "当前未开放密码登录")
		return
	}
	// 按账号维度限流：叠加在 IP 限流之上，防止分布式爆破绕过单 IP 限制。
	// 不做大小写折叠，否则仅大小写不同的两个账号会共用一个限流桶。
	if !h.accountLimiter.AllowKey("acct:" + login) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "登录尝试过于频繁，请稍后再试")
		return
	}
	if ok, err := h.verifyCaptcha(r, req.Captcha, h.captchaRequiredForLogin()); !ok {
		h.captchaFailure(w, r, err)
		return
	}
	// 用 found 区分“用户不存在”，并配合 dummy 哈希做恒定时间比较，抹平时序差异防枚举。
	found := true
	u, err := findUserByAccount(r.Context(), h.db, login)
	if errors.Is(err, sql.ErrNoRows) {
		found = false
	} else if err != nil {
		// 存量数据出现同名歧义时明确报错，不随机挑一个账号放行。
		fail(w, r, http.StatusConflict, "user.ambiguous", err.Error())
		return
	}
	if !checkPasswordConstantTime(found, u.PasswordHash, req.Password) {
		// 记录失败事件（含尝试账号，便于审计追溯爆破来源）
		h.logEvent(r, 0, &models.Event{
			Type:     "login.failed",
			Summary:  "密码登录失败",
			Metadata: map[string]string{"login": login},
		})
		// 审计日志：登录失败是爆破与撞库的直接信号，
		// 必须独立留痕，才能与限流/告警联动并及时察觉攻击。
		h.audit(r, "failure", "auth", "password_login", 0, "登录账号="+login)
		fail(w, r, http.StatusUnauthorized, "session.invalid_credentials", "账号或密码错误")
		return
	}

	// 双因素认证：已启用时先发 MFA 挑战，不直接登录。
	// 例外：当前设备已被标记为可信且在有效期内 → 跳过二次验证，
	// 兑现「可信设备可跳过 MFA」的产品承诺（通行密钥同理，本身即强认证）。
	// mfaSkipped 仅用于审计记录：可信设备登录时标记跳过原因，便于事后追溯。
	mfaSkipped := h.userMFAEnabled(u.ID)
	if h.userMFAEnabled(u.ID) && !h.isTrustedDevice(r, u.ID) {
		challengeID := h.createMFAChallenge(u.ID, "password")
		// 审计：密码已通过但等待二次验证，属于"半程登录"，
		// 记录它才能区分"卡在 MFA"与"密码错误"两类问题。
		h.audit(r, "pending", "mfa", "challenge_issued", u.ID, "密码校验已通过，等待 TOTP")
		ok(w, r, map[string]any{
			"mfaRequired": true,
			"challengeId": challengeID,
			"method":      "totp",
			"user": map[string]any{
				"id": u.ID, "username": u.Username,
				"displayName": u.DisplayName, "email": u.Email,
			},
		})
		return
	}

	csrf := auth.RandomToken(32)
	sessID, err := h.issueSession(w, r, &u, "password")
	if err != nil {
		internal(w, r, err)
		return
	}
	h.tokens.Set(csrf, u.ID, sessID)
	h.touchTrustedDevice(r.Context(), u.ID, h.deviceIDFromRequest(r))
	meta := map[string]string{"method": "password"}
	if mfaSkipped {
		meta["mfaSkipped"] = "trustedDevice"
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:     "login.success",
		Summary:  "密码登录成功",
		Metadata: meta,
	})
	// session.* 前缀事件：安全中心的「会话」分类按该前缀筛选，
	// 此前后端从不写入，导致该分类永远为空。
	h.logEvent(r, u.ID, &models.Event{
		Type:     "session.created",
		Summary:  "建立新会话",
		Metadata: meta,
	})
	h.audit(r, "success", "auth", "password_login", u.ID, "用户名="+u.Username)
	ok(w, r, h.sessionPayloadWithIP(r, &u, csrf))
}

// completeLogin 是密码登录 / 邮箱验证码登录 / MFA verify / 通行密钥登录共用的
// 登录收尾流程：签发会话 → 绑定 CSRF → 刷新可信设备 → 记录登录成功事件。
// 各登录入口只需准备好用户并传入 method（与 summary），消除三处逐行重复。
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, u *models.User, method, summary string) {
	csrf := auth.RandomToken(32)
	sessID, err := h.issueSession(w, r, u, method)
	if err != nil {
		internal(w, r, err)
		return
	}
	h.tokens.Set(csrf, u.ID, sessID)
	if method != "passkey" {
		// 通行密钥 ceremony 不下发设备 Cookie，保持原行为。
		h.touchTrustedDevice(r.Context(), u.ID, h.deviceIDFromRequest(r))
	}
	meta := map[string]string{"method": method}
	if summary == "" {
		summary = "登录成功"
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:     "login.success",
		Summary:  summary,
		Metadata: meta,
	})
	ok(w, r, h.sessionPayloadWithIP(r, u, csrf))
}

// GET /api/v1/session/ip — public client IP/region lookup (used on the login page).
func (h *Handler) handleClientIP(w http.ResponseWriter, r *http.Request) {
	ok(w, r, map[string]any{
		"ipAddress": clientIP(r),
		"ipRegion":  requestRegion(r),
	})
}

// GET /api/v1/session
func (h *Handler) handleGetSession(w http.ResponseWriter, r *http.Request) {
	u, s, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 复用当前会话仍未过期的 CSRF 令牌，避免每次轮询都增发新令牌、
	// 旧令牌又永不失效导致 TokenStore 无限膨胀。
	//
	// 绑定的必须是原始会话 Cookie 值：CSRF 中间件按 Cookie 取会话做校验，
	// 而 s.ID 是摘要（不可用于 Cookie），用摘要会永远校验失败。
	raw := rawSessionCookie(r, h.cfg.SessionCookieName)
	csrf := h.csrfTokenForSession(raw, u.ID)
	s.LastSeenAt = db.Now()
	_, _ = h.db.NewUpdate().Model(s).Set("last_seen_at = ?", s.LastSeenAt).WherePK().Exec(r.Context())
	ok(w, r, h.sessionPayloadWithIP(r, u, csrf))
}

// DELETE /api/v1/session (logout)
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// 先取用户信息再清 Cookie：清理后会话已失效，无法再归属用户。
	u, _, _ := h.currentUser(r)
	h.clearSessionCookies(w, r)
	if u != nil {
		h.logEvent(r, u.ID, &models.Event{Type: "session.ended", Summary: "退出登录"})
		h.audit(r, "success", "auth", "logout", u.ID, "")
	}
	ok(w, r, map[string]any{"success": true})
}

// clearSessionCookies deletes the session record and clears session/device cookies.
// 供 handleLogout（JSON API）与 HandleLogout（OIDC end-session）共用。
func (h *Handler) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(h.cfg.SessionCookieName); err == nil && c.Value != "" {
		_, _ = h.db.NewDelete().Model((*models.Session)(nil)).
			Where("session_hash = ?", hashSessionID(c.Value)).Exec(r.Context())
	}
	// 清除 Cookie 时也必须带上与签发时一致的属性（SameSite/Secure/Path），
	// 否则浏览器可能匹配不到原 Cookie，出现「登出后仍处于登录态」。
	http.SetCookie(w, &http.Cookie{
		Name: h.cfg.SessionCookieName, Value: "", Path: "/",
		MaxAge: -1, Expires: time.Unix(0, 0), HttpOnly: true,
		Secure: h.cookieSecure(), SameSite: h.cookieSameSite(),
	})
	http.SetCookie(w, &http.Cookie{
		Name: h.cfg.DeviceCookieName, Value: "", Path: "/",
		MaxAge: -1, Expires: time.Unix(0, 0), HttpOnly: true,
		Secure: h.cookieSecure(), SameSite: h.cookieSameSite(),
	})
}

// logEvent records a security event with request metadata.
// If userID > 0 it is used directly (e.g. right after login, when the
// request cookie is not yet populated).
// r 允许为 nil（内部事件，如挑战被锁定时无请求上下文）：此时不记录请求元数据，
// 但事件本身仍会落库，避免审计丢失。
func (h *Handler) logEvent(r *http.Request, userID int64, e *models.Event) {
	// 「仅记录登录/安全事件」开关：开启后跳过非安全类事件，显著降低写入放大。
	// 判定放在最前面（且本函数本身被大量调用），因此只做一次前缀匹配，
	// 不再回源读配置——配置读取走 5 秒 TTL 的进程内缓存。
	if a := h.loadAuditSetting(); a != nil && a.LoginEventsOnly && !isSecurityEvent(e.Type) {
		return
	}
	if userID == 0 && r != nil {
		if u, _, err := h.currentUser(r); err == nil {
			userID = u.ID
		}
		// 无法归属用户（如登录失败）时仍要落审计记录，避免失败尝试不可追溯；
		// user_id 保持 0，表示匿名/未识别主体。
	}
	e.UserID = userID
	if r != nil {
		e.IPAddress = clientIP(r)
		// 走 requestRegion 而非 regionOf：前者复用请求级的归属地缓存，
		// 同一请求里 clientIP / 归属地被多处使用时只解析一次。
		e.IPRegion = requestRegion(r)
		e.UserAgent = r.UserAgent()
	}
	e.CreatedAt = db.Now()
	// 这里有意使用 context.Background() 而非 r.Context()：审计事件必须在客户端
	// 中途断开（r.Context() 被取消）时仍然落库，否则攻击者只要断开连接就能让
	// 自己的失败登录/越权尝试不留痕迹。这不是疏漏，请勿「顺手」改回 r.Context()。
	_, _ = h.db.NewInsert().Model(e).Exec(context.Background())

	// 发布到事件总线，供邮件通知 / 审计 / Webhook 等消费方异步处理。
	h.events.Publish(context.Background(), event.Data{
		Type:   "security." + e.Type,
		UserID: e.UserID,
		Payload: map[string]any{
			"summary":   e.Summary,
			"ipAddress": e.IPAddress,
			"ipRegion":  e.IPRegion,
			"userAgent": e.UserAgent,
			"metadata":  e.Metadata,
		},
	})
}

// securityEventPrefixes 是「登录 / 安全」类事件的前缀白名单。
// 开启「仅记录登录/安全事件」后，只有这些事件会落库，
// 其余（如纯管理操作、数据导出）仅保留在应用日志中。
var securityEventPrefixes = []string{
	"login.", "session.", "signup.", "password.", "mfa.", "email.",
	"oauth.", "account.", "passkey.", "phone.", "step_up.", "reauth.",
	"device_auth.", "avatar.", "timezone.",
}

// isSecurityEvent 判断事件类型是否属于登录/安全类。
func isSecurityEvent(t string) bool {
	for _, p := range securityEventPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// csrfTokenForSession 返回绑定到该会话的 CSRF 令牌：
// 会话已有未过期令牌时直接复用，否则才签发新令牌。
// 这样既避免每次 GET /session 都增发令牌（旧令牌永不失效、TokenStore 无限膨胀），
// 也保证令牌始终绑定会话（无法跨会话使用）。
//
// sessionValue 必须是原始会话 Cookie 值（不是库里的摘要）：CSRF 中间件
// 按请求 Cookie 取值校验，绑定摘要会导致合法请求被 403。
func (h *Handler) csrfTokenForSession(sessionValue string, userID int64) string {
	if sessionValue == "" {
		return ""
	}
	if existing := h.tokens.SessionCSRFToken(sessionValue); existing != "" {
		return existing
	}
	token := auth.RandomToken(32)
	h.tokens.Set(token, userID, sessionValue)
	h.tokens.BindSessionCSRFToken(sessionValue, token, userID)
	return token
}

// rawSessionCookie 返回请求携带的原始会话 Cookie 值（不存在时为空串）。
func rawSessionCookie(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

// effectiveSessionTTLDays 返回实际生效的会话有效期（天）：
// 后台安全策略（SecurityPolicy.SessionTTLDays）优先，未配置时回退环境变量，
// 避免后台修改了会话有效期却不生效。
func (h *Handler) effectiveSessionTTLDays() int {
	sp := h.loadSecurityPolicy()
	if sp != nil && sp.SessionTTLDays > 0 {
		return sp.SessionTTLDays
	}
	if h.cfg.SessionTTLDays > 0 {
		return h.cfg.SessionTTLDays
	}
	return 14
}

func internal(w http.ResponseWriter, r *http.Request, err error) {
	// 500 类错误必须留下可定位的根因：此前 err 被直接丢弃，服务端返回
	// 「服务器内部错误」但日志中查不到任何线索（如 bun 的 column/约束错误），
	// 排障只能靠猜。这里把根因写入日志（客户端仍只收到通用文案，不回显内部细节）。
	if err != nil {
		logging.Error("❌ [Internal] %s %s 处理失败: %v", r.Method, r.URL.Path, err)
	}
	fail(w, r, http.StatusInternalServerError, "internal.error", "服务器内部错误")
}

// audit 记录一条安全审计日志（受 OPENIDP_AUDIT_LOG_ENABLED 控制）。
//
// result 建议取值 "success" / "failure"，category 用于归类（auth / mfa /
// password / email / passkey / oauth ...）。
// detail 只放非敏感摘要：密码、验证码、令牌一律不得写入。
func (h *Handler) audit(r *http.Request, result, category, action string, userID int64, detail string) {
	if h.cfg == nil || !h.cfg.AuditLogEnabled {
		return
	}
	logging.Audit(result, category, action, userID, clientIP(r), detail)
}

// auditConfigChange 记录一次配置变更（受 OPENIDP_CONFIG_LOG_ENABLED 控制）。
//
// fields 只记录被修改的字段名，不记录值——值里可能含 SMTP 密码、S3 密钥等凭据。
func (h *Handler) auditConfigChange(r *http.Request, scope, action string, userID int64, fields []string) {
	if h.cfg == nil || !h.cfg.ConfigLogEnabled {
		return
	}
	logging.ConfigChange(scope, action, userID, clientIP(r), fields)
}

// clientIP extracts the trusted client IP that was injected into the request
// context by withClientIP (resolved from proxy/CDN headers when TRUST_PROXY
// and the peer is a trusted proxy).
func clientIP(r *http.Request) string {
	return logging.ClientIPFromContext(r.Context())
}

// withClientIP is a middleware that resolves and injects the trusted client IP
// as well as a per-request GeoIP cache (see requestRegion).
//
// IP 同时写入 logx 的上下文键：访问日志在 middleware 层产出，那里读不到 handler
// 包的私有键，而 logx 是最底层、双方都能依赖的地方。
func (h *Handler) withClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := middleware.ResolveClientIP(r, h.clientIPConfig())
		ctx := logging.WithClientIP(r.Context(), ip)
		// 归属地解析开关在这里读取一次：整个请求共用同一判定，
		// 不会出现「同一请求里两处解析结果口径不同」。
		ls := h.loadLocationSetting()
		ctx = context.WithValue(ctx, ctxGeoKey{}, &geoCache{enabled: ls == nil || ls.Enabled})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// clientIPConfig 组装客户端 IP 的解析配置。
//
// 来源有两处，非空的管理后台配置优先于环境变量：
//   - 环境变量 OPENIDP_TRUST_PROXY / OPENIDP_CLIENT_IP_HEADER / OPENIDP_TRUSTED_PROXIES（部署层默认值）
//   - 管理后台「系统设置 → 归属地」的真实 IP 头 / 可信代理（运维期可调整）
//
// 此前后台这两项只被持久化、从未参与解析，填写后不会有任何效果；
// 现在它们真正生效，且保存后由 h.conf.invalidate() 在数秒内生效。
func (h *Handler) clientIPConfig() middleware.ClientIPConfig {
	cfg := middleware.ClientIPConfig{
		TrustProxy: h.cfg.TrustProxy,
		Header:     strings.TrimSpace(h.cfg.ClientIPHeader),
	}
	if ls := h.loadLocationSetting(); ls != nil {
		if v := strings.TrimSpace(ls.RealIPHeader); v != "" {
			cfg.Header = v
		}
		if v := strings.TrimSpace(ls.TrustedProxies); v != "" {
			// 逐项 trim 并丢弃空项，便于填写 "127.0.0.1/8, 10.0.0.0/8" 这类带空格的写法。
			for _, part := range strings.Split(v, ",") {
				if part = strings.TrimSpace(part); part != "" {
					cfg.TrustedProxies = append(cfg.TrustedProxies, part)
				}
			}
		}
	}
	if len(cfg.TrustedProxies) == 0 {
		cfg.TrustedProxies = h.cfg.TrustedProxies
	}
	return cfg
}

type ctxGeoKey struct{}

// geoCache 缓存单个请求内的 IP 归属地解析结果。
type geoCache struct {
	once   sync.Once
	region string
	// enabled 对应管理后台「启用归属地解析」开关：关闭时不再解析，
	// 只返回固定占位值。此前该开关只影响「测试解析」按钮，实际解析照常进行。
	enabled bool
}

// requestRegion 返回当前请求的归属地，结果在请求内缓存，
// 避免同一请求里 clientIP 与 regionOf 被分开调用造成的重复解析。
func requestRegion(r *http.Request) string {
	ip := clientIP(r)
	gc, ok := r.Context().Value(ctxGeoKey{}).(*geoCache)
	if !ok {
		return geolocation.Resolve(ip)
	}
	if !gc.enabled {
		return unparsedRegion
	}
	gc.once.Do(func() { gc.region = geolocation.Resolve(ip) })
	return gc.region
}

// unparsedRegion 是归属地解析被关闭时写入的值（与「未知」区分开：
// 明确告诉查看者这是被关闭的，而不是解析失败）。
const unparsedRegion = "归属地解析已关闭"

func isLocal(r *http.Request) bool {
	host := r.Host
	return strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "0.0.0.0")
}

// cookieSameSite 解析会话/设备 Cookie 的 SameSite 属性。
//
// auto（默认）：配置了跨域白名单（CORS_ALLOWED_ORIGINS，即前后端分离部署）时为
// SameSite=None，否则为 Lax。跨站部署下浏览器不会在 fetch 中携带 Lax Cookie，
// 表现为「接口能调通但始终是未登录」，文档里宣称支持的前后端分离部署因此不可用。
//
// SameSite=None 必须搭配 Secure（浏览器强制要求），故这种情况下同时打开 Secure：
// 若站点本身不是 https，Cookie 仍会被浏览器丢弃——此时应显式配置 COOKIE_SAME_SITE
// 与 COOKIE_SECURE，而不是让服务端静默下发一个必然失效的 Cookie。
func (h *Handler) cookieSameSite() http.SameSite {
	switch strings.ToLower(strings.TrimSpace(h.cfg.CookieSameSite)) {
	case "none":
		return http.SameSiteNoneMode
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	}
	if len(h.cfg.CORSAllowedOrigins) > 0 {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

// cookieSecure reports whether session/device cookies should set the Secure flag.
// It is derived from configuration (COOKIE_SECURE) or the SiteURL scheme, never
// from the client-controllable Host header (which could be spoofed to downgrade
// Secure on a production HTTPS site).
func (h *Handler) cookieSecure() bool {
	switch strings.ToLower(h.cfg.CookieSecure) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	// auto: derive from SiteURL scheme
	if strings.HasPrefix(strings.ToLower(h.cfg.SiteURL), "https://") {
		return true
	}
	// 跨站 Cookie（SameSite=None）在浏览器中必须带 Secure，否则会被直接丢弃。
	// 未配置 SITE_URL 时按请求协议判定，避免「文档说能用、实际登录不上」。
	return h.cookieSameSite() == http.SameSiteNoneMode
}

// ResolvePasskeyConfig 解析通行密钥（WebAuthn）依赖方配置。
//
// 规则：
//  1. 未在系统设置中显式开启通行密钥 → 不启用（返回空配置）；
//  2. 依赖方 URL 优先使用系统设置中的站点 URL（SiteSetting.SiteURL）；
//  3. 系统设置未配置站点 URL 时，按当前访问域名（originHint，请求 Host 兑底）推导；
//  4. 站点 URL 与当前访问地址均无法确定时 → 不启用。
//
// RPID 由所选 origin 推导（默认取主机名，不含端口）。
func (h *Handler) ResolvePasskeyConfig(originHint string) passkey.Config {
	ss := h.loadSiteSetting()
	if !ss.PasskeyEnabled {
		return passkey.Config{}
	}

	// 依赖方 URL：优先系统设置中显式配置的站点 URL / 通行密钥依赖方 URL。
	origin := strings.TrimSpace(ss.PasskeyRPID)
	if origin == "" {
		origin = strings.TrimSpace(ss.SiteURL)
	}
	if origin != "" && !strings.Contains(origin, "://") {
		// 若只填了域名，补全协议（http 时依据 allowInsecure）
		scheme := "https://"
		if ss.PasskeyAllowInsecure {
			scheme = "http://"
		}
		origin = scheme + origin
	}
	if origin != "" && strings.HasPrefix(origin, "http://localhost") && !h.cfg.TrustProxy {
		// localhost 占位视为未配置，走当前访问域名兑底
		origin = ""
	}
	// 其次按当前访问 URL 兑底。
	if origin == "" {
		origin = originHint
	}
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		return passkey.Config{}
	}

	rpName := h.cfg.WebAuthnRPName
	if rpName == "" {
		rpName = h.cfg.SiteDisplay
	}
	if strings.TrimSpace(ss.PasskeyDisplayName) != "" {
		rpName = strings.TrimSpace(ss.PasskeyDisplayName)
	}
	return passkey.Config{
		Enabled: true,
		Origin:  origin,
		RPID:    derivePasskeyRPID(origin),
		RPName:  rpName,
		Origins: ss.PasskeyOrigins,
	}
}

// derivePasskeyRPID 从依赖方 origin 推导 WebAuthn RPID（取主机名，不含端口）。
func derivePasskeyRPID(origin string) string {
	o := strings.TrimSpace(origin)
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(o, prefix) {
			o = o[len(prefix):]
			break
		}
	}
	if i := strings.IndexByte(o, ':'); i > 0 {
		o = o[:i]
	}
	if i := strings.IndexByte(o, '/'); i > 0 {
		o = o[:i]
	}
	return strings.TrimSpace(o)
}

// sanitizeHost cleans a hostname[:port] for use in absolute URLs, rejecting
// values with path/query/userinfo or illegal characters (Host-header injection).
func sanitizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// 去掉可能的端口后再做基本合法性校验（合法 hostname 字符 + 数字/点/短横线）。
	h := host
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') && c != '.' && c != '-' && c != '_' {
			return ""
		}
	}
	return host
}

// requestHost sanitizes the Host header for use in building absolute URLs
// (issuer / redirect_uri / callback).
func requestHost(r *http.Request) string {
	return sanitizeHost(r.Host)
}

// shortUA trims a user-agent to a short friendly device label.
func shortUA(ua string) string {
	if ua == "" {
		return "未知设备"
	}
	switch {
	case strings.Contains(ua, "curl"):
		return "curl 命令行"
	case strings.Contains(ua, "HeadlessChrome"):
		return "无头浏览器"
	case strings.Contains(ua, "Windows"):
		return "Windows 设备"
	case strings.Contains(ua, "Macintosh"):
		return "Mac 设备"
	case strings.Contains(ua, "iPhone"):
		return "iPhone"
	case strings.Contains(ua, "iPad"):
		return "iPad"
	case strings.Contains(ua, "Android"):
		return "Android 设备"
	case strings.Contains(ua, "Linux"):
		return "Linux 设备"
	}
	if len(ua) > 24 {
		return ua[:24] + "…"
	}
	return ua
}
