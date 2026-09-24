package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- Admin site settings ----

func (h *Handler) loadSiteSetting() *models.SiteSetting {
	return cached(h.conf, peekSite, storeSite, h.fetchSiteSetting)
}

// fetchSiteSetting 从数据库读取站点设置；缺失时写入一行空配置。
// 初始化不填入任何内容：品牌名 / Logo / Favicon / 站点 URL / 备案信息等全部留空，
// 由管理员在「系统设置 → 品牌信息」中自行填写；未填写时展示层回退到环境变量或内置默认。
func (h *Handler) fetchSiteSetting() *models.SiteSetting {
	ss := &models.SiteSetting{}
	err := h.db.NewSelect().Model(ss).Where("id = 1").Scan(context.Background())
	if err != nil {
		ss = &models.SiteSetting{
			ID:                  1,
			DisplayName:         "",
			LogoURL:             "",
			FaviconURL:          "",
			SiteURL:             "",
			FooterText:          "",
			ICPBeian:            "",
			PublicSecurityBeian: "",
			PasskeyDisplayName:  "",
			PasskeyRPID:         "",
			Languages:           []string{"zh-CN", "zh-TW", "ja", "en"},
			DefaultLanguage:     "zh-CN",
			UpdatedAt:           db.Now(),
		}
		_, _ = h.db.NewInsert().Model(ss).Exec(context.Background())
	}
	return ss
}

// GET /api/v1/admin/site
func (h *Handler) handleAdminGetSite(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ok(w, r, h.loadSiteSetting())
}

// PATCH /api/v1/admin/site
func (h *Handler) handleAdminUpdateSite(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ss := h.loadSiteSetting()
	var req struct {
		SiteName    *string  `json:"siteName"`
		DisplayName *string  `json:"displayName"`
		LogoURL     *string  `json:"logoUrl"`
		FaviconURL  *string  `json:"faviconUrl"`
		Languages   []string `json:"languages"`
		// DefaultLanguage 站点默认语言（未登录页面使用）。
		DefaultLanguage *string `json:"defaultLanguage"`
		// AvatarUploadEnabled 允许用户上传自定义头像（默认关闭）
		AvatarUploadEnabled *bool `json:"avatarUploadEnabled"`
		// SiteURL 站点公网地址（OAuth 回调 / 邮件链接 / 通行密钥依赖方 URL 用）
		SiteURL *string `json:"siteUrl"`
		// PasskeyEnabled 是否启用通行密钥（默认关闭）
		PasskeyEnabled *bool `json:"passkeyEnabled"`
		// 系统信息：页脚 / ICP / 公安备案
		FooterText          *string `json:"footerText"`
		ICPBeian            *string `json:"icpBeian"`
		PublicSecurityBeian *string `json:"publicSecurityBeian"`
		// 通行密钥扩展配置
		PasskeyDisplayName   *string  `json:"passkeyDisplayName"`
		PasskeyRPID          *string  `json:"passkeyRPID"`
		PasskeyAllowInsecure *bool    `json:"passkeyAllowInsecure"`
		PasskeyOrigins       []string `json:"passkeyOrigins"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.SiteName != nil {
		ss.SiteName = *req.SiteName
	}
	if req.DisplayName != nil {
		ss.DisplayName = *req.DisplayName
	}
	// 站点 Logo / Favicon 同样会下发给所有访客（favicon 还会写进 <link rel=icon>），
	// 走与其他外部地址一致的校验，避免协议非 http/https 或畸形地址被直接渲染。
	if req.LogoURL != nil {
		v, ok := sanitizeAssetURL(*req.LogoURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "site.logo_invalid", "Logo 地址无效，仅支持站内路径或 http/https 绝对地址")
			return
		}
		ss.LogoURL = v
	}
	if req.FaviconURL != nil {
		v, ok := sanitizeAssetURL(*req.FaviconURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "site.favicon_invalid", "Favicon 地址无效，仅支持站内路径或 http/https 绝对地址")
			return
		}
		ss.FaviconURL = v
	}
	if len(req.Languages) > 0 {
		ss.Languages = req.Languages
	}
	if req.DefaultLanguage != nil {
		if v := strings.TrimSpace(*req.DefaultLanguage); validLanguage(v) {
			ss.DefaultLanguage = v
		}
	}
	if req.AvatarUploadEnabled != nil {
		ss.AvatarUploadEnabled = *req.AvatarUploadEnabled
	}
	if req.SiteURL != nil {
		ss.SiteURL = *req.SiteURL
	}
	if req.PasskeyEnabled != nil {
		ss.PasskeyEnabled = *req.PasskeyEnabled
	}
	if req.FooterText != nil {
		ss.FooterText = *req.FooterText
	}
	if req.ICPBeian != nil {
		ss.ICPBeian = *req.ICPBeian
	}
	if req.PublicSecurityBeian != nil {
		ss.PublicSecurityBeian = *req.PublicSecurityBeian
	}
	if req.PasskeyDisplayName != nil {
		ss.PasskeyDisplayName = *req.PasskeyDisplayName
	}
	if req.PasskeyRPID != nil {
		ss.PasskeyRPID = *req.PasskeyRPID
	}
	if req.PasskeyAllowInsecure != nil {
		ss.PasskeyAllowInsecure = *req.PasskeyAllowInsecure
	}
	if len(req.PasskeyOrigins) > 0 {
		ss.PasskeyOrigins = req.PasskeyOrigins
	}
	ss.UpdatedAt = db.Now()
	// 只写本次提交的列：全量覆盖会在多实例并发下把其他管理员
	// 同时提交、但本次请求尚未读取到的改动整行冲掉。
	if _, err := h.db.NewUpdate().Model(ss).WherePK().
		Set("site_name = ?", ss.SiteName).
		Set("display_name = ?", ss.DisplayName).
		Set("logo_url = ?", ss.LogoURL).
		Set("favicon_url = ?", ss.FaviconURL).
		Set("languages = ?", ss.Languages).
		Set("default_language = ?", ss.DefaultLanguage).
		Set("avatar_upload_enabled = ?", ss.AvatarUploadEnabled).
		Set("site_url = ?", ss.SiteURL).
		Set("passkey_enabled = ?", ss.PasskeyEnabled).
		Set("footer_text = ?", ss.FooterText).
		Set("icp_beian = ?", ss.ICPBeian).
		Set("public_security_beian = ?", ss.PublicSecurityBeian).
		Set("passkey_display_name = ?", ss.PasskeyDisplayName).
		Set("passkey_rpid = ?", ss.PasskeyRPID).
		Set("passkey_allow_insecure = ?", ss.PasskeyAllowInsecure).
		Set("passkey_origins = ?", ss.PasskeyOrigins).
		Set("updated_at = ?", ss.UpdatedAt).
		Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	h.auditConfigChange(r, "site", "update", 0, []string{
		"siteName", "displayName", "logoUrl", "faviconUrl", "languages",
		"avatarUploadEnabled", "siteUrl", "passkeyEnabled",
		"footerText", "icpBeian", "publicSecurityBeian",
		"passkeyDisplayName", "passkeyRPID", "passkeyAllowInsecure", "passkeyOrigins",
	})
	h.logEvent(r, 0, &models.Event{Type: "admin.site_updated", Summary: "管理员更新系统设置"})
	ok(w, r, ss)
}

// ---- Admin security policy ----

func (h *Handler) loadSecurityPolicy() *models.SecurityPolicy {
	return cached(h.conf, peekSec, storeSec, h.fetchSecurityPolicy)
}

// fetchSecurityPolicy 从数据库读取安全策略；缺失时写入一行宽松默认值。
// 只写入开关与结构性数值，不从环境变量灌入任何内容。
func (h *Handler) fetchSecurityPolicy() *models.SecurityPolicy {
	sp := &models.SecurityPolicy{}
	err := h.db.NewSelect().Model(sp).Where("id = 1").Scan(context.Background())
	if err != nil {
		sp = &models.SecurityPolicy{
			ID: 1, MinPasswordLength: 8, RequireUppercase: false, RequireLowercase: false,
			RequireNumber: false, RequireSymbol: false, SessionTTLDays: 14,
			// 开放注册默认关闭：新部署不应在管理员尚未决策时对外敞开注册入口，
			// 需要开放时由管理员在「系统设置 → 安全策略」中显式开启。
			PasswordResetEnabled: true, SignupEnabled: false, SignupEmailVerification: true,
			// 注销冷静期默认 24 小时（仅新建策略行时生效；存量库保持 0 即不设冷静期，
			// 避免升级后突然改变既有行为）。
			// 密码登录默认开启：安全策略页已隐藏该开关，新建策略行时即为开启状态。
			PasswordLoginEnabled: true, EmailDomainWhitelist: "", EmailDomainWhitelistEnabled: false, DisableAliasEmail: false,
			// 手机号默认允许添加：与存量行为保持一致，由管理员按需关闭。
			PhoneAddEnabled: true,
			UpdatedAt:       db.Now(),
		}
		_, _ = h.db.NewInsert().Model(sp).Exec(context.Background())
	}
	return sp
}

// GET /api/v1/admin/security-policy
func (h *Handler) handleAdminGetSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ok(w, r, h.loadSecurityPolicy())
}

// PATCH /api/v1/admin/security-policy
func (h *Handler) handleAdminUpdateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	sp := h.loadSecurityPolicy()
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	// asInt 兼容 float64 / int64 / json.Number 三种由不同解码路径产生的数字类型。
	asInt := func(v any) (int, bool) {
		switch t := v.(type) {
		case float64:
			n := int(t)
			// 拒绝小数/溢出（例如 8.5、1e20），仅接受整数且不超过 int 范围。
			if float64(n) != t {
				return 0, false
			}
			return n, true
		case int64:
			return int(t), true
		case json.Number:
			if i, err := t.Int64(); err == nil {
				return int(i), true
			}
			return 0, false
		default:
			return 0, false
		}
	}
	applyInt := func(key string, field *int, min, max int) {
		v, ok := req[key]
		if !ok {
			return
		}
		n, ok := asInt(v)
		if !ok {
			return
		}
		if n < min {
			n = min
		}
		if n > max {
			n = max
		}
		*field = n
	}
	// 兼容布尔与字符串两种写法（前端表单可能提交 "true"/"false"），
	// 无法识别的类型保持旧值，而不是静默置 false。
	applyBool := func(key string, field *bool) {
		switch v := req[key].(type) {
		case bool:
			*field = v
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "1", "true", "yes", "on":
				*field = true
			case "0", "false", "no", "off":
				*field = false
			}
		}
	}
	// 密码长度：1~64；会话有效期：1~365 天（钳制非法输入，避免写入 0/负值）。
	applyInt("minPasswordLength", &sp.MinPasswordLength, 1, 64)
	applyInt("sessionTTLDays", &sp.SessionTTLDays, 1, 365)
	applyBool("requireUppercase", &sp.RequireUppercase)
	applyBool("requireLowercase", &sp.RequireLowercase)
	applyBool("requireNumber", &sp.RequireNumber)
	applyBool("requireSymbol", &sp.RequireSymbol)
	applyBool("passwordResetEnabled", &sp.PasswordResetEnabled)
	applyBool("signupEnabled", &sp.SignupEnabled)
	applyBool("signupEmailVerification", &sp.SignupEmailVerification)
	applyBool("passwordLoginEnabled", &sp.PasswordLoginEnabled)
	applyBool("disableAliasEmail", &sp.DisableAliasEmail)
	applyBool("emailDomainWhitelistEnabled", &sp.EmailDomainWhitelistEnabled)
	// 可信设备有效期（天）：0 表示回退环境变量；上限 3650 天，防止写入离谱值。
	applyInt("trustedDeviceTTLDays", &sp.TrustedDeviceTTLDays, 0, 3650)
	// 自助注销开关：默认关闭，需管理员显式开放。
	applyBool("accountDeletionEnabled", &sp.AccountDeletionEnabled)
	// 注销冷静期（小时）：0 表示不设冷静期；上限 720 小时（30 天）。
	applyInt("accountDeletionCooldownHours", &sp.AccountDeletionCooldownHours, 0, 720)
	// 是否允许用户自助添加手机号（关闭后用户侧隐藏手机号入口）。
	applyBool("phoneAddEnabled", &sp.PhoneAddEnabled)
	if v, ok := req["emailDomainWhitelist"].(string); ok {
		sp.EmailDomainWhitelist = v
	}
	sp.UpdatedAt = db.Now()
	// 与系统设置同理：只写本次提交的列，避免并发整行覆盖。
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("min_password_length = ?", sp.MinPasswordLength).
		Set("require_uppercase = ?", sp.RequireUppercase).
		Set("require_lowercase = ?", sp.RequireLowercase).
		Set("require_number = ?", sp.RequireNumber).
		Set("require_symbol = ?", sp.RequireSymbol).
		Set("session_ttl_days = ?", sp.SessionTTLDays).
		Set("password_reset_enabled = ?", sp.PasswordResetEnabled).
		Set("signup_enabled = ?", sp.SignupEnabled).
		Set("signup_email_verification = ?", sp.SignupEmailVerification).
		Set("password_login_enabled = ?", sp.PasswordLoginEnabled).
		Set("email_domain_whitelist = ?", sp.EmailDomainWhitelist).
		Set("email_domain_whitelist_enabled = ?", sp.EmailDomainWhitelistEnabled).
		Set("disable_alias_email = ?", sp.DisableAliasEmail).
		Set("trusted_device_ttl_days = ?", sp.TrustedDeviceTTLDays).
		Set("account_deletion_enabled = ?", sp.AccountDeletionEnabled).
		Set("account_deletion_cooldown_hours = ?", sp.AccountDeletionCooldownHours).
		Set("phone_add_enabled = ?", sp.PhoneAddEnabled).
		Set("updated_at = ?", sp.UpdatedAt).
		Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	h.auditConfigChange(r, "security-policy", "update", 0, []string{
		"minPasswordLength", "sessionTTLDays",
		"requireUppercase", "requireLowercase", "requireNumber", "requireSymbol",
		"passwordResetEnabled", "signupEnabled", "signupEmailVerification",
		"passwordLoginEnabled", "emailDomainWhitelist", "emailDomainWhitelistEnabled",
		"disableAliasEmail", "trustedDeviceTTLDays",
		"accountDeletionEnabled", "accountDeletionCooldownHours",
		"phoneAddEnabled",
	})
	h.logEvent(r, 0, &models.Event{Type: "admin.security_policy_updated", Summary: "管理员更新安全策略"})
	ok(w, r, sp)
}

// validLanguage 校验站点默认语言取值，避免写入不受支持的语言标识。
func validLanguage(v string) bool {
	switch v {
	case "zh-CN", "zh-TW", "ja", "en":
		return true
	}
	return false
}
