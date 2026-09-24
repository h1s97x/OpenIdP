package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/h1s97x/openidp/api/internal/models"
)

// maxPasswordBytes 是密码允许的最大字节数，与 bcrypt 的输入上限一致
// （bcrypt 只处理前 72 字节，更长的部分既不参与校验也不提升强度）。
const maxPasswordBytes = 72

// validatePassword checks a password against the configured SecurityPolicy.
// Returns an error message (empty string means valid).
func validatePassword(sp *models.SecurityPolicy, password string) string {
	if sp == nil {
		sp = &models.SecurityPolicy{MinPasswordLength: 8}
	}
	minLen := sp.MinPasswordLength
	if minLen <= 0 {
		minLen = 8
	}
	// 按「字符数」而非字节数计长度：len() 对中文等多字节字符偏严，
	// 一个 8 个汉字的密码按字节算是 24，与配置的 8 位最小长度语义不符。
	if utf8.RuneCountInString(password) < minLen {
		return "密码长度至少 " + strconv.Itoa(minLen) + " 位"
	}
	// 上限校验：bcrypt 只取前 72 字节，更长的输入既不影响实际强度，
	// 又会白烧一次高开销的哈希计算（可被用来放大 CPU 开销）。
	// 超限直接拒绝，而不是静默截断——截断会让用户以为设置了更长更安全的密码。
	if len(password) > maxPasswordBytes {
		return "密码过长（最多 " + strconv.Itoa(maxPasswordBytes) + " 字节，约 72 个西文字符）"
	}
	hasUpper, hasLower, hasNum, hasSym := false, false, false, false
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasNum = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSym = true
		}
	}
	if sp.RequireUppercase && !hasUpper {
		return "密码需包含大写字母"
	}
	if sp.RequireLowercase && !hasLower {
		return "密码需包含小写字母"
	}
	if sp.RequireNumber && !hasNum {
		return "密码需包含数字"
	}
	if sp.RequireSymbol && !hasSym {
		return "密码需包含特殊符号"
	}
	return ""
}

// isValidEmail does a lightweight email format check (must contain a single @
// with a non-empty domain part). 用于注册/管理端建号前的格式校验，避免仅靠 DB 约束报 500。
func isValidEmail(email string) bool {
	e := strings.TrimSpace(email)
	if e == "" || !strings.Contains(e, "@") {
		return false
	}
	at := strings.Index(e, "@")
	if at == 0 || at == len(e)-1 {
		return false
	}
	// 不允许 @ 前后再有 @，且 domain 至少包含一个点或为合法域名片段。
	if strings.Contains(e[at+1:], "@") {
		return false
	}
	return true
}

// 用户名命名规则：仅允许半角字母与数字，长度 3-32，区分大小写。
// 排除全角字符、形近字母（如西里尔字母）与不可见字符，避免注册出
// 肉眼难以分辨的账号。
const (
	usernameMinLength = 3
	usernameMaxLength = 32
)

// validateUsername 校验用户名格式，返回中文提示；空字符串表示通过。
func validateUsername(username string) string {
	n := 0
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			n++
			continue
		}
		return "用户名只能包含字母和数字"
	}
	if n < usernameMinLength {
		return "用户名至少 " + strconv.Itoa(usernameMinLength) + " 位"
	}
	if n > usernameMaxLength {
		return "用户名最多 " + strconv.Itoa(usernameMaxLength) + " 位"
	}
	return ""
}

// GET /api/v1/login-policy
func (h *Handler) handleLoginPolicy(w http.ResponseWriter, r *http.Request) {
	sp := h.loadSecurityPolicy()
	// 邮箱验证码登录/注册依赖 SMTP 邮件服务；未配置时禁用，避免“提示发送成功但实际未发送”。
	mailEnabled := h.mailer.Enabled()
	// 通行密钥依赖系统设置开关：未开启时登录页不应展示该入口，
	// 否则用户点击后才收到 passkey.unavailable，属于“先给入口再打脸”。
	passkeyEnabled := h.ResolvePasskeyConfig(h.requestBaseURL(r)).Enabled
	ok(w, r, map[string]any{
		// 与安全策略里的开关保持一致：此前硬编码 true，
		// 关闭密码登录后登录页拿到的仍是「可用」，字段与真实能力不符。
		"password":                sp.PasswordLoginEnabled,
		"emailCode":               mailEnabled,
		"webAuthn":                passkeyEnabled,
		"signup":                  sp.SignupEnabled,
		"signupEmailVerification": sp.SignupEmailVerification && mailEnabled,
		"mailEnabled":             mailEnabled,
		"providers":               h.publicProviders(r.Context()),
		"passwordRequirements": map[string]any{
			"minimumLength":    sp.MinPasswordLength,
			"requireUppercase": sp.RequireUppercase,
			"requireLowercase": sp.RequireLowercase,
			"requireNumber":    sp.RequireNumber,
			"requireSymbol":    sp.RequireSymbol,
		},
		"captcha": h.captchaConfigPayload(),
	})
}

// GET /api/v1/site
// 公开站点信息（品牌 + 页脚备案信息），供未登录页面（登录/注册/找回密码/授权确认）渲染页脚。
// 与 /api/v1/session 中的 site 同源，均来自 siteInfo()，不含任何用户数据。
func (h *Handler) handleGetSite(w http.ResponseWriter, r *http.Request) {
	ok(w, r, h.siteInfo())
}

// GET /api/v1/login/providers
func (h *Handler) handleLoginProviders(w http.ResponseWriter, r *http.Request) {
	ok(w, r, h.publicProviders(r.Context()))
}

// publicProviders returns the enabled OAuth providers for the public login UI.
//
// 只返回「已开启且凭据齐备」的提供商：未配置完整的提供商不可能被开启
// （见 handleAdminUpdateOAuthProvider / handleAdminCreateOAuthProvider 的校验），
// 这里再按同一条件过滤，兜住历史数据与直接改库留下的脏行 —— 否则登录页与安全中心
// 会出现一个点了必然报错的入口（授权端点会以 providerReadyErr 拒绝）。
// 全部不可用时返回空列表（前端隐藏该区域）。
func (h *Handler) publicProviders(ctx context.Context) []map[string]any {
	var providers []models.OAuthProvider
	if err := h.db.NewSelect().Model(&providers).
		Where("enabled = true").
		// NULL 与空串都算「未配置」：SQL 里 NULL <> '' 为 NULL，行会被过滤掉，
		// 正是这里想要的结果（没有 client_id 就无法发起授权）。
		Where("client_id <> ''").
		Where("client_secret <> ''").
		Order("id ASC").Scan(ctx); err != nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(providers))
	for _, p := range providers {
		// 出库前再过滤一次 Logo 地址：这份数据会下发到未登录的登录页，
		// 历史数据或直接改库都可能留下非 http/https 取值（见 sanitizeExternalURL）。
		logo, _ := sanitizeAssetURL(p.LogoURL)
		// 不下发 ready 之类的可用性标记：列表本身已经只含可用项，
		// 前端不需要（也不应该）再判一次「能不能用」。
		out = append(out, map[string]any{
			"name":         p.Name,
			"displayName":  p.DisplayName,
			"logoUrl":      logo,
			"providerType": p.ProviderType,
		})
	}
	return out
}

// GET /api/v1/capabilities
func (h *Handler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	admin := h.adminCapabilities(u)
	providers := h.publicProviders(r.Context())
	providerNames := make([]string, 0, len(providers))
	for _, p := range providers {
		if n, ok := p["name"].(string); ok {
			providerNames = append(providerNames, n)
		}
	}
	sp := h.loadSecurityPolicy()
	// 二次验证可用方式：前端据此渲染重验证/step-up 弹窗的输入项。
	// 没有第二因素的账号只索要密码；有 MFA 的默认走 MFA 并给出切换入口。
	factors := h.loadSecondFactorOptions(u)
	ok(w, r, map[string]any{
		"secondFactor": map[string]any{
			"required":       factors.Required,
			"mfaEnabled":     factors.MFAEnabled,
			"emailAvailable": factors.EmailAvailable,
			"methods":        factors.Methods,
		},
		"personal": map[string]bool{
			// emailChange 依赖邮件服务：新邮箱必须完成验证，
			// 未配置 SMTP 时改邮箱会让账号无法接收验证邮件，故按不可用下发。
			"profileEdit": true, "avatarUpload": true, "passwordChange": true,
			"emailChange": h.mailer.Enabled(),
			// phoneVerify 依赖短信服务：未配置时用户仍可填写手机号，
			// 但无法完成验证，届时手机号恒为未验证。
			"phoneVerify": h.smsUsable(),
			// phoneAdd 是管理员的策略开关：关闭后用户侧不展示任何手机号入口。
			"phoneAdd":          sp.PhoneAddEnabled,
			"sessionManagement": true, "grantManagement": true, "identityManagement": true,
			"securityEvents": true,
			// 自助注销依赖管理员开关；未开放时安全中心展示为不可用而不是静默失败。
			"accountDeletion": sp.AccountDeletionEnabled,
			// 邮件类自动通知依赖 SMTP：未配置时收不到，「新设备登录邮件」开关应展示为不可用。
			"notificationEmail": h.mailer.Enabled(),
		},
		"login": map[string]any{
			"password":  sp.PasswordLoginEnabled,
			"providers": providerNames,
		},
		"admin": admin,
	})
}
