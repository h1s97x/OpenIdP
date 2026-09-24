package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/captcha"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- 极验 / Cloudflare Turnstile 验证码辅助 ----

// unifiedCaptcha is the payload the frontend sends for any captcha flow.
// It carries either a GeeTest v4 proof (captcha) or a Cloudflare Turnstile
// token (turnstile). Server-side verification prefers Turnstile when it is
// configured and falls back to GeeTest otherwise.
type unifiedCaptcha = captcha.Proof

// checkEmailPolicy 校验邮箱是否符合身份验证策略：
//   - 邮箱域名白名单（仅允许指定域名）
//   - 禁止别名邮箱（+tag 形式）
//
// 返回错误信息字符串；空字符串表示通过。
func (h *Handler) checkEmailPolicy(sp *models.SecurityPolicy, email string) string {
	// 禁止别名邮箱（+tag / =tag 等别名形式）
	if sp.DisableAliasEmail {
		local := email
		if i := strings.Index(email, "@"); i >= 0 {
			local = email[:i]
		}
		if strings.Contains(local, "+") || strings.Contains(local, "=") {
			return "该邮箱为别名邮箱，已被禁止"
		}
	}
	// 邮箱域名白名单：未启用开关时跳过校验（配置了名单也不生效）。
	if sp.EmailDomainWhitelistEnabled {
		if wl := strings.TrimSpace(sp.EmailDomainWhitelist); wl != "" {
			at := strings.Index(email, "@")
			if at < 0 {
				return "请输入有效的邮箱地址"
			}
			domain := strings.ToLower(email[at+1:])
			allowed := false
			for _, d := range strings.Split(wl, ",") {
				if strings.EqualFold(strings.TrimSpace(d), domain) {
					allowed = true
					break
				}
			}
			if !allowed {
				return "该邮箱域名不在允许列表中"
			}
		}
	}
	return ""
}

// captchaProvider 返回当前生效的人机验证提供商（Turnstile 优先，其次极验）。
// 未配置任何提供商时返回空实现（Required 恒 false、Verify 恒通过），
// 调用方无需区分具体提供商。
func (h *Handler) captchaProvider() captcha.Provider {
	return captcha.NewProvider(h.captchaCfg(), h.turnstileCfg())
}

// captchaConfigPayload builds the unified captcha block for login-policy.
func (h *Handler) captchaConfigPayload() map[string]any {
	return h.captchaProvider().ConfigPayload()
}

// captchaRequiredFor 返回指定流程是否要求人机验证。
func (h *Handler) captchaRequiredFor(flow captcha.Flow) bool {
	return h.captchaProvider().Required(flow)
}

// captchaRequiredForLogin 返回登录类流程（密码/邮箱验证码/三方登录）是否要求人机验证。
func (h *Handler) captchaRequiredForLogin() bool {
	return h.captchaRequiredFor(captcha.FlowLogin)
}

// captchaRequiredForSignup 返回注册流程是否要求人机验证。
func (h *Handler) captchaRequiredForSignup() bool {
	return h.captchaRequiredFor(captcha.FlowSignup)
}

// captchaRequiredForPasswordReset 返回找回密码流程是否要求人机验证。
func (h *Handler) captchaRequiredForPasswordReset() bool {
	return h.captchaRequiredFor(captcha.FlowPasswordReset)
}

// verifyCaptcha 在流程要求人机验证时校验客户端证明（required 开关真正生效）。
// 未要求或未配置提供商时返回 (true, nil)。
func (h *Handler) verifyCaptcha(r *http.Request, c *unifiedCaptcha, required bool) (bool, error) {
	if !required {
		return true, nil
	}
	return h.captchaProvider().Verify(r.Context(), c, clientIP(r))
}

// captchaFailure 根据 verifyCaptcha 的返回错误发送准确响应：
//
//	用户尚未提交证明（或格式不完整）→ captcha.required（请先完成人机验证）
//	已提交但服务端验证拒绝/网络错误 → captcha.failed（不回显上游细节）
func (h *Handler) captchaFailure(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil && !captcha.IsNotProof(err) {
		// 上游校验失败原因可能含服务商内部信息：只记日志，不回显给客户端。
		log.Printf("⚠️ [Captcha] 校验失败: %v", err)
		fail(w, r, http.StatusBadRequest, "captcha.failed", "验证码校验失败，请重新完成人机验证")
	} else {
		fail(w, r, http.StatusBadRequest, "captcha.required", "请先完成人机验证")
	}
}

// ---- 邮箱验证码（登录 / 注册 / 找回密码） ----

const (
	codePurposeLogin  = "login"
	codePurposeSignup = "signup"
	codePurposeReset  = "reset"
	// codePurposeChangeEmail 用于邮箱变更、注销账号等高危操作的二次验证。
	codePurposeChangeEmail = "change_email"
	codeTTLMinutes         = 10
	codeCooldownSecs       = 60
)

type emailCodeReq struct {
	Email     string          `json:"email"`
	ReturnURL string          `json:"returnUrl"`
	Captcha   *unifiedCaptcha `json:"captcha"`
}

// POST /api/v1/session/email-code/request
func (h *Handler) handleEmailCodeRequest(w http.ResponseWriter, r *http.Request) {
	var req emailCodeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的邮箱地址")
		return
	}
	if msg := h.checkEmailPolicy(h.loadSecurityPolicy(), email); msg != "" {
		fail(w, r, http.StatusBadRequest, "email.policy_blocked", msg)
		return
	}
	if !h.accountLimiter.AllowKey("acct:" + email) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	// 未配置 SMTP 时禁止邮箱验证码登录（避免“提示发送成功但实际未发送”）。
	if !h.mailer.Enabled() {
		fail(w, r, http.StatusServiceUnavailable, "mail.not_configured", "邮件服务未配置，无法使用邮箱验证码登录")
		return
	}
	if ok, err := h.verifyCaptcha(r, req.Captcha, h.captchaRequiredForLogin()); !ok {
		h.captchaFailure(w, r, err)
		return
	}
	var last models.VerificationCode
	err := h.db.NewSelect().Model(&last).
		Where("email = ? AND purpose = ?", email, codePurposeLogin).
		Order("created_at DESC").Limit(1).Scan(r.Context())
	if err == nil && time.Since(last.CreatedAt) < codeCooldownSecs*time.Second {
		wait := codeCooldownSecs - int(time.Since(last.CreatedAt).Seconds())
		fail(w, r, http.StatusTooManyRequests, "email.code_cooldown", fmt.Sprintf("发送过于频繁，请 %d 秒后重试", wait))
		return
	}
	code, err := h.mailer.SendCode(email, codePurposeLogin, codeTTLMinutes, h.requestBaseURL(r))
	if err != nil {
		internal(w, r, err)
		return
	}
	h.persistCode(email, codePurposeLogin, codeTTLMinutes, code)
	ok(w, r, map[string]any{"retryAfterSeconds": codeCooldownSecs})
}

// POST /api/v1/session/email-code/verify — 邮箱验证码登录
func (h *Handler) handleEmailCodeVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email     string          `json:"email"`
		Code      string          `json:"code"`
		ReturnURL string          `json:"returnUrl"`
		Captcha   *unifiedCaptcha `json:"captcha"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的邮箱地址")
		return
	}
	if !h.accountLimiter.AllowKey("acct:" + email) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	if ok, err := h.verifyCaptcha(r, req.Captcha, h.captchaRequiredForLogin()); !ok {
		h.captchaFailure(w, r, err)
		return
	}
	if !h.checkCode(email, codePurposeLogin, req.Code) {
		fail(w, r, http.StatusBadRequest, "email.code_invalid", "验证码错误或已过期")
		return
	}
	var u models.User
	err := h.db.NewSelect().Model(&u).Where("lower(email) = lower(?)", email).Scan(r.Context())
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "user.not_found", "该邮箱尚未注册")
		return
	}
	if err != nil {
		internal(w, r, err)
		return
	}

	// 双因素认证：已启用时先发 MFA 挑战。
	// 与密码登录一致：当前设备已是该用户的有效可信设备时跳过二次验证。
	if h.userMFAEnabled(u.ID) && !h.isTrustedDevice(r, u.ID) {
		challengeID := h.createMFAChallenge(u.ID, "emailCode")
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

	h.completeLogin(w, r, &u, "emailCode", "邮箱验证码登录成功")
}

// ---- 注册 ----

// POST /api/v1/signup/email-code/request
func (h *Handler) handleSignupEmailCodeRequest(w http.ResponseWriter, r *http.Request) {
	sp := h.loadSecurityPolicy()
	if !sp.SignupEnabled {
		fail(w, r, http.StatusForbidden, "signup.disabled", "当前未开放注册")
		return
	}
	var req emailCodeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的邮箱地址")
		return
	}
	if msg := h.checkEmailPolicy(sp, email); msg != "" {
		fail(w, r, http.StatusBadRequest, "email.policy_blocked", msg)
		return
	}
	if !h.accountLimiter.AllowKey("acct:" + email) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	// 未配置 SMTP 时禁止邮箱验证注册（避免“提示发送成功但实际未发送”）。
	if !h.mailer.Enabled() {
		fail(w, r, http.StatusServiceUnavailable, "mail.not_configured", "邮件服务未配置，无法进行邮箱验证注册")
		return
	}
	if ok, err := h.verifyCaptcha(r, req.Captcha, h.captchaRequiredForSignup()); !ok {
		h.captchaFailure(w, r, err)
		return
	}
	// 邮箱已被注册（放在人机验证之后，避免未验证即泄露邮箱存在性）
	n, _ := h.db.NewSelect().Model((*models.User)(nil)).Where("lower(email) = lower(?)", email).Count(r.Context())
	if n > 0 {
		fail(w, r, http.StatusConflict, "email.exists", "该邮箱已被注册")
		return
	}
	if h.cooldownCheck(w, r, email, codePurposeSignup) {
		return
	}
	code, err := h.mailer.SendCode(email, codePurposeSignup, codeTTLMinutes, h.requestBaseURL(r))
	if err != nil {
		internal(w, r, err)
		return
	}
	h.persistCode(email, codePurposeSignup, codeTTLMinutes, code)
	ok(w, r, map[string]any{"retryAfterSeconds": codeCooldownSecs})
}

// POST /api/v1/signup
func (h *Handler) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string          `json:"email"`
		Username    string          `json:"username"`
		DisplayName string          `json:"displayName"`
		Password    string          `json:"password"`
		EmailCode   string          `json:"emailCode"`
		ReturnURL   string          `json:"returnUrl"`
		Captcha     *unifiedCaptcha `json:"captcha"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	sp := h.loadSecurityPolicy()
	if !sp.SignupEnabled {
		fail(w, r, http.StatusForbidden, "signup.disabled", "当前未开放注册")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	username := strings.TrimSpace(req.Username)
	// 管理员开放注册但关闭邮箱验证时，允许不填邮箱直接「用户名 + 密码」注册；
	// 邮箱留空落库，后续可在安全中心补绑。
	emailOptional := !sp.SignupEmailVerification
	if email == "" && !emailOptional {
		fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的邮箱地址")
		return
	}
	if email != "" {
		if !strings.Contains(email, "@") {
			fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的邮箱地址")
			return
		}
		if msg := h.checkEmailPolicy(sp, email); msg != "" {
			fail(w, r, http.StatusBadRequest, "email.policy_blocked", msg)
			return
		}
	}
	if msg := validateUsername(username); msg != "" {
		fail(w, r, http.StatusBadRequest, "username.invalid", msg)
		return
	}
	if !h.accountLimiter.AllowKey("acct:" + username) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	if msg := validatePassword(sp, req.Password); msg != "" {
		fail(w, r, http.StatusBadRequest, "password.too_weak", msg)
		return
	}
	if ok, err := h.verifyCaptcha(r, req.Captcha, h.captchaRequiredForSignup()); !ok {
		h.captchaFailure(w, r, err)
		return
	}
	if sp.SignupEmailVerification {
		// 需要邮箱验证但未配置 SMTP 时禁止注册（避免“提示发送成功但实际未发送”）。
		if !h.mailer.Enabled() {
			fail(w, r, http.StatusServiceUnavailable, "mail.not_configured", "邮件服务未配置，无法进行邮箱验证注册")
			return
		}
		if !h.checkCode(email, codePurposeSignup, req.EmailCode) {
			fail(w, r, http.StatusBadRequest, "email.code_invalid", "邮箱验证码错误或已过期")
			return
		}
	}
	// 唯一性：用户名按精确值比对（区分大小写，Admin 与 admin 是两个账号）；
	// 邮箱仍按小写归一化比对。邮箱留空时只比对用户名。
	uniq := "username = ?"
	args := []any{username}
	if email != "" {
		uniq = "username = ? OR lower(email) = lower(?)"
		args = append(args, email)
	}
	n, _ := h.db.NewSelect().Model((*models.User)(nil)).Where(uniq, args...).Count(r.Context())
	if n > 0 {
		fail(w, r, http.StatusConflict, "user.exists", "用户名或邮箱已被占用")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		internal(w, r, err)
		return
	}
	u := &models.User{
		Username:      username,
		DisplayName:   auth.FirstNonEmpty(req.DisplayName, username),
		Email:         email,
		EmailVerified: sp.SignupEmailVerification,
		AvatarURL:     defaultAvatarURL,
		PasswordHash:  hash,
		PasswordSet:   true,
	}
	if err := h.createUser(r.Context(), u); err != nil {
		internal(w, r, err)
		return
	}
	csrf := auth.RandomToken(32)
	sessID, err := h.issueSession(w, r, u, "email")
	if err != nil {
		internal(w, r, err)
		return
	}
	h.tokens.Set(csrf, u.ID, sessID)
	h.logEvent(r, u.ID, &models.Event{
		Type:     "signup.success",
		Summary:  "注册成功",
		Metadata: map[string]string{"method": "email"},
	})
	// 邮箱注册后默认发送验证邮件：若注册流程未通过验证码完成邮箱验证（signupEmailVerification 关闭），
	// 且邮件服务可用，则自动向用户发送一封验证邮件。
	if !u.EmailVerified && h.mailer.Enabled() && u.Email != "" {
		token := auth.RandomHex(24)
		h.tokens.Set("email:verify:"+token, u.ID, "")
		if err := h.mailer.SendVerifyLink(u.Email, auth.FirstNonEmpty(u.DisplayName, u.Username), token, h.requestBaseURL(r)); err == nil {
			h.logEvent(r, u.ID, &models.Event{Type: "email.verify_sent", Summary: "注册后自动发送邮箱验证邮件"})
		}
	}
	ok(w, r, h.sessionPayloadWithIP(r, u, csrf))
}

// ---- 找回密码 ----

// POST /api/v1/password-reset/request
func (h *Handler) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	// 安全策略开关：管理员关闭找回密码后，整条找回流程必须真正不可用。
	if !h.loadSecurityPolicy().PasswordResetEnabled {
		fail(w, r, http.StatusForbidden, "password.reset_disabled", "当前未开放找回密码")
		return
	}
	var req struct {
		Email   string          `json:"email"`
		Captcha *unifiedCaptcha `json:"captcha"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的邮箱地址")
		return
	}
	if !h.accountLimiter.AllowKey("acct:" + email) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	if ok, err := h.verifyCaptcha(r, req.Captcha, h.captchaRequiredForPasswordReset()); !ok {
		h.captchaFailure(w, r, err)
		return
	}
	if h.cooldownCheck(w, r, email, codePurposeReset) {
		return
	}
	// 无论邮箱是否注册都返回成功（防枚举）
	code, err := h.mailer.SendCode(email, codePurposeReset, codeTTLMinutes, h.requestBaseURL(r))
	if err != nil {
		internal(w, r, err)
		return
	}
	h.persistCode(email, codePurposeReset, codeTTLMinutes, code)
	ok(w, r, map[string]any{"success": true})
}

// POST /api/v1/password-reset/confirm
func (h *Handler) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.loadSecurityPolicy().PasswordResetEnabled {
		fail(w, r, http.StatusForbidden, "password.reset_disabled", "当前未开放找回密码")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !h.accountLimiter.AllowKey("acct:" + email) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	// 与注册/改密保持一致的安全策略（不只校验长度）。
	if msg := validatePassword(h.loadSecurityPolicy(), req.Password); msg != "" {
		fail(w, r, http.StatusBadRequest, "password.too_weak", msg)
		return
	}
	if !h.checkCode(email, codePurposeReset, req.Code) {
		fail(w, r, http.StatusBadRequest, "email.code_invalid", "验证码错误或已过期")
		return
	}
	var u models.User
	err := h.db.NewSelect().Model(&u).Where("lower(email) = lower(?)", email).Scan(r.Context())
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "user.not_found", "该邮箱尚未注册")
		return
	}
	if err != nil {
		internal(w, r, err)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		internal(w, r, err)
		return
	}
	u.PasswordHash = hash
	u.PasswordSet = true
	if _, err := h.db.NewUpdate().Model(&u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	// 重置成功后撤销该用户的所有会话，防止旧会话在密码重置后继续可用。
	if _, err := h.db.NewDelete().Model((*models.Session)(nil)).
		Where("user_id = ?", u.ID).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "password.reset", Summary: "通过邮箱验证码重置密码"})
	ok(w, r, map[string]any{"success": true})
}
