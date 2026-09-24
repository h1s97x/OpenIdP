package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/captcha"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/mail"
	"github.com/h1s97x/openidp/api/internal/mfa"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/sms"
)

// ---- 设置持久化（SMTP / 人机验证）----
// applyPersistedSettings loads the admin-persisted mail & captcha settings
// from the database and applies them at runtime (persisted values win over env).
func (h *Handler) applyPersistedSettings() {
	// 邮件（仅当开关开启且配置了主机时才启用 SMTP；否则保持停用状态）
	ms := h.loadMailSetting()
	if ms.Enabled && ms.Host != "" {
		h.mailer.Reconfigure(mail.Config{
			Enabled: true,
			Host:    ms.Host, Port: ms.Port,
			User: ms.User, Password: secretpkg.Decrypt(ms.Password),
			From: ms.From, FromName: ms.FromName,
			UseTLS: ms.UseTLS, InsecureSkipVerify: ms.SkipVerify,
			Template: ms.Template,
			SiteName: h.cfg.SiteDisplay,
			SiteURL:  h.cfg.SiteURL,
		})
	} else {
		// 未开启或未配置主机时停用邮件发送
		h.mailer.Reconfigure(mail.Config{
			Enabled:  false,
			Host:     "",
			SiteName: h.cfg.SiteDisplay,
			SiteURL:  h.cfg.SiteURL,
		})
	}

	// 人机验证（管理员后台持久化配置优先）
	cs := h.loadCaptchaSetting()
	h.applyCaptchaSetting(cs)

	// 短信验证码（管理员后台持久化配置优先）
	h.applySmsSetting(h.loadSmsSetting())
}

// loadMailSetting returns the persisted mail setting (single row, id=1).
func (h *Handler) loadMailSetting() *models.MailSetting {
	return cached(h.conf, peekMail, storeMail, h.fetchMailSetting)
}

// fetchMailSetting 从数据库读取邮件设置；缺失时写入一行空配置。
// 初始化不填入任何内容：主机 / 账号 / 密码 / 发件人 / 模板等全部留空，
// 由管理员在「系统设置 → 邮件服务」中自行填写；未配置主机时邮件服务保持停用。
func (h *Handler) fetchMailSetting() *models.MailSetting {
	ms := &models.MailSetting{}
	err := h.db.NewSelect().Model(ms).Where("id = 1").Scan(context.Background())
	if err != nil {
		// Enabled 是开关而非内容：空配置一律停用，避免用空主机尝试发信。
		ms = &models.MailSetting{
			ID:        1,
			Enabled:   false,
			Host:      "",
			Port:      h.cfg.SMTPPort,
			User:      "",
			Password:  "",
			From:      "",
			FromName:  "",
			Template:  "",
			UpdatedAt: db.Now(),
		}
		_, _ = h.db.NewInsert().Model(ms).Exec(context.Background())
	}
	return ms
}

// loadCaptchaSetting returns the persisted captcha setting (single row, id=1).
func (h *Handler) loadCaptchaSetting() *models.CaptchaSetting {
	return cached(h.conf, peekCapt, storeCapt, h.fetchCaptchaSetting)
}

// fetchCaptchaSetting 从数据库读取人机验证设置；缺失时写入一行空配置。
// 初始化不填入任何内容：提供商与各类密钥 / ID / API 域名全部留空，
// 由管理员在「系统设置 → 人机验证」中自行填写；未配置提供商时人机验证保持停用。
func (h *Handler) fetchCaptchaSetting() *models.CaptchaSetting {
	cs := &models.CaptchaSetting{}
	err := h.db.NewSelect().Model(cs).Where("id = 1").Scan(context.Background())
	if err != nil {
		// Provider 留空即 none：applyCaptchaSetting 会同时停用两类验证。
		cs = &models.CaptchaSetting{
			ID:                       1,
			Provider:                 "",
			GeetestCaptchaID:         "",
			GeetestCaptchaKey:        "",
			GeetestAPIDomain:         "",
			GeetestBindMode:          "",
			TurnstileSiteKey:         "",
			TurnstileSecretKey:       "",
			RequiredForLogin:         h.cfg.TurnstileRequiredForLogin || h.cfg.GeetestRequiredForLogin,
			RequiredForSignup:        h.cfg.TurnstileRequiredForSignup || h.cfg.GeetestRequiredForSignup,
			RequiredForPasswordReset: false,
			UpdatedAt:                db.Now(),
		}
		_, _ = h.db.NewInsert().Model(cs).Exec(context.Background())
	}
	return cs
}

// applyCaptchaSetting applies a persisted captcha setting at runtime.
//
// 写入方式：先构造好完整的不可变配置副本，再整体原子替换。
// 直接原地改字段会让并发的登录请求读到「一半新一半旧」的配置
// （例如 SiteKey 已更新而 SecretKey 还是旧的）。
func (h *Handler) applyCaptchaSetting(cs *models.CaptchaSetting) {
	switch cs.Provider {
	case "turnstile":
		ts := *h.turnstileCfg()
		ts.SiteKey = auth.FirstNonEmpty(cs.TurnstileSiteKey, h.cfg.TurnstileSiteKey)
		ts.SecretKey = auth.FirstNonEmpty(secretpkg.Decrypt(cs.TurnstileSecretKey), h.cfg.TurnstileSecretKey)
		ts.RequiredForLogin = cs.RequiredForLogin
		ts.RequiredForSignup = cs.RequiredForSignup
		ts.RequiredForPasswordReset = cs.RequiredForPasswordReset
		// 校验端点同样优先取库内配置，未配置时回落到环境变量/内置默认：
		// 后台原本能保存该字段却从不生效，填了等于白填。
		ts.VerifyURL = auth.FirstNonEmpty(cs.TurnstileVerifyURL, h.cfg.TurnstileVerifyURL)
		ts.Enabled = ts.SiteKey != "" && ts.SecretKey != ""
		h.turnstile.Store(&ts)
		geetest := *h.captchaCfg()
		geetest.Enabled = false
		h.captcha.Store(&geetest)
	case "geetest":
		geetest := *h.captchaCfg()
		geetest.CaptchaID = auth.FirstNonEmpty(cs.GeetestCaptchaID, h.cfg.GeetestCaptchaID)
		geetest.CaptchaKey = auth.FirstNonEmpty(secretpkg.Decrypt(cs.GeetestCaptchaKey), h.cfg.GeetestCaptchaKey)
		geetest.RequiredForLogin = cs.RequiredForLogin
		geetest.RequiredForSignup = cs.RequiredForSignup
		geetest.RequiredForPasswordReset = cs.RequiredForPasswordReset
		geetest.BindMode = auth.FirstNonEmpty(cs.GeetestBindMode, h.cfg.GeetestBindMode, "bind")
		geetest.APIDomain = auth.FirstNonEmpty(cs.GeetestAPIDomain, h.cfg.GeetestAPIDomain)
		geetest.Enabled = geetest.CaptchaID != "" && geetest.CaptchaKey != ""
		h.captcha.Store(&geetest)
		ts := *h.turnstileCfg()
		ts.Enabled = false
		h.turnstile.Store(&ts)
	default:
		ts := *h.turnstileCfg()
		ts.Enabled = false
		h.turnstile.Store(&ts)
		geetest := *h.captchaCfg()
		geetest.Enabled = false
		h.captcha.Store(&geetest)
	}
}

// ---- 短信验证码设置 ----

// loadSmsSetting returns the persisted SMS setting (single row, id=1).
func (h *Handler) loadSmsSetting() *models.SmsSetting {
	return cached(h.conf, peekSms, storeSms, h.fetchSmsSetting)
}

// fetchSmsSetting 从数据库读取短信设置；缺失时写入一行空配置。
// 空配置一律停用：未选择服务商 / 未填凭据时不允许发送验证码。
func (h *Handler) fetchSmsSetting() *models.SmsSetting {
	ss := &models.SmsSetting{}
	err := h.db.NewSelect().Model(ss).Where("id = 1").Scan(context.Background())
	if err != nil {
		ss = &models.SmsSetting{
			ID:        1,
			Enabled:   false,
			Provider:  "",
			CodeTTL:   5,
			Cooldown:  60,
			UpdatedAt: db.Now(),
		}
		_, _ = h.db.NewInsert().Model(ss).Exec(context.Background())
	}
	return ss
}

// smsConfig 把持久化设置转换为运行时配置（凭据解密后注入）。
func smsConfig(ss *models.SmsSetting) *sms.Config {
	return &sms.Config{
		Enabled:  ss.Enabled,
		Provider: ss.Provider,
		SiteName: ss.SiteName,
		CodeTTL:  ss.CodeTTL,
		Cooldown: ss.Cooldown,

		AliyunAccessKeyID:     ss.AliyunAccessKeyID,
		AliyunAccessKeySecret: secretpkg.Decrypt(ss.AliyunAccessKeySecret),
		AliyunSignName:        ss.AliyunSignName,
		AliyunTemplateCode:    ss.AliyunTemplateCode,
		AliyunEndpoint:        ss.AliyunEndpoint,

		TencentSecretID:  ss.TencentSecretID,
		TencentSecretKey: secretpkg.Decrypt(ss.TencentSecretKey),
		TencentSdkAppID:  ss.TencentSdkAppID,
		TencentSignName:  ss.TencentSignName,
		TencentTemplate:  ss.TencentTemplate,
		TencentRegion:    ss.TencentRegion,

		VolcAccessKeyID:     ss.VolcAccessKeyID,
		VolcAccessKeySecret: secretpkg.Decrypt(ss.VolcAccessKeySecret),
		VolcSmsAccount:      ss.VolcSmsAccount,
		VolcSign:            ss.VolcSign,
		VolcTemplateID:      ss.VolcTemplateID,
		VolcRegion:          ss.VolcRegion,

		HuaweiAppKey:    ss.HuaweiAppKey,
		HuaweiAppSecret: secretpkg.Decrypt(ss.HuaweiAppSecret),
		HuaweiSender:    ss.HuaweiSender,
		HuaweiTemplate:  ss.HuaweiTemplate,
		HuaweiEndpoint:  ss.HuaweiEndpoint,

		QimoAccountSID: ss.QimoAccountSID,
		QimoAuthToken:  secretpkg.Decrypt(ss.QimoAuthToken),
		QimoAppID:      ss.QimoAppID,
		QimoTemplate:   ss.QimoTemplate,

		SubmailAppID:    ss.SubmailAppID,
		SubmailAppKey:   secretpkg.Decrypt(ss.SubmailAppKey),
		SubmailSign:     ss.SubmailSign,
		SubmailTemplate: ss.SubmailTemplate,

		CustomURL:     ss.CustomURL,
		CustomMethod:  ss.CustomMethod,
		CustomHeaders: ss.CustomHeaders,
		CustomBody:    ss.CustomBody,
		CustomSecret:  secretpkg.Decrypt(ss.CustomSecret),
	}
}

// applySmsSetting applies a persisted SMS setting at runtime.
func (h *Handler) applySmsSetting(ss *models.SmsSetting) {
	// 整体替换而非原地改字段：并发发送验证码的请求可能正读取旧配置。
	h.sms.Store(smsConfig(ss))
}

// smsUsable 报告短信服务当前是否可用（总开关开启且服务商配置完整）。
func (h *Handler) smsUsable() bool {
	cfg := h.smsCfg()
	return cfg.Enabled && sms.NewProvider(cfg).Enabled()
}

// ---- MFA (TOTP) ----

// GET /api/v1/me/mfa
func (h *Handler) handleMFAGet(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	m := h.loadMFA(u.ID)
	ok(w, r, map[string]any{"enabled": m != nil && m.Enabled})
}

// GET /api/v1/me/mfa/begin — start TOTP enrollment, returns provisioning info.
func (h *Handler) handleMFABegin(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	m := h.loadMFA(u.ID)
	if m == nil {
		m = &models.MFA{UserID: u.ID, Enabled: false}
	}
	if m.Enabled {
		fail(w, r, http.StatusBadRequest, "mfa.already_enabled", "双因素认证已启用")
		return
	}
	secret, err := mfa.GenerateSecret()
	if err != nil {
		internal(w, r, err)
		return
	}
	m.Secret = secretpkg.Encrypt(secret)
	m.Enabled = false
	m.UpdatedAt = db.Now()
	if err := h.saveMFA(m); err != nil {
		internal(w, r, err)
		return
	}
	account := u.Email
	if account == "" {
		account = u.Username
	}
	issuer := h.cfg.SiteDisplay
	ok(w, r, map[string]any{
		"secret":          secret,
		"provisioningUri": mfa.ProvisioningURI(issuer, account, secret),
		"issuer":          issuer,
		"account":         account,
	})
}

// POST /api/v1/me/mfa/confirm {code} — confirm a TOTP code to enable MFA.
func (h *Handler) handleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	m := h.loadMFA(u.ID)
	if m == nil || m.Secret == "" {
		fail(w, r, http.StatusBadRequest, "mfa.not_started", "请先获取密钥并完成绑定")
		return
	}
	if !mfa.Verify(m.Secret, req.Code) {
		fail(w, r, http.StatusBadRequest, "mfa.code_invalid", "验证码错误，请重试")
		return
	}
	codes, err := mfa.GenerateRecoveryCodes(10)
	if err != nil {
		internal(w, r, err)
		return
	}
	raw, _ := json.Marshal(codes)
	m.RecoveryCodes = []byte(secretpkg.Encrypt(string(raw)))
	m.Enabled = true
	m.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(m).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "mfa.enabled", Summary: "启用双因素认证"})
	ok(w, r, map[string]any{"success": true, "recoveryCodes": codes})
}

// POST /api/v1/me/mfa/disable {code?} — disable MFA (requires current TOTP or recovery code).
func (h *Handler) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	m := h.loadMFA(u.ID)
	if m == nil || !m.Enabled {
		fail(w, r, http.StatusBadRequest, "mfa.not_enabled", "双因素认证未启用")
		return
	}
	if !mfa.Verify(m.Secret, req.Code) && !h.consumeRecoveryCode(m, req.Code, r.Context()) {
		fail(w, r, http.StatusBadRequest, "mfa.code_invalid", "验证码错误，无法关闭双因素认证")
		return
	}
	m.Enabled = false
	m.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(m).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "mfa.disabled", Summary: "关闭双因素认证"})
	ok(w, r, map[string]any{"success": true})
}

// POST /api/v1/me/mfa/recovery-codes — regenerate recovery codes (requires TOTP).
func (h *Handler) handleMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	m := h.loadMFA(u.ID)
	if m == nil || !m.Enabled {
		fail(w, r, http.StatusBadRequest, "mfa.not_enabled", "双因素认证未启用")
		return
	}
	if !mfa.Verify(m.Secret, req.Code) {
		fail(w, r, http.StatusBadRequest, "mfa.code_invalid", "验证码错误，请重试")
		return
	}
	codes, err := mfa.GenerateRecoveryCodes(10)
	if err != nil {
		internal(w, r, err)
		return
	}
	raw, _ := json.Marshal(codes)
	m.RecoveryCodes = []byte(secretpkg.Encrypt(string(raw)))
	m.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(m).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, map[string]any{"success": true, "recoveryCodes": codes})
}

// POST /api/v1/session/mfa/verify — complete a two-factor challenge at login.
func (h *Handler) handleSessionMFAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		fail(w, r, http.StatusBadRequest, "mfa.challenge_invalid", "二次验证会话已失效，请重新登录")
		return
	}
	var ch models.MFAChallenge
	err := h.db.NewSelect().Model(&ch).Where("id = ?", challengeID).Scan(r.Context())
	if errors.Is(err, sql.ErrNoRows) || ch.Used || time.Now().After(ch.ExpiresAt) {
		if err == nil {
			_, _ = h.db.NewDelete().Model(&ch).WherePK().Exec(r.Context())
		}
		fail(w, r, http.StatusBadRequest, "mfa.challenge_invalid", "二次验证会话已失效，请重新登录")
		return
	}
	if err != nil {
		internal(w, r, err)
		return
	}
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", ch.UserID).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "user.not_found", "用户不存在")
		return
	}
	// 按用户维度限流：叠加在 IP 限流之上，6 位 TOTP 空间有限，
	// 必须防止分布式/慢速爆破绕过单 IP 限制。
	if !h.accountLimiter.AllowKey("mfa:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "尝试次数过多，请稍后再试")
		return
	}
	m := h.loadMFA(u.ID)
	codeOK := m != nil && mfa.Verify(m.Secret, req.Code)
	if !codeOK {
		// 回退到恢复码（一次性）。
		if !h.consumeRecoveryCode(m, req.Code, r.Context()) {
			// 校验失败：原子累加尝试次数，达到上限即作废该挑战（防 6 位验证码爆破）。
			h.countMFAFailure(u.ID, &ch)
			h.logEvent(r, ch.UserID, &models.Event{
				Type:     "mfa.verify_failed",
				Summary:  "二次验证失败",
				Metadata: map[string]string{"method": ch.Method},
			})
			fail(w, r, http.StatusBadRequest, "mfa.code_invalid", "验证码错误，请重试")
			return
		}
	}
	// 消耗挑战（原子条件更新，防止并发重复消费同一挑战）
	res, err := h.db.NewUpdate().Model(&ch).
		Set("used = true").
		Where("id = ? AND used = false", ch.ID).
		Exec(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		fail(w, r, http.StatusBadRequest, "mfa.challenge_invalid", "二次验证会话已失效，请重新登录")
		return
	}

	h.completeLogin(w, r, &u, "password", "密码+二次验证登录成功")
}

// maxMFAAttempts 是单个二次验证挑战允许的错误尝试次数。
// 6 位 TOTP 只有 10^6 空间，达到上限即作废挑战，杜绝无限爆破。
const maxMFAAttempts = 5

// countMFAFailure 原子累加挑战的错误尝试次数，并在同一条 SQL 中判断是否达到上限
// （并发安全，避免多个请求基于同一旧值判断导致 attempts 远超上限才作废）。
func (h *Handler) countMFAFailure(userID int64, ch *models.MFAChallenge) {
	ctx := context.Background()
	// 达到上限时直接作废（used=true），后续校验一律失败。
	res, err := h.db.NewUpdate().Model((*models.MFAChallenge)(nil)).
		Set("attempts = attempts + 1, used = CASE WHEN attempts + 1 >= ? THEN true ELSE used END", maxMFAAttempts).
		Where("id = ? AND used = false", ch.ID).
		Exec(ctx)
	if err != nil {
		return
	}
	ch.Attempts++
	if n, _ := res.RowsAffected(); n > 0 && ch.Attempts >= maxMFAAttempts {
		h.logEvent(nil, userID, &models.Event{
			Type:    "mfa.challenge_locked",
			Summary: "二次验证尝试次数过多，挑战已作废",
		})
	}
}

// consumeRecoveryCode 校验并消费一次性恢复码（命中即从余量中移除并重新加密落库）。
// 返回 true 表示命中；原先在三处（MFA 关闭、MFA 挑战校验、高危操作二次确认）
// 各写一遍的逻辑统一收敛到这里。
func (h *Handler) consumeRecoveryCode(m *models.MFA, code string, ctx context.Context) bool {
	var codes []string
	if m == nil || len(m.RecoveryCodes) == 0 {
		return false
	}
	_ = json.Unmarshal(m.RecoveryCodes, &codes)
	okV, remaining := mfa.VerifyRecoveryCode(codes, code)
	if !okV {
		return false
	}
	raw, _ := json.Marshal(remaining)
	m.RecoveryCodes = []byte(secretpkg.Encrypt(string(raw)))
	_, _ = h.db.NewUpdate().Model(m).Set("recovery_codes = ?", m.RecoveryCodes).WherePK().Exec(ctx)
	return true
}

// loadMFA returns the MFA record for a user (nil if absent).
// 返回前将 TOTP 密钥与恢复码解密（库内密文存储，内存中明文用于校验）。
func (h *Handler) loadMFA(userID int64) *models.MFA {
	m := &models.MFA{}
	err := h.db.NewSelect().Model(m).Where("user_id = ?", userID).Scan(context.Background())
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return nil
	}
	m.Secret = secretpkg.Decrypt(m.Secret)
	m.RecoveryCodes = []byte(secretpkg.Decrypt(string(m.RecoveryCodes)))
	return m
}

// saveMFA 写入（新增或覆盖）用户的 MFA 记录，按 user_id 唯一。
// 采用先查后写的方式，避免在仅支持部分 UPSERT 语法的方言上生成非法 SQL。
func (h *Handler) saveMFA(m *models.MFA) error {
	existing := &models.MFA{}
	err := h.db.NewSelect().Model(existing).Where("user_id = ?", m.UserID).Scan(context.Background())
	switch {
	case err == nil:
		m.ID = existing.ID
		if m.CreatedAt.IsZero() {
			m.CreatedAt = existing.CreatedAt
		}
		_, err = h.db.NewUpdate().Model(m).
			Set("secret = ?", m.Secret).
			Set("enabled = ?", m.Enabled).
			Set("updated_at = ?", m.UpdatedAt).
			Where("user_id = ?", m.UserID).Exec(context.Background())
		return err
	case errors.Is(err, sql.ErrNoRows):
		if m.CreatedAt.IsZero() {
			m.CreatedAt = m.UpdatedAt
		}
		_, err = h.db.NewInsert().Model(m).Exec(context.Background())
		return err
	default:
		return err
	}
}

// createMFAChallenge issues a pending two-factor challenge.
// 同一用户只保留一个有效挑战：签发前先清理该用户待验证的挑战，
// 避免攻击者堆积大量挑战绕过按挑战计数的尝试上限。
func (h *Handler) createMFAChallenge(userID int64, method string) string {
	_, _ = h.db.NewDelete().Model((*models.MFAChallenge)(nil)).
		Where("user_id = ?", userID).Exec(context.Background())
	ch := &models.MFAChallenge{
		ID:        auth.NewID(),
		UserID:    userID,
		Method:    method,
		ExpiresAt: db.Now().Add(10 * time.Minute),
		CreatedAt: db.Now(),
	}
	_, _ = h.db.NewInsert().Model(ch).Exec(context.Background())
	return ch.ID
}

// userMFAEnabled reports whether the user has two-factor enabled.
func (h *Handler) userMFAEnabled(userID int64) bool {
	m := h.loadMFA(userID)
	return m != nil && m.Enabled
}

// ---- Admin mail & captcha settings API ----

// GET /api/v1/admin/mail — full persisted config (no secret echoed)
func (h *Handler) handleAdminMail(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ms := h.loadMailSetting()
	ok(w, r, map[string]any{
		"enabled":     ms.Enabled,
		"provider":    "smtp",
		"host":        ms.Host,
		"port":        ms.Port,
		"user":        ms.User,
		"fromEmail":   ms.From,
		"fromName":    ms.FromName,
		"useTLS":      ms.UseTLS,
		"skipVerify":  ms.SkipVerify,
		"hasPassword": ms.Password != "",
		"testResult":  nil,
		// usable 是「真的能发信」的判定（开关开启且主机非空），
		// 与 h.mailer.Enabled() 同源：前端据此决定邮件类通知开关是否可用。
		"usable": h.mailer.Enabled(),
	})
}

// PATCH /api/v1/admin/mail — update SMTP config (optionally template) and persist.
func (h *Handler) handleAdminUpdateMail(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Enabled    *bool  `json:"enabled"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		User       string `json:"user"`
		Password   string `json:"password"`
		FromEmail  string `json:"fromEmail"`
		FromName   string `json:"fromName"`
		UseTLS     *bool  `json:"useTLS"`
		SkipVerify *bool  `json:"skipVerify"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	ms := h.loadMailSetting()
	if req.Enabled != nil {
		ms.Enabled = *req.Enabled
	}
	ms.Host = strings.TrimSpace(req.Host)
	if req.Port > 0 {
		ms.Port = req.Port
	}
	ms.User = strings.TrimSpace(req.User)
	if req.Password != "" {
		ms.Password = secretpkg.Encrypt(req.Password)
	}
	if req.FromEmail != "" {
		ms.From = req.FromEmail
	}
	if req.FromName != "" {
		ms.FromName = req.FromName
	}
	if req.UseTLS != nil {
		ms.UseTLS = *req.UseTLS
	}
	if req.SkipVerify != nil {
		ms.SkipVerify = *req.SkipVerify
	}
	// 功能校验：未配置 SMTP 主机时不允许开启邮件服务。
	// 否则库里的开关是「已启用」，实际发信仍被 mail.Sender 判为不可用——
	// 界面显示已开启、用户却收不到任何邮件，比明确拒绝更容易误导排查。
	if ms.Enabled && strings.TrimSpace(ms.Host) == "" {
		fail(w, r, http.StatusBadRequest, "mail.host_required", "请先填写 SMTP 主机地址，再开启邮件服务")
		return
	}
	ms.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(ms).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	// 只记录字段名，不记录值（含 SMTP 密码等凭据）。
	h.auditConfigChange(r, "mail", "update", 0, []string{
		"enabled", "host", "port", "user", "password", "fromEmail", "fromName",
		"useTLS", "skipVerify",
	})
	h.logEvent(r, 0, &models.Event{Type: "admin.mail_updated", Summary: "管理员更新邮件服务配置"})
	// 立即生效（启用开关 + 主机配置共同决定邮件是否可用）
	h.mailer.Reconfigure(mail.Config{
		Enabled: ms.Enabled,
		Host:    ms.Host, Port: ms.Port,
		User: ms.User, Password: secretpkg.Decrypt(ms.Password),
		From: ms.From, FromName: ms.FromName,
		UseTLS: ms.UseTLS, InsecureSkipVerify: ms.SkipVerify,
		Template: ms.Template, SiteName: h.cfg.SiteDisplay, SiteURL: h.cfg.SiteURL,
	})
	ok(w, r, ms)
}

// POST /api/v1/admin/mail/test {to} — send a test email.
func (h *Handler) handleAdminMailTest(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	to := strings.TrimSpace(req.To)
	if to == "" || !strings.Contains(to, "@") {
		fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的收件邮箱")
		return
	}
	if err := h.mailer.SendTest(to); err != nil {
		h.logEvent(r, 0, &models.Event{Type: "admin.mail_test_failed", Summary: "测试邮件发送失败"})
		fail(w, r, http.StatusBadGateway, "mail.test_failed", "测试邮件发送失败，请检查 SMTP 配置后重试")
		return
	}
	ok(w, r, map[string]any{"success": true, "to": to})
}

// GET /api/v1/admin/captcha — captcha configuration for the admin console.
func (h *Handler) handleAdminCaptcha(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	cs := h.loadCaptchaSetting()
	// 供管理后台展示的内置默认域名（未覆盖时的默认值）
	geetestDefaultDomain := captcha.DefaultAPIDomain
	turnstileDefaultDomain := captcha.DefaultVerifyURL
	ok(w, r, map[string]any{
		"provider":                  cs.Provider,
		"geetestCaptchaId":          cs.GeetestCaptchaID,
		"geetestApiDomain":          cs.GeetestAPIDomain,
		"geetestApiDomainDefault":   geetestDefaultDomain,
		"geetestBindMode":           cs.GeetestBindMode,
		"hasGeetestKey":             cs.GeetestCaptchaKey != "",
		"turnstileSiteKey":          cs.TurnstileSiteKey,
		"turnstileVerifyUrl":        auth.FirstNonEmpty(cs.TurnstileVerifyURL, h.cfg.TurnstileVerifyURL),
		"turnstileVerifyUrlDefault": turnstileDefaultDomain,
		"hasTurnstileKey":           cs.TurnstileSecretKey != "",
		"requiredForLogin":          cs.RequiredForLogin,
		"requiredForSignup":         cs.RequiredForSignup,
		"requiredForPasswordReset":  cs.RequiredForPasswordReset,
		"geetestEnabled":            h.captchaCfg().Enabled,
		"turnstileEnabled":          h.turnstileCfg().Enabled,
		"active":                    h.captchaConfigPayload(),
	})
}

// PATCH /api/v1/admin/captcha — update captcha config and apply at runtime.
func (h *Handler) handleAdminUpdateCaptcha(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Provider           string `json:"provider"`
		GeetestCaptchaID   string `json:"geetestCaptchaId"`
		GeetestCaptchaKey  string `json:"geetestCaptchaKey"`
		GeetestAPIDomain   string `json:"geetestApiDomain"`
		GeetestBindMode    string `json:"geetestBindMode"`
		TurnstileSiteKey   string `json:"turnstileSiteKey"`
		TurnstileSecretKey string `json:"turnstileSecretKey"`
		// TurnstileVerifyUrl 自定义 siteverify 端点（留空使用内置默认）。
		TurnstileVerifyURL       string `json:"turnstileVerifyUrl"`
		RequiredForLogin         bool   `json:"requiredForLogin"`
		RequiredForSignup        bool   `json:"requiredForSignup"`
		RequiredForPasswordReset bool   `json:"requiredForPasswordReset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	// 取值白名单校验：未知 provider 会落到 applyCaptchaSetting 的 default 分支
	// 把两类验证同时静默关掉，管理员看到的却是「已保存」。
	switch strings.TrimSpace(req.Provider) {
	case "turnstile", "geetest", "none":
	default:
		fail(w, r, http.StatusBadRequest, "captcha.invalid_provider", "验证提供商取值无效")
		return
	}
	cs := h.loadCaptchaSetting()
	cs.Provider = strings.TrimSpace(req.Provider)
	cs.GeetestCaptchaID = strings.TrimSpace(req.GeetestCaptchaID)
	if req.GeetestCaptchaKey != "" {
		cs.GeetestCaptchaKey = secretpkg.Encrypt(req.GeetestCaptchaKey)
	}
	cs.GeetestAPIDomain = strings.TrimSpace(req.GeetestAPIDomain)
	cs.GeetestBindMode = req.GeetestBindMode
	cs.TurnstileSiteKey = strings.TrimSpace(req.TurnstileSiteKey)
	cs.TurnstileVerifyURL = strings.TrimSpace(req.TurnstileVerifyURL)
	if req.TurnstileSecretKey != "" {
		cs.TurnstileSecretKey = secretpkg.Encrypt(req.TurnstileSecretKey)
	}
	cs.RequiredForLogin = req.RequiredForLogin
	cs.RequiredForSignup = req.RequiredForSignup
	cs.RequiredForPasswordReset = req.RequiredForPasswordReset
	cs.UpdatedAt = db.Now()

	// 保存前对极验做一次服务端校验，避免“私钥 captcha_key 与 captcha_id 不匹配”
	// 这类配置错误被静默落库、直到登录才报 sign_token error。
	// 仅在能明确诊断为凭据/域名问题时拦截；网络不可达（超时/DNS）则放行，
	// 避免离线/代理环境无法保存配置。
	if cs.Provider == "geetest" {
		id := cs.GeetestCaptchaID
		key := req.GeetestCaptchaKey
		if strings.TrimSpace(key) == "" {
			key = secretpkg.Decrypt(cs.GeetestCaptchaKey)
		}
		if strings.TrimSpace(id) != "" && strings.TrimSpace(key) != "" {
			if _, terr := captcha.TestConnection(r.Context(), cs.GeetestAPIDomain, id, key); terr != nil {
				msg := terr.Error()
				if strings.Contains(msg, "HTTP") || strings.Contains(msg, "初始化失败") || strings.Contains(msg, "解析失败") {
					fail(w, r, http.StatusBadRequest, "captcha.key_mismatch",
						"极验校验未通过："+msg+"（请确认 captcha_key 与 captcha_id 属于同一极验验证码，且保存时密钥字段已正确填写）")
					return
				}
			}
		}
	}

	if _, err := h.db.NewUpdate().Model(cs).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	h.applyCaptchaSetting(cs)
	h.auditConfigChange(r, "captcha", "update", 0, []string{
		"provider", "geetestCaptchaId", "geetestCaptchaKey", "geetestApiDomain", "geetestBindMode",
		"turnstileSiteKey", "turnstileSecretKey", "turnstileVerifyUrl",
		"requiredForLogin", "requiredForSignup", "requiredForPasswordReset",
	})
	h.logEvent(r, 0, &models.Event{Type: "admin.captcha_updated", Summary: "管理员更新人机验证配置"})
	ok(w, r, cs)
}

// POST /api/v1/admin/captcha/test — 测试人机验证连接（不保存，仅验证配置有效）。
// 用户填好密钥后点击“测试连接”，后端用当前输入值直接请求验证服务。
func (h *Handler) handleAdminCaptchaTest(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Provider           string `json:"provider"`
		GeetestCaptchaID   string `json:"geetestCaptchaId"`
		GeetestCaptchaKey  string `json:"geetestCaptchaKey"`
		GeetestAPIDomain   string `json:"geetestApiDomain"`
		TurnstileSiteKey   string `json:"turnstileSiteKey"`
		TurnstileSecretKey string `json:"turnstileSecretKey"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	switch req.Provider {
	case "geetest":
		id := strings.TrimSpace(req.GeetestCaptchaID)
		key := req.GeetestCaptchaKey
		domain := strings.TrimSpace(req.GeetestAPIDomain)
		// 密钥留空时回退到库内已保存的值（便于“未修改密钥仅测试”）
		if key == "" {
			cs := h.loadCaptchaSetting()
			key = secretpkg.Decrypt(cs.GeetestCaptchaKey)
			if strings.TrimSpace(domain) == "" {
				domain = cs.GeetestAPIDomain
			}
		}
		result, err := captcha.TestConnection(r.Context(), domain, id, key)
		if err != nil {
			fail(w, r, http.StatusBadGateway, "captcha.test_failed", "极验连接失败："+err.Error())
			return
		}
		ok(w, r, result)
	case "turnstile":
		siteKey := strings.TrimSpace(req.TurnstileSiteKey)
		secretKey := req.TurnstileSecretKey
		verifyURL := ""
		// 密钥留空时回退到库内已保存的值（便于"未修改密钥仅测试"）
		if secretKey == "" || siteKey == "" {
			cs := h.loadCaptchaSetting()
			if secretKey == "" {
				secretKey = secretpkg.Decrypt(cs.TurnstileSecretKey)
			}
			if siteKey == "" {
				siteKey = cs.TurnstileSiteKey
			}
			if strings.TrimSpace(cs.TurnstileVerifyURL) != "" {
				verifyURL = cs.TurnstileVerifyURL
			}
		}
		result, err := captcha.TestTurnstileConnection(r.Context(), siteKey, secretKey, verifyURL)
		if err != nil {
			fail(w, r, http.StatusBadGateway, "captcha.test_failed", "Turnstile 连接失败："+err.Error())
			return
		}
		ok(w, r, result)
	default:
		fail(w, r, http.StatusBadRequest, "captcha.invalid_provider", "请先选择验证提供商")
	}
}

// ---- Admin SMS settings API ----

// smsSettingPayload 构造管理后台展示用的短信配置（不回显密钥明文）。
func smsSettingPayload(ss *models.SmsSetting) map[string]any {
	return map[string]any{
		"enabled":  ss.Enabled,
		"provider": ss.Provider,
		"siteName": ss.SiteName,
		"codeTtl":  ss.CodeTTL,
		"cooldown": ss.Cooldown,
		// 各服务商字段（密钥只回显「是否已配置」）
		"aliyunAccessKeyId":     ss.AliyunAccessKeyID,
		"hasAliyunSecret":       ss.AliyunAccessKeySecret != "",
		"aliyunSignName":        ss.AliyunSignName,
		"aliyunTemplateCode":    ss.AliyunTemplateCode,
		"aliyunEndpoint":        ss.AliyunEndpoint,
		"aliyunEndpointDefault": sms.DefaultAliyunEndpoint,

		"tencentSecretId":   ss.TencentSecretID,
		"hasTencentSecret":  ss.TencentSecretKey != "",
		"tencentSdkAppId":   ss.TencentSdkAppID,
		"tencentSignName":   ss.TencentSignName,
		"tencentTemplateId": ss.TencentTemplate,
		"tencentRegion":     ss.TencentRegion,

		"volcAccessKeyId": ss.VolcAccessKeyID,
		"hasVolcSecret":   ss.VolcAccessKeySecret != "",
		"volcSmsAccount":  ss.VolcSmsAccount,
		"volcSign":        ss.VolcSign,
		"volcTemplateId":  ss.VolcTemplateID,
		"volcRegion":      ss.VolcRegion,

		"huaweiAppKey":     ss.HuaweiAppKey,
		"hasHuaweiSecret":  ss.HuaweiAppSecret != "",
		"huaweiSender":     ss.HuaweiSender,
		"huaweiTemplateId": ss.HuaweiTemplate,
		"huaweiEndpoint":   ss.HuaweiEndpoint,

		"qimoAccountSid": ss.QimoAccountSID,
		"hasQimoToken":   ss.QimoAuthToken != "",
		"qimoAppId":      ss.QimoAppID,
		"qimoTemplateId": ss.QimoTemplate,

		"submailAppId":      ss.SubmailAppID,
		"hasSubmailKey":     ss.SubmailAppKey != "",
		"submailSign":       ss.SubmailSign,
		"submailTemplateId": ss.SubmailTemplate,

		"customUrl":       ss.CustomURL,
		"customMethod":    ss.CustomMethod,
		"customHeaders":   ss.CustomHeaders,
		"customBody":      ss.CustomBody,
		"hasCustomSecret": ss.CustomSecret != "",

		"providers": sms.Providers(),
		"usable":    smsConfig(ss) != nil && sms.NewProvider(smsConfig(ss)).Enabled(),
	}
}

// GET /api/v1/admin/sms — 短信验证码配置。
func (h *Handler) handleAdminSms(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ok(w, r, smsSettingPayload(h.loadSmsSetting()))
}

// PATCH /api/v1/admin/sms — 更新短信配置并即时生效。
func (h *Handler) handleAdminUpdateSms(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Enabled  *bool  `json:"enabled"`
		Provider string `json:"provider"`
		SiteName string `json:"siteName"`
		CodeTTL  int    `json:"codeTtl"`
		Cooldown int    `json:"cooldown"`

		AliyunAccessKeyID     string `json:"aliyunAccessKeyId"`
		AliyunAccessKeySecret string `json:"aliyunAccessKeySecret"`
		AliyunSignName        string `json:"aliyunSignName"`
		AliyunTemplateCode    string `json:"aliyunTemplateCode"`
		AliyunEndpoint        string `json:"aliyunEndpoint"`

		TencentSecretID  string `json:"tencentSecretId"`
		TencentSecretKey string `json:"tencentSecretKey"`
		TencentSdkAppID  string `json:"tencentSdkAppId"`
		TencentSignName  string `json:"tencentSignName"`
		TencentTemplate  string `json:"tencentTemplateId"`
		TencentRegion    string `json:"tencentRegion"`

		VolcAccessKeyID     string `json:"volcAccessKeyId"`
		VolcAccessKeySecret string `json:"volcAccessKeySecret"`
		VolcSmsAccount      string `json:"volcSmsAccount"`
		VolcSign            string `json:"volcSign"`
		VolcTemplateID      string `json:"volcTemplateId"`
		VolcRegion          string `json:"volcRegion"`

		HuaweiAppKey    string `json:"huaweiAppKey"`
		HuaweiAppSecret string `json:"huaweiAppSecret"`
		HuaweiSender    string `json:"huaweiSender"`
		HuaweiTemplate  string `json:"huaweiTemplateId"`
		HuaweiEndpoint  string `json:"huaweiEndpoint"`

		QimoAccountSID string `json:"qimoAccountSid"`
		QimoAuthToken  string `json:"qimoAuthToken"`
		QimoAppID      string `json:"qimoAppId"`
		QimoTemplate   string `json:"qimoTemplateId"`

		SubmailAppID    string `json:"submailAppId"`
		SubmailAppKey   string `json:"submailAppKey"`
		SubmailSign     string `json:"submailSign"`
		SubmailTemplate string `json:"submailTemplateId"`

		CustomURL     string `json:"customUrl"`
		CustomMethod  string `json:"customMethod"`
		CustomHeaders string `json:"customHeaders"`
		CustomBody    string `json:"customBody"`
		CustomSecret  string `json:"customSecret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	ss := h.loadSmsSetting()
	if req.Enabled != nil {
		ss.Enabled = *req.Enabled
	}
	ss.Provider = strings.TrimSpace(req.Provider)
	ss.SiteName = strings.TrimSpace(req.SiteName)
	if req.CodeTTL > 0 {
		ss.CodeTTL = req.CodeTTL
	}
	if req.Cooldown > 0 {
		ss.Cooldown = req.Cooldown
	}

	ss.AliyunAccessKeyID = strings.TrimSpace(req.AliyunAccessKeyID)
	if req.AliyunAccessKeySecret != "" {
		ss.AliyunAccessKeySecret = secretpkg.Encrypt(req.AliyunAccessKeySecret)
	}
	ss.AliyunSignName = strings.TrimSpace(req.AliyunSignName)
	ss.AliyunTemplateCode = strings.TrimSpace(req.AliyunTemplateCode)
	ss.AliyunEndpoint = strings.TrimSpace(req.AliyunEndpoint)

	ss.TencentSecretID = strings.TrimSpace(req.TencentSecretID)
	if req.TencentSecretKey != "" {
		ss.TencentSecretKey = secretpkg.Encrypt(req.TencentSecretKey)
	}
	ss.TencentSdkAppID = strings.TrimSpace(req.TencentSdkAppID)
	ss.TencentSignName = strings.TrimSpace(req.TencentSignName)
	ss.TencentTemplate = strings.TrimSpace(req.TencentTemplate)
	ss.TencentRegion = strings.TrimSpace(req.TencentRegion)

	ss.VolcAccessKeyID = strings.TrimSpace(req.VolcAccessKeyID)
	if req.VolcAccessKeySecret != "" {
		ss.VolcAccessKeySecret = secretpkg.Encrypt(req.VolcAccessKeySecret)
	}
	ss.VolcSmsAccount = strings.TrimSpace(req.VolcSmsAccount)
	ss.VolcSign = strings.TrimSpace(req.VolcSign)
	ss.VolcTemplateID = strings.TrimSpace(req.VolcTemplateID)
	ss.VolcRegion = strings.TrimSpace(req.VolcRegion)

	ss.HuaweiAppKey = strings.TrimSpace(req.HuaweiAppKey)
	if req.HuaweiAppSecret != "" {
		ss.HuaweiAppSecret = secretpkg.Encrypt(req.HuaweiAppSecret)
	}
	ss.HuaweiSender = strings.TrimSpace(req.HuaweiSender)
	ss.HuaweiTemplate = strings.TrimSpace(req.HuaweiTemplate)
	ss.HuaweiEndpoint = strings.TrimSpace(req.HuaweiEndpoint)

	ss.QimoAccountSID = strings.TrimSpace(req.QimoAccountSID)
	if req.QimoAuthToken != "" {
		ss.QimoAuthToken = secretpkg.Encrypt(req.QimoAuthToken)
	}
	ss.QimoAppID = strings.TrimSpace(req.QimoAppID)
	ss.QimoTemplate = strings.TrimSpace(req.QimoTemplate)

	ss.SubmailAppID = strings.TrimSpace(req.SubmailAppID)
	if req.SubmailAppKey != "" {
		ss.SubmailAppKey = secretpkg.Encrypt(req.SubmailAppKey)
	}
	ss.SubmailSign = strings.TrimSpace(req.SubmailSign)
	ss.SubmailTemplate = strings.TrimSpace(req.SubmailTemplate)

	ss.CustomURL = strings.TrimSpace(req.CustomURL)
	ss.CustomMethod = strings.TrimSpace(req.CustomMethod)
	ss.CustomHeaders = req.CustomHeaders
	ss.CustomBody = req.CustomBody
	if req.CustomSecret != "" {
		ss.CustomSecret = secretpkg.Encrypt(req.CustomSecret)
	}
	ss.UpdatedAt = db.Now()

	if _, err := h.db.NewUpdate().Model(ss).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	h.applySmsSetting(ss)
	h.auditConfigChange(r, "sms", "update", 0, []string{
		"enabled", "provider", "siteName", "codeTtl", "cooldown",
		"aliyunAccessKeyId", "aliyunAccessKeySecret", "aliyunSignName", "aliyunTemplateCode", "aliyunEndpoint",
		"tencentSecretId", "tencentSecretKey", "tencentSdkAppId", "tencentSignName", "tencentTemplateId", "tencentRegion",
		"volcAccessKeyId", "volcAccessKeySecret", "volcSmsAccount", "volcSign", "volcTemplateId", "volcRegion",
		"huaweiAppKey", "huaweiAppSecret", "huaweiSender", "huaweiTemplateId", "huaweiEndpoint",
		"qimoAccountSid", "qimoAuthToken", "qimoAppId", "qimoTemplateId",
		"submailAppId", "submailAppKey", "submailSign", "submailTemplateId",
		"customUrl", "customMethod", "customHeaders", "customBody", "customSecret",
	})
	h.logEvent(r, 0, &models.Event{Type: "admin.sms_updated", Summary: "管理员更新短信验证码配置"})
	ok(w, r, smsSettingPayload(ss))
}

// POST /api/v1/admin/sms/test — 测试短信服务连接（不保存，仅验证配置有效）。
func (h *Handler) handleAdminSmsTest(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Provider string `json:"provider"`
		// 复用 PATCH 的字段，允许直接用当前输入值测试。
		AliyunAccessKeyID     string `json:"aliyunAccessKeyId"`
		AliyunAccessKeySecret string `json:"aliyunAccessKeySecret"`
		AliyunSignName        string `json:"aliyunSignName"`
		AliyunTemplateCode    string `json:"aliyunTemplateCode"`
		AliyunEndpoint        string `json:"aliyunEndpoint"`

		TencentSecretID  string `json:"tencentSecretId"`
		TencentSecretKey string `json:"tencentSecretKey"`
		TencentSdkAppID  string `json:"tencentSdkAppId"`
		TencentSignName  string `json:"tencentSignName"`
		TencentTemplate  string `json:"tencentTemplateId"`
		TencentRegion    string `json:"tencentRegion"`

		VolcAccessKeyID     string `json:"volcAccessKeyId"`
		VolcAccessKeySecret string `json:"volcAccessKeySecret"`
		VolcSmsAccount      string `json:"volcSmsAccount"`
		VolcSign            string `json:"volcSign"`
		VolcTemplateID      string `json:"volcTemplateId"`
		VolcRegion          string `json:"volcRegion"`

		HuaweiAppKey    string `json:"huaweiAppKey"`
		HuaweiAppSecret string `json:"huaweiAppSecret"`
		HuaweiSender    string `json:"huaweiSender"`
		HuaweiTemplate  string `json:"huaweiTemplateId"`
		HuaweiEndpoint  string `json:"huaweiEndpoint"`

		QimoAccountSID string `json:"qimoAccountSid"`
		QimoAuthToken  string `json:"qimoAuthToken"`
		QimoAppID      string `json:"qimoAppId"`
		QimoTemplate   string `json:"qimoTemplateId"`

		SubmailAppID    string `json:"submailAppId"`
		SubmailAppKey   string `json:"submailAppKey"`
		SubmailSign     string `json:"submailSign"`
		SubmailTemplate string `json:"submailTemplateId"`

		CustomURL     string `json:"customUrl"`
		CustomMethod  string `json:"customMethod"`
		CustomHeaders string `json:"customHeaders"`
		CustomBody    string `json:"customBody"`
		CustomSecret  string `json:"customSecret"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// 以库内已保存配置为基线，用输入值覆盖（密钥留空则回退已保存值）。
	base := h.loadSmsSetting()
	cfg := smsConfig(base)
	cfg.Enabled = true
	cfg.Provider = strings.TrimSpace(req.Provider)

	cfg.AliyunAccessKeyID = firstNonEmptyStr(req.AliyunAccessKeyID, cfg.AliyunAccessKeyID)
	cfg.AliyunAccessKeySecret = firstNonEmptyStr(req.AliyunAccessKeySecret, cfg.AliyunAccessKeySecret)
	cfg.AliyunSignName = firstNonEmptyStr(req.AliyunSignName, cfg.AliyunSignName)
	cfg.AliyunTemplateCode = firstNonEmptyStr(req.AliyunTemplateCode, cfg.AliyunTemplateCode)
	cfg.AliyunEndpoint = firstNonEmptyStr(req.AliyunEndpoint, cfg.AliyunEndpoint)

	cfg.TencentSecretID = firstNonEmptyStr(req.TencentSecretID, cfg.TencentSecretID)
	cfg.TencentSecretKey = firstNonEmptyStr(req.TencentSecretKey, cfg.TencentSecretKey)
	cfg.TencentSdkAppID = firstNonEmptyStr(req.TencentSdkAppID, cfg.TencentSdkAppID)
	cfg.TencentSignName = firstNonEmptyStr(req.TencentSignName, cfg.TencentSignName)
	cfg.TencentTemplate = firstNonEmptyStr(req.TencentTemplate, cfg.TencentTemplate)
	cfg.TencentRegion = firstNonEmptyStr(req.TencentRegion, cfg.TencentRegion)

	cfg.VolcAccessKeyID = firstNonEmptyStr(req.VolcAccessKeyID, cfg.VolcAccessKeyID)
	cfg.VolcAccessKeySecret = firstNonEmptyStr(req.VolcAccessKeySecret, cfg.VolcAccessKeySecret)
	cfg.VolcSmsAccount = firstNonEmptyStr(req.VolcSmsAccount, cfg.VolcSmsAccount)
	cfg.VolcSign = firstNonEmptyStr(req.VolcSign, cfg.VolcSign)
	cfg.VolcTemplateID = firstNonEmptyStr(req.VolcTemplateID, cfg.VolcTemplateID)
	cfg.VolcRegion = firstNonEmptyStr(req.VolcRegion, cfg.VolcRegion)

	cfg.HuaweiAppKey = firstNonEmptyStr(req.HuaweiAppKey, cfg.HuaweiAppKey)
	cfg.HuaweiAppSecret = firstNonEmptyStr(req.HuaweiAppSecret, cfg.HuaweiAppSecret)
	cfg.HuaweiSender = firstNonEmptyStr(req.HuaweiSender, cfg.HuaweiSender)
	cfg.HuaweiTemplate = firstNonEmptyStr(req.HuaweiTemplate, cfg.HuaweiTemplate)
	cfg.HuaweiEndpoint = firstNonEmptyStr(req.HuaweiEndpoint, cfg.HuaweiEndpoint)

	cfg.QimoAccountSID = firstNonEmptyStr(req.QimoAccountSID, cfg.QimoAccountSID)
	cfg.QimoAuthToken = firstNonEmptyStr(req.QimoAuthToken, cfg.QimoAuthToken)
	cfg.QimoAppID = firstNonEmptyStr(req.QimoAppID, cfg.QimoAppID)
	cfg.QimoTemplate = firstNonEmptyStr(req.QimoTemplate, cfg.QimoTemplate)

	cfg.SubmailAppID = firstNonEmptyStr(req.SubmailAppID, cfg.SubmailAppID)
	cfg.SubmailAppKey = firstNonEmptyStr(req.SubmailAppKey, cfg.SubmailAppKey)
	cfg.SubmailSign = firstNonEmptyStr(req.SubmailSign, cfg.SubmailSign)
	cfg.SubmailTemplate = firstNonEmptyStr(req.SubmailTemplate, cfg.SubmailTemplate)

	cfg.CustomURL = firstNonEmptyStr(req.CustomURL, cfg.CustomURL)
	cfg.CustomMethod = firstNonEmptyStr(req.CustomMethod, cfg.CustomMethod)
	cfg.CustomHeaders = firstNonEmptyStr(req.CustomHeaders, cfg.CustomHeaders)
	cfg.CustomBody = firstNonEmptyStr(req.CustomBody, cfg.CustomBody)
	cfg.CustomSecret = firstNonEmptyStr(req.CustomSecret, cfg.CustomSecret)

	if cfg.Provider == "" || cfg.Provider == "none" {
		fail(w, r, http.StatusBadRequest, "sms.invalid_provider", "请先选择短信服务商")
		return
	}
	provider := sms.NewProvider(cfg)
	if !provider.Enabled() {
		fail(w, r, http.StatusBadRequest, "sms.incomplete", "当前服务商配置不完整，请补齐必填字段")
		return
	}
	if err := provider.TestConnection(r.Context()); err != nil {
		fail(w, r, http.StatusBadGateway, "sms.test_failed", "连接失败："+err.Error())
		return
	}
	ok(w, r, map[string]any{"ok": true, "provider": provider.Name(), "detail": "连接成功"})
}

// firstNonEmptyStr 返回首个非空白字符串。
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
