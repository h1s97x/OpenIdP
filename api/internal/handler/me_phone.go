package handler

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/sms"
)

// 手机号验证码的最小/最大 TTL 与默认冷却，作为后台配置缺省值。
const (
	defaultSmsCodeTTLMinutes = 5
	defaultSmsCooldownSecs   = 60
)

// phonePurposeVerify 是手机号验证码在 verification_codes 表中的用途标识。
const phonePurposeVerify = "phone_verify"

// generateNumericCode 生成 n 位数字验证码（使用密码学安全随机源）。
func generateNumericCode(n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + v.Int64()))
	}
	return b.String(), nil
}

// smsCodeTTL 返回当前短信验证码有效期（分钟）。
func (h *Handler) smsCodeTTL() int {
	if ttl := h.smsCfg().CodeTTL; ttl > 0 {
		return ttl
	}
	return defaultSmsCodeTTLMinutes
}

// smsCooldown 返回当前短信发送冷却（秒）。
func (h *Handler) smsCooldown() int {
	if cd := h.smsCfg().Cooldown; cd > 0 {
		return cd
	}
	return defaultSmsCooldownSecs
}

// phoneAddAllowed 返回管理员是否允许用户自助添加/更换手机号。
//
// 关闭后用户侧安全中心不再展示手机号相关入口（见 capabilities 的 phoneAdd），
// 这里再守一道：入口隐藏只是界面约定，端点仍必须拒绝，否则旧缓存的前端
// 或直接调用接口都能绕过开关写入手机号。
func (h *Handler) phoneAddAllowed() bool {
	sp := h.loadSecurityPolicy()
	return sp == nil || sp.PhoneAddEnabled
}

// requirePhoneAdd 在手机号功能被管理员关闭时拒绝请求：
// 回 403 而不是 400——这是策略性禁用，不是请求格式错误。
func (h *Handler) requirePhoneAdd(w http.ResponseWriter, r *http.Request) bool {
	if h.phoneAddAllowed() {
		return true
	}
	fail(w, r, http.StatusForbidden, "phone.add_disabled", "管理员已关闭手机号功能")
	return false
}

// POST /api/v1/me/phone/send-code
//
// 向当前用户填写的手机号发送验证码。短信服务未开启时明确拒绝，
// 绝不静默当作成功（前端仍可填写手机号，但无法完成验证，恒为未验证）。
func (h *Handler) handleSendPhoneCode(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if !h.requirePhoneAdd(w, r) {
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	phone, okNum := sms.NormalizePhone(req.Phone)
	if !okNum {
		fail(w, r, http.StatusBadRequest, "phone.invalid", "请输入有效的手机号")
		return
	}
	// 短信服务未启用：明确告知不可用，避免用户反复尝试却收不到短信。
	if !h.smsUsable() {
		fail(w, r, http.StatusServiceUnavailable, "sms.not_configured", "短信服务未配置，无法发送验证码")
		return
	}
	// 按账号维度限流，防止短信轰炸与费用被刷爆。
	if !h.accountLimiter.AllowKey("sms:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "操作过于频繁，请稍后再试")
		return
	}
	// 冷却：同一手机号在冷却期内不得重复发送。
	cooldown := h.smsCooldown()
	var last models.VerificationCode
	err = h.db.NewSelect().Model(&last).
		Where("email = ? AND purpose = ?", phone, phonePurposeVerify).
		Order("created_at DESC").Limit(1).Scan(r.Context())
	if err == nil && last.CreatedAt.Unix() > 0 {
		wait := cooldown - int(db.Now().Sub(last.CreatedAt).Seconds())
		if wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(wait))
			fail(w, r, http.StatusTooManyRequests, "phone.code_cooldown", fmt.Sprintf("发送过于频繁，请 %d 秒后重试", wait))
			return
		}
	}
	code, err := generateNumericCode(6)
	if err != nil {
		internal(w, r, err)
		return
	}
	var sendErr error
	if h.smsSendHookForTest != nil {
		_, sendErr = h.smsSendHookForTest(phone, code)
	} else {
		provider := sms.NewProvider(h.smsCfg())
		_, sendErr = provider.Send(r.Context(), phone, code)
	}
	if sendErr != nil {
		h.logEvent(r, u.ID, &models.Event{Type: "phone.code_send_failed", Summary: "手机号验证码发送失败"})
		fail(w, r, http.StatusBadGateway, "sms.send_failed", "验证码发送失败，请稍后重试")
		return
	}
	h.persistCode(phone, phonePurposeVerify, h.smsCodeTTL(), code)
	ok(w, r, map[string]any{"retryAfterSeconds": cooldown})
}

// POST /api/v1/me/phone/verify
//
// 校验手机号验证码。校验通过后写入手机号并标记为已验证。手机号发生变更时
// 必须重新验证（换号即不可信）。
func (h *Handler) handleVerifyPhone(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if !h.requirePhoneAdd(w, r) {
		return
	}
	var req struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	phone, okNum := sms.NormalizePhone(req.Phone)
	if !okNum {
		fail(w, r, http.StatusBadRequest, "phone.invalid", "请输入有效的手机号")
		return
	}
	if !h.smsUsable() {
		fail(w, r, http.StatusServiceUnavailable, "sms.not_configured", "短信服务未配置，无法完成验证")
		return
	}
	if !h.accountLimiter.AllowKey("smsverify:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "尝试次数过多，请稍后再试")
		return
	}
	if !h.checkCode(phone, phonePurposeVerify, req.Code) {
		fail(w, r, http.StatusBadRequest, "phone.code_invalid", "验证码错误或已过期")
		return
	}
	prev := u.Phone
	u.Phone = phone
	u.PhoneVerified = true
	u.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:     "phone.verified",
		Summary:  "手机号验证通过",
		Metadata: map[string]string{"previous": prev, "verified": phone},
	})
	ok(w, r, u)
}

// PATCH /api/v1/me/phone — 保存/更换手机号（未验证）。
//
// 手机号允许先行填写，但换号后必须重新验证：任何写入都会把 PhoneVerified
// 重置为 false，避免旧号验证状态被套用到新号上。
func (h *Handler) handlePatchPhone(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if !h.requirePhoneAdd(w, r) {
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	phone := strings.TrimSpace(req.Phone)
	// 允许清空手机号（解绑）。
	if phone == "" {
		u.Phone = ""
		u.PhoneVerified = false
	} else {
		normalized, okNum := sms.NormalizePhone(phone)
		if !okNum {
			fail(w, r, http.StatusBadRequest, "phone.invalid", "请输入有效的手机号")
			return
		}
		// 手机号变化即重置验证状态；未变化则保留原状态。
		if normalized != u.Phone {
			u.PhoneVerified = false
		}
		u.Phone = normalized
	}
	u.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, u)
}
