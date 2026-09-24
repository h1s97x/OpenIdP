package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// reauthTTLSeconds 是重新验证令牌的有效期（秒）。
// 与 step-up 共用过期时长：都是「证明当前操作者确实掌握凭据」的短效凭证。
const reauthTTLSeconds = stepUpTTLSeconds

// POST /api/v1/me/reauthenticate — 敏感操作的通用前置校验
//
// 与 step-up 的区别：step-up 用于「已登录但要证明身份」（如改邮箱），
// reauthenticate 额外支持 MFA 码，并返回短效凭据供解绑第三方、删除通行密钥等
// 操作复用，避免每个敏感端点各自实现一遍密码+二次验证校验。
func (h *Handler) handleReauthenticate(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Password string `json:"password"`
		MFACode  string `json:"mfaCode"`
		// Method 指定二次验证方式（mfa / email）。为空则自动选择。
		// 用户主动切换方式后必须带上它，否则服务端仍按 MFA 优先隐式校验，
		// 界面上选的与后端验的就不是同一件事。
		Method string `json:"method"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// 按账号维度限流：防止在已登录状态下对本账号反复猜测密码/MFA。
	if !h.accountLimiter.AllowKey("reauth:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "尝试次数过多，请稍后再试")
		return
	}
	// 未设置密码的账号（纯三方登录）跳过密码校验，只校验二次因素。
	if u.PasswordSet && !auth.CheckPassword(u.PasswordHash, strings.TrimSpace(req.Password)) {
		fail(w, r, http.StatusUnauthorized, "password.incorrect", "当前密码错误")
		return
	}
	// 没有任何可用第二因素（未启用 MFA 且无可用邮箱）时，仅凭密码放行：
	// 这类账号不具备完成二次验证的能力，强制索要等于把用户永久锁在敏感操作之外。
	// 安全上仍优于旧行为——旧行为是直接报错「请先启用双因素认证或绑定邮箱」，
	// 用户连改密码、解绑都做不了，只能求助管理员。
	factors := h.loadSecondFactorOptions(u)
	if factors.Required {
		if !h.verifySecondFactorMethod(u, strings.TrimSpace(req.MFACode), strings.ToLower(strings.TrimSpace(req.Method))) {
			fail(w, r, http.StatusBadRequest, "mfa.code_invalid", "验证码错误或已失效")
			return
		}
	}
	// 令牌绑定会话：换会话即失效，避免被跨会话盗用。
	// 显式指定 TTL：必须与响应体里的 expiresAt 一致，否则用户以为只有 10 分钟可用，
	// 实际有效期却是令牌库的默认值。
	token := auth.RandomToken(32)
	h.tokens.SetWithTTL("reauth:"+token, u.ID, curSessionID(cur), reauthTTLSeconds*time.Second)
	h.logEvent(r, u.ID, &models.Event{
		Type:    "reauth.verified",
		Summary: "完成敏感操作身份重验证",
		Metadata: map[string]string{
			"secondFactor": map[bool]string{true: strings.Join(factors.Methods, ","), false: "password-only"}[factors.Required],
		},
	})
	ok(w, r, map[string]any{
		"reauthToken": token,
		"expiresAt":   db.Now().Add(reauthTTLSeconds * time.Second),
	})
}

// verifyReauthToken 校验重新验证令牌是否属于该用户且绑定到当前会话。
func (h *Handler) verifyReauthToken(userID int64, sessID, token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	return h.tokens.Check("reauth:"+token, sessID) && h.tokens.UserOf("reauth:"+token) == userID
}

// consumeReauthToken 用后即焚，保证一次重验证只对应一次敏感操作。
func (h *Handler) consumeReauthToken(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	h.tokens.Delete("reauth:" + token)
}

// canReauthenticate 判断该账号是否有能力完成身份重验证。
//
// 纯三方登录且未绑定邮箱、也未启用双因素的账号无法完成二次验证
// （handleReauthenticate 此时返回 reauth.unavailable），
// 对这类账号不应强制要求 reauth，否则会导致其无法解绑/删除任何东西。
func (h *Handler) canReauthenticate(u *models.User) bool {
	return u.PasswordSet || h.loadMFA(u.ID) != nil || strings.TrimSpace(u.Email) != ""
}

// requireReauth 校验并消费一次身份重验证凭据。
//
// 这是解绑第三方、删除通行密钥等敏感操作的统一前置校验。
// 返回 false 时已写入错误响应，调用方应直接 return。
//
// 设计要点：
//   - 令牌必须绑定到当前会话（换会话即失效），防止跨会话盗用；
//   - 校验通过后立即消费（用后即焚），一次重验证只能支撑一次敏感操作；
//   - 账号不具备重验证条件时跳过，避免把用户锁死。
//
// 此前这两个校验函数从未被调用：/me/reauthenticate 签发了令牌却没有端点验证它，
// 等于敏感操作只需普通会话即可执行，该前置校验形同虚设。
func (h *Handler) requireReauth(w http.ResponseWriter, r *http.Request, u *models.User, sessID string) bool {
	if !h.canReauthenticate(u) {
		return true
	}
	// 令牌优先取请求体，其次取自定义头，便于 DELETE 等无体请求携带。
	token := strings.TrimSpace(r.URL.Query().Get("reauthToken"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-OpenIdP-Reauth"))
	}
	if token == "" {
		fail(w, r, http.StatusUnauthorized, "reauth.required", "该操作需要先完成身份验证")
		return false
	}
	if !h.verifyReauthToken(u.ID, sessID, token) {
		fail(w, r, http.StatusUnauthorized, "reauth.invalid", "身份验证已失效，请重新验证")
		return false
	}
	h.consumeReauthToken(token)
	return true
}
