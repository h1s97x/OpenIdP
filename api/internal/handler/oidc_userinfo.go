package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authz, "Bearer ")
	if token == "" || token == authz {
		writeJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}
	var tok models.Token
	err := h.db.NewSelect().Model(&tok).Where("id = ? AND type = 'access' AND revoked = false", token).Scan(r.Context())
	if err != nil || time.Now().After(tok.ExpiresAt) {
		writeJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", tok.UserID).Scan(r.Context()); err != nil {
		writeJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}
	// 尊重授权 scope：仅返回令牌授予范围内的字段，避免无条件泄露 email/phone 等。
	scopeSet := map[string]bool{}
	for _, s := range strings.Fields(tok.Scope) {
		scopeSet[s] = true
	}
	claims := map[string]any{"sub": u.Subject}
	if scopeSet["profile"] {
		claims["preferred_username"] = u.Username
		claims["name"] = u.DisplayName
		claims["picture"] = u.AvatarURL
	}
	if scopeSet["email"] {
		claims["email"] = u.Email
		claims["email_verified"] = u.EmailVerified
	}
	if scopeSet["phone"] {
		claims["phone"] = u.Phone
		// 未验证的手机号不可信：按 OIDC 标准附带 phone_number_verified。
		claims["phone_number_verified"] = u.PhoneVerified
	}
	writeJSON(w, 200, claims)
}

// authenticateClient authenticates an OAuth client from either HTTP Basic auth
// or form parameters (client_id + client_secret). Returns the client or nil.
func (h *Handler) authenticateClient(r *http.Request) *models.OAuthClient {
	clientID := ""
	clientSecret := ""
	if id, secret, ok := r.BasicAuth(); ok {
		clientID = id
		clientSecret = secret
	} else {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}
	if clientID == "" {
		return nil
	}
	var client models.OAuthClient
	if err := h.db.NewSelect().Model(&client).Where("id = ?", clientID).Scan(r.Context()); err != nil {
		return nil
	}
	// 只有机密客户端才能通过客户端认证：无密钥（public）客户端一律拒绝，
	// 否则仅凭公开可知的 client_id 就能内省/撤销他人令牌。
	if !clientConfidential(&client) {
		return nil
	}
	if !auth.CheckPassword(client.SecretHash, clientSecret) {
		return nil
	}
	return &client
}

// clientConfidential 报告客户端是否是机密客户端（必须校验 client_secret）。
// 判定顺序：显式声明的 client_type 优先；未声明时按是否配置了密钥推导，
// 保证历史数据在回填 client_type 之前也能被正确保护。
func clientConfidential(c *models.OAuthClient) bool {
	if c == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.ClientType)) {
	case "confidential":
		return true
	case "public":
		return false
	}
	return strings.TrimSpace(c.SecretHash) != ""
}
