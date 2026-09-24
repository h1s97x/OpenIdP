package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"net/http"
	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// offlineGranted 判断请求的 scope 是否包含 offline_access。
// 只有显式申请离线访问的客户端才应拿到刷新令牌。
func offlineGranted(scope string) bool {
	return contains(strings.Fields(scope), "offline_access")
}

// persistTokens 在一个事务内写入 access / refresh 两条令牌记录，
// 保证不会出现「只写了一半」的状态。
// 当未申请 offline_access 时 refreshID 为空，此时只写入访问令牌。
func (h *Handler) persistTokens(ctx context.Context, accessID, refreshID string, userID int64, clientID, scope string, now time.Time) error {
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.NewInsert().Model(&models.Token{
		ID: accessID, UserID: userID, ClientID: clientID, Type: "access",
		Scope: scope, ExpiresAt: now.Add(time.Hour),
	}).Exec(ctx); err != nil {
		return err
	}
	if refreshID != "" {
		if _, err := tx.NewInsert().Model(&models.Token{
			ID: refreshID, UserID: userID, ClientID: clientID, Type: "refresh",
			Scope: scope, ExpiresAt: now.AddDate(0, 0, 30),
		}).Exec(ctx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.oauthJSONError(w, r, "invalid_request", "无法解析请求体")
		return
	}
	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		h.tokenByCode(w, r)
	case "refresh_token":
		h.tokenByRefresh(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.tokenByDeviceCode(w, r)
	default:
		// RFC 6749
		writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type", "error_description": "不支持的授权类型"})
	}
}

func (h *Handler) tokenByCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	verifier := r.Form.Get("code_verifier")
	redirectURI := r.Form.Get("redirect_uri")

	var ac models.AuthorizationCode
	err := h.db.NewSelect().Model(&ac).Where("code = ?", code).Scan(r.Context())
	// 授权码必须未使用且未过期（签发时设 10 分钟有效期，过期后作废并清理）。
	if err != nil || ac.Used || time.Now().After(ac.ExpiresAt) {
		if err == nil && time.Now().After(ac.ExpiresAt) {
			_, _ = h.db.NewDelete().Model((*models.AuthorizationCode)(nil)).Where("code = ?", code).Exec(r.Context())
		}
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "无效的授权码"})
		return
	}
	// 授权码必须与签发它的客户端绑定（防授权码混淆 / code swapping）：
	// 签发时记录了 client_id 与 redirect_uri，兑换时两者都必须一致。
	if ac.ClientID != clientID {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "授权码不属于该客户端"})
		return
	}
	if ac.RedirectURI != redirectURI {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "redirect_uri 与授权码绑定不一致"})
		return
	}
	// verify client
	var client models.OAuthClient
	if err := h.db.NewSelect().Model(&client).Where("id = ?", clientID).Scan(r.Context()); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "无效的客户端"})
		return
	}
	// 校验 PKCE：授权码带 challenge 时 verifier 必须匹配；
	// 未带 challenge 时仅机密客户端允许免 PKCE（authorize 阶段已强制 public 必须带）。
	if ac.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if challenge != ac.CodeChallenge {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "PKCE 校验失败"})
			return
		}
	} else if !clientConfidential(&client) {
		// 无密钥且无 PKCE：等于零认证换 token，一律拒绝。
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "public 客户端必须使用 PKCE"})
		return
	}
	// 客户端认证：confidential 客户端（有密钥 / 显式声明）必须出示正确密钥，
	// 不再允许「无密钥即可通过认证」。
	if clientConfidential(&client) && !auth.CheckPassword(client.SecretHash, clientSecret) {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "客户端密钥错误"})
		return
	}

	ac.Used = true
	// 原子条件更新：仅当授权码尚未被使用时才置为已用，防止并发重复兑换同一授权码。
	res, err := h.db.NewUpdate().Model(&ac).
		Set("used = ?", true).
		Where("code = ? AND used = false", code).
		Exec(r.Context())
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "internal_error", "error_description": "授权码兑换失败"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "无效的授权码"})
		return
	}

	// issue tokens
	access, refresh, idToken, tokOK := h.issueTokens(w, r, &client, ac.UserID, ac.Scope, ac.Nonce)
	if !tokOK {
		return
	}
	payload := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
		"scope":        ac.Scope,
	}
	if refresh != "" {
		payload["refresh_token"] = refresh
	}
	writeJSON(w, 200, payload)
}

func (h *Handler) tokenByRefresh(w http.ResponseWriter, r *http.Request) {
	refresh := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	var tok models.Token
	err := h.db.NewSelect().Model(&tok).Where("id = ? AND type = 'refresh'", refresh).Scan(r.Context())
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "无效的刷新令牌"})
		return
	}
	// 刷新令牌必须与签发它的客户端绑定，并校验该客户端身份：
	// 防止泄露的 refresh token 被任意客户端/匿名使用。
	if tok.ClientID != clientID {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "刷新令牌不属于该客户端"})
		return
	}
	var client models.OAuthClient
	if err := h.db.NewSelect().Model(&client).Where("id = ?", clientID).Scan(r.Context()); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "无效的客户端"})
		return
	}
	if clientConfidential(&client) && !auth.CheckPassword(client.SecretHash, clientSecret) {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "客户端密钥错误"})
		return
	}
	// 重用检测（RFC 6819 §5.2.2.3）：refresh token 轮换后旧值不删除而是保留为
	// 墓碑并记录后继 ID。若旧值再次出现，说明令牌已泄露（合法用户与攻击者
	// 各持一份），吊销该用户在此客户端的整个令牌家族并拒绝本次请求。
	//
	// 必须在「是否已吊销 / 是否过期」之前判定：轮换后的墓碑本身就是
	// revoked=true，先判 revoked 会让这段家族吊销逻辑恒不可达，
	// 攻击者拿着旧令牌只会拿到 invalid_grant，家族却依旧有效。
	if tok.ReplacedBy != "" {
		if _, err := h.db.NewUpdate().Model((*models.Token)(nil)).
			Set("revoked = true").
			Where("user_id = ? AND client_id = ? AND revoked = false", tok.UserID, tok.ClientID).
			Exec(r.Context()); err != nil {
			internal(w, r, err)
			return
		}
		h.logEvent(r, tok.UserID, &models.Event{
			Type:    "oauth.token_reuse",
			Summary: "检测到刷新令牌重用，已吊销相关令牌",
			Metadata: map[string]string{
				"clientId":   tok.ClientID,
				"clientName": h.clientName(tok.ClientID),
			},
		})
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "刷新令牌已被使用，为保护账号已吊销全部相关令牌，请重新登录"})
		return
	}
	if tok.Revoked || time.Now().After(tok.ExpiresAt) {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "无效的刷新令牌"})
		return
	}

	access, newRefresh, idToken, tokOK := h.issueTokens(w, r, &client, tok.UserID, tok.Scope, "")
	if !tokOK {
		return
	}
	// 旧 token 保留为墓碑（保留 scope/时间戳供审计），仅记录后继并立即失效。
	_, _ = h.db.NewUpdate().Model((*models.Token)(nil)).
		Set("revoked = true, replaced_by = ?", newRefresh).
		Where("id = ?", refresh).Exec(r.Context())
	payload := map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": 3600,
		"id_token": idToken, "scope": tok.Scope,
	}
	if newRefresh != "" {
		payload["refresh_token"] = newRefresh
	}
	writeJSON(w, 200, payload)
}

// issueTokens creates access/refresh tokens and ID token.
// 刷新令牌仅在 scope 含 offline_access 时返回，未申请时 refreshID 为空字符串。
// 用户不存在或查询失败时返回 ok=false 并已写出 400 响应，
// 调用方必须立即 return，绝不签发无身份信息的令牌。
func (h *Handler) issueTokens(w http.ResponseWriter, r *http.Request, client *models.OAuthClient, userID int64, scope, nonce string) (accessID, refreshID, idToken string, ok bool) {
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", userID).Scan(r.Context()); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "用户不存在或状态异常"})
		return "", "", "", false
	}

	accessID = auth.RandomToken(32)
	// 仅当申请了 offline_access 时才签发刷新令牌，避免未申请离线访问的客户端
	// 也能拿到长效凭证。
	if offlineGranted(scope) {
		refreshID = auth.RandomToken(32)
	}
	now := db.Now()
	// 令牌必须一并落库。此前这里用 `_, _ =` 吞掉错误：插入失败仍然返回 ok=true，
	// 客户端拿到的是数据库里并不存在的令牌，userinfo / introspect 全部 401，
	// 而且没有任何日志线索可查。改为事务内插入，任一失败即回滚并返回错误。
	if err := h.persistTokens(r.Context(), accessID, refreshID, userID, client.ID, scope, now); err != nil {
		internal(w, r, err)
		return "", "", "", false
	}

	claims := map[string]any{}
	if contains(strings.Fields(scope), "profile") {
		claims["preferred_username"] = u.Username
		claims["name"] = u.DisplayName
		claims["picture"] = u.AvatarURL
	}
	if contains(strings.Fields(scope), "email") {
		claims["email"] = u.Email
		claims["email_verified"] = u.EmailVerified
	}
	if contains(strings.Fields(scope), "phone") && u.Phone != "" {
		claims["phone"] = u.Phone
		// 按 OIDC 标准下发 phone_number_verified：手机号由用户自填，
		// 仅当通过短信验证码确认归属后才为 true，第三方据此判断号码是否可信。
		claims["phone_number_verified"] = u.PhoneVerified
	}
	idToken, err := h.oidc.provider.SignIDToken(h.issuer(r), u.Subject, client.ID, nonce, claims, time.Hour)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "server_error", "error_description": "令牌签发失败"})
		return "", "", "", false
	}
	return accessID, refreshID, idToken, true
}
