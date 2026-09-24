package handler

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oidc"
)

// authorizationCodeTTL 是 OIDC 授权码的有效期。
// 签发、consent 缓存与消费校验三处共用此常量，避免改动时遗漏。
const authorizationCodeTTL = 10 * time.Minute

// oidcProvider is injected into the Handler.
type oidcHolder struct {
	provider *oidc.Provider
}

// HandleJWKS: GET /.well-known/jwks
func (h *Handler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.oidc.provider.JWKS())
}

// HandleDiscovery: GET /.well-known/openid-configuration
func (h *Handler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuer(r)
	cfg := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/login/oauth/authorize",
		"token_endpoint":                        issuer + "/api/login/oauth/access_token",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"userinfo_endpoint":                     issuer + "/api/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks",
		"introspection_endpoint":                issuer + "/api/login/oauth/introspect",
		"revocation_endpoint":                   issuer + "/api/login/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"device_authorization_endpoint":         issuer + "/api/login/oauth/device_authorization",
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", "phone", "offline_access"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "exp", "nonce", "preferred_username", "name", "picture", "email", "email_verified", "phone", "phone_number_verified"},
		"request_parameter_supported":           false,
		"end_session_endpoint":                  issuer + "/api/logout",
		"backchannel_logout_supported":          false,
		"backchannel_logout_session_supported":  false,
	}
	writeJSON(w, 200, cfg)
}

func (h *Handler) issuer(r *http.Request) string {
	// 默认用 SITE_URL（受信任的显式配置），避免依据客户端可控的 Host 头影响
	// id_token 的 iss。仅当未显式配置 SITE_URL 时才回退到请求 Host。
	if u := strings.TrimRight(h.cfg.SiteURL, "/"); !h.cfg.SiteURLIsPlaceholder() {
		return u
	}
	scheme := "https"
	if isLocal(r) {
		scheme = "http"
	}
	// 使用经过清洗的 Host，防止 Host 头注入影响 id_token 的 iss。
	host := requestHost(r)
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host
}

// GET /login/oauth/authorize
func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if responseType != "code" {
		// 客户端尚未校验，redirect_uri 不可信，不得用于重定向（防开放重定向）。
		h.oauthJSONError(w, r, "unsupported_response_type", "不支持的 response_type")
		return
	}
	var client models.OAuthClient
	err := h.db.NewSelect().Model(&client).Where("id = ?", clientID).Scan(r.Context())
	if err != nil {
		// 客户端无效：redirect_uri 未经验证，返回 JSON 错误而非跳转（防开放重定向）。
		h.oauthJSONError(w, r, "invalid_client", "无效的客户端")
		return
	}
	if !contains(client.RedirectURIs, redirectURI) {
		// 校验失败的 redirect_uri 属于不可信输入，不得用于重定向：
		// 若跳过去就变成开放重定向（攻击者可构造
		// /login/oauth/authorize?client_id=<合法>&redirect_uri=http://evil.example.com
		// 把已登录用户导向钓鱼站点，且链接域名仍是本站）。
		// RFC 6749 §4.1.2.1 亦要求此时不得自动重定向，故统一返回 JSON 错误。
		// 注意：下面 PKCE 相关的错误仍可安全重定向——它们位于本校验之后，
		// 此时 redirectURI 已确认在白名单内。
		h.oauthJSONError(w, r, "invalid_request", "redirect_uri 不在白名单")
		return
	}

	// require login
	u, _, err := h.currentUser(r)
	if err != nil {
		// 带上完整的授权请求 URI（含路径与查询串）作为 returnUrl，登录后才能
		// 回到授权流程；此前只编码了查询串（且未按 URL 规则转义），登录页拿到
		// 的是一个残缺、被拆散的 returnUrl，登录后无法继续授权。
		http.Redirect(w, r, loginRedirectURL(r), http.StatusFound)
		return
	}

	// 仅支持 S256 的 PKCE 挑战方式，拒绝 plain 或缺省（防止降级为弱校验）。
	if codeChallenge != "" && codeChallengeMethod != "S256" {
		h.oauthError(w, r, redirectURI, state, "invalid_request", "仅支持 S256 的 PKCE 挑战")
		return
	}
	// 对无 secret 的 public client 强制要求 PKCE（S256）：防止授权码被截获后
	// 在无客户端认证的情况下被任意兑换（授权码窃取/交换攻击）。
	if !clientConfidential(&client) && codeChallenge == "" {
		h.oauthError(w, r, redirectURI, state, "invalid_request", "public 客户端必须使用 PKCE")
		return
	}

	// scope 必须收敛到该客户端已登记的权限范围内。否则应用可以在用户首次同意后
	// 静默扩大权限（例如从 openid 提到 email / phone / address / offline_access），
	// 而下面基于「已存在 grant」的快速通道会跳过同意页，用户全程无感知。
	// 设备码流早已做此收敛（见 HandleDeviceAuthorization），此处此前遗漏。
	scope = h.intersectScopes(r.Context(), scope, client.Scopes)

	// 仅当已有的授权（grant）完整覆盖本次请求的 scope 时才跳过 consent 授权页；
	// 首次授权、或应用扩大了权限范围时，都必须重新向用户展示同意页并记录新的授权。
	if !h.grantCoversScope(u.ID, clientID, scope) {
		ticket := auth.RandomToken(32)
		// 把完整授权请求参数绑定到 ticket，consent 确认时据此重建授权码（避免重放/篡改）。
		h.storeConsent(ticket, consentReq{
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			Scope:         scope,
			Nonce:         nonce,
			CodeChallenge: codeChallenge,
			State:         state,
			UserID:        u.ID,
			CreatedAt:     db.Now(),
		})
		// 绑定到当前会话，consent 页必须携带同一会话 cookie 才能查看/操作。
		h.tokens.Set("consent:"+ticket, u.ID, h.sessionID(r))
		http.Redirect(w, r, "/oauth/consent?request="+ticket, http.StatusFound)
		return
	}

	http.Redirect(w, r, h.issueAuthorizationCode(w, r, clientID, redirectURI, scope, nonce, codeChallenge, state, u.ID), http.StatusFound)
}

// issueAuthorizationCode 签发一个 OIDC 授权码，并返回重定向到 redirect_uri 的 URL。
// 被 HandleAuthorize 与 consent 确认流程共用（consent 同意后同样走此路径）。
// 返回的 redirect URL 由调用方决定是直接重定向还是返回给前端跳转。
func (h *Handler) issueAuthorizationCode(w http.ResponseWriter, r *http.Request, clientID, redirectURI, scope, nonce, codeChallenge, state string, userID int64) string {
	code := auth.RandomToken(32)
	ac := &models.AuthorizationCode{
		Code:          code,
		ClientID:      clientID,
		UserID:        userID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		Nonce:         nonce,
		CodeChallenge: codeChallenge,
		ExpiresAt:     db.Now().Add(authorizationCodeTTL),
	}
	if _, err := h.db.NewInsert().Model(ac).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return ""
	}
	loc := redirectURI
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	loc += sep + "code=" + code
	if state != "" {
		loc += "&state=" + state
	}
	return loc
}

// POST /api/login/oauth/access_token
func (h *Handler) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// 引入客户端认证：防止未认证方对任意令牌做枚举/探测。
	client := h.authenticateClient(r)
	if client == nil {
		writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": "客户端认证失败"})
		return
	}
	token := r.Form.Get("token")
	var tok models.Token
	err := h.db.NewSelect().Model(&tok).Where("id = ?", token).Scan(r.Context())
	if err != nil {
		// 令牌不存在或查询失败：按 RFC 7662 返回 inactive，不泄露令牌是否存在。
		writeJSON(w, 200, map[string]any{"active": false})
		return
	}
	// 令牌细节只返回给令牌所属客户端，避免任意已认证客户端探测他人令牌。
	if tok.ClientID != client.ID {
		writeJSON(w, 200, map[string]any{"active": false})
		return
	}
	active := !tok.Revoked && time.Now().Before(tok.ExpiresAt)
	writeJSON(w, 200, map[string]any{
		"active": active, "client_id": tok.ClientID, "scope": tok.Scope,
		"token_type": "Bearer", "exp": tok.ExpiresAt.Unix(),
	})
}

// POST /api/login/oauth/revoke
func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// 引入客户端认证：仅允许令牌所属客户端或其自身撤销令牌。
	client := h.authenticateClient(r)
	if client == nil {
		writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": "客户端认证失败"})
		return
	}
	token := r.Form.Get("token")
	var tok models.Token
	err := h.db.NewSelect().Model(&tok).Where("id = ?", token).Scan(r.Context())
	if err == nil && tok.ClientID != client.ID {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "令牌不属于该客户端"})
		return
	}
	_, _ = h.db.NewUpdate().Model((*models.Token)(nil)).
		Set("revoked = ?", true).Where("id = ?", token).Exec(r.Context())
	writeJSON(w, 200, map[string]any{})
}

// GET /api/logout (end session)
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// 注销是破坏性操作：校验浏览器携带的 Origin/Referer 与本站同源，
	// 阻止跨站页面（<img> 等）在用户不知情时触发注销 CSRF。
	if !sameSiteRequest(h, r) {
		http.Error(w, "cross-site logout blocked", http.StatusForbidden)
		return
	}
	h.clearSessionCookies(w, r)
	redirect := r.URL.Query().Get("post_logout_redirect_uri")
	if redirect != "" {
		// 仅允许同站相对路径，防止开放重定向 / 注销 CSRF 把用户引导到恶意站点。
		redirect = parseReturnURL(redirect)
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// sameSiteRequest 校验请求的 Origin / Referer 头（浏览器在跨站请求中总会携带其一）
// 与本站发布地址同源。当两个头都不存在（curl、服务端调用等无浏览器上下文场景）
// 时视为本站直接调用，予以放行，避免误伤 API 客户端。
func sameSiteRequest(h *Handler, r *http.Request) bool {
	// 基准 host：优先取受信任配置的 SITE_URL；SITE_URL 仍是占位值时按实际访问域名判定。
	//
	// 这里必须与 issuer() / requestBaseURL() 用同一套判定（SiteURLIsPlaceholder）。
	// 此前只判空串，占位值 "http://localhost:6099" 会被当作基准 host，
	// 于是自定义域名下「发现 / 授权 / 回调 / 通行密钥都能用，唯独登出恒定 403」。
	base := strings.TrimRight(h.cfg.SiteURL, "/")
	if h.cfg.SiteURLIsPlaceholder() {
		base = h.requestBaseURL(r)
	}
	var baseHost string
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		baseHost = strings.ToLower(u.Host)
	}
	if baseHost == "" {
		// 回退：清洗请求 Host（保留端口）。
		baseHost = strings.ToLower(requestHost(r))
	}
	if baseHost == "" {
		return true
	}
	hostOf := func(v string) string {
		if strings.TrimSpace(v) == "" {
			return ""
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return ""
		}
		return strings.ToLower(u.Host)
	}
	origin := hostOf(r.Header.Get("Origin"))
	referer := hostOf(r.Header.Get("Referer"))
	if origin != "" && origin != baseHost {
		return false
	}
	if referer != "" && referer != baseHost {
		return false
	}
	return true
}

func (h *Handler) oauthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	if redirectURI != "" {
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		loc := redirectURI + sep + "error=" + code + "&error_description=" + escape(desc)
		if state != "" {
			loc += "&state=" + state
		}
		http.Redirect(w, r, loc, http.StatusFound)
		return
	}
	writeJSON(w, 400, map[string]any{"error": code, "error_description": desc})
}

func (h *Handler) oauthJSONError(w http.ResponseWriter, r *http.Request, code, desc string) {
	writeJSON(w, 400, map[string]any{"error": code, "error_description": desc})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// escape 对拼入重定向 URL 查询串的值做 URL 转义。
//
// 此前用 json.Marshal 冒充 URL 编码：它会把 & 变成 \u0026，却不会编码
// #、%、空格——一旦传入的是动态值，就会造成参数注入或 URL 截断。
// 这里改用标准的 url.QueryEscape，与 loginRedirectURL 保持一致。
func escape(s string) string {
	return url.QueryEscape(s)
}

// loginRedirectURL 构造跳往登录页并携带回跳地址的重定向目标。
//
// returnUrl 必须是「路径 + 查询串」并按 URL 规则转义：不转义时其中的 &、=
// 会被当成登录页自身的查询参数，登录页读到的 returnUrl 会被截断，
// 登录后只能回到首页而无法继续原本的授权流程。
// 回跳地址同时受 parseReturnURL 的同站校验约束，不会造成开放重定向。
func loginRedirectURL(r *http.Request) string {
	return "/sign-in?returnUrl=" + url.QueryEscape(parseReturnURL(r.URL.RequestURI()))
}

// sessionID 返回当前请求的会话 cookie 值（无则空串）。
func (h *Handler) sessionID(r *http.Request) string {
	if c, err := r.Cookie(h.cfg.SessionCookieName); err == nil {
		return c.Value
	}
	return ""
}
