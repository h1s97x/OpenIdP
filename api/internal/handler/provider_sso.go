package handler

import (
	"context"
	"database/sql"

	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"

	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oauth2"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
)

// ---- 第三方登录（OAuth 授权码） ----

// providerTypeFromPath extracts the provider type from any authorize/bind/callback path
// (e.g. /api/oauth/callback/qq, /api/login/provider/qq/authorize, /api/v1/login/provider/qq/bind).
// 绑定与登录共用同一个 /api/oauth/callback/{type} 回调地址，因此不需要再解析 /bind 后缀。
func providerTypeFromPath(p string) string {
	p = strings.TrimPrefix(p, "/api/login/provider/")
	p = strings.TrimPrefix(p, "/api/v1/login/provider/")
	p = strings.TrimPrefix(p, "/api/oauth/callback/")
	if i := strings.Index(p, "/"); i > 0 {
		p = p[:i]
	}
	return p
}

// providerReadyErr returns nil when the provider can be used, or a descriptive
// error when it is disabled / has no client id / has no client appcrypto.
func providerReadyErr(prov *models.OAuthProvider) error {
	if prov == nil || !prov.Enabled {
		return errors.New("provider not enabled")
	}
	if prov.ClientID == "" {
		return errors.New("provider client id is empty")
	}
	if prov.ClientSecret == "" {
		return errors.New("provider client secret is empty")
	}
	return nil
}

// providerErrorPage renders a self-contained HTML error page for the
// authorize/bind/callback browser flows, instead of a bare text error.
// It explains why the provider cannot be used and gives the user a way back
// (login page for sign-in, settings for binding).
func providerErrorPage(w http.ResponseWriter, status int, title, detail, backURL, backText string) {
	html := `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + htmlEsc(title) + `</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;padding:0;background:#f5f5f5;color:#0a0a0a;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#fff;border:1px solid #e8e8e8;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.05);padding:40px;max-width:460px;width:100%;margin:24px;text-align:center}
  .icon{font-size:44px;line-height:1;margin-bottom:12px}
  h1{font-size:18px;margin:0 0 8px}
  p{font-size:14px;color:#606060;line-height:1.6;margin:0 0 24px;word-break:break-word}
  a{display:inline-block;background:#0276ea;color:#fff;text-decoration:none;font-size:14px;font-weight:500;padding:10px 20px;border-radius:8px}
  a:hover{background:#0263c4}
</style></head><body><div class="card">
<div class="icon">⚠️</div>
<h1>` + htmlEsc(title) + `</h1>
<p>` + htmlEsc(detail) + `</p>
<a href="` + htmlEsc(backURL) + `">` + htmlEsc(backText) + `</a>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(html))
}

func htmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// providerFriendlyHint maps a providerReadyErr to a human-readable Chinese hint
// shown on the browser-facing error page, so the user knows what to do next.
func providerFriendlyHint(prov *models.OAuthProvider) string {
	msg := "该第三方登录暂不可用，请稍后再试。"
	if prov == nil {
		return msg
	}
	switch {
	case !prov.Enabled:
		msg = "该第三方登录尚未启用，请联系站点管理员在后台开启。"
	case prov.ClientID == "":
		msg = "该第三方登录缺少 Client ID，请联系站点管理员在后台补充配置。"
	case prov.ClientSecret == "":
		msg = "该第三方登录缺少 Client Secret，请联系管理员在后台「系统设置 → 登录提供商」中填写明文 Client Secret 后即可使用。"
	}
	return msg
}

// GET /api/login/provider/{type}/authorize — 发起第三方授权（前端内部跳转，非三方回调）
func (h *Handler) handleProviderAuthorize(w http.ResponseWriter, r *http.Request) {
	providerType := providerTypeFromPath(r.URL.Path)
	p, ok := h.resolveProvider(providerType)
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	// 三方登录不再要求人机验证：身份由提供商侧认证，本站人机验证仅针对
	// 密码 / 邮箱验证码流程。（旧的 captchaProof 兼容端已移除。）
	prov, err := h.loadProvider(providerType)
	if err != nil {
		providerErrorPage(w, http.StatusNotFound, "提供商不存在", "该第三方登录方式未配置或已移除，请联系站点管理员。", "/sign-in", "返回登录")
		return
	}
	if err := providerReadyErr(prov); err != nil {
		providerErrorPage(w, http.StatusBadRequest, "第三方登录暂不可用",
			providerFriendlyHint(prov),
			"/sign-in", "返回登录")
		return
	}
	state := auth.RandomToken(16)
	// 登录 CSRF 防护：把 state 绑定到本次浏览器会话（随机 cookie 值）。
	// 回调时校验同一 cookie 必须存在且匹配，否则 state 视为无效——
	// 攻击者在自己浏览器发起的授权，其回调 URL 在受害者浏览器中无法通过校验，
	// 从而阻止"诱导受害者点击回调链接"导致的登录 CSRF / 会话注入。
	binding := auth.RandomToken(16)
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.OAuthStateCookieName,
		Value:    binding,
		Path:     "/",
		MaxAge:   600,
		Expires:  db.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   h.cookieSecure(),
		// 这里固定 Lax：第三方平台的回调是顶层 GET 导航，Lax Cookie 会被正常携带，
		// 而 SameSite=None 会让该绑定 Cookie 在跨站子请求中也可用，反而削弱 CSRF 防护。
		SameSite: http.SameSiteLaxMode,
	})
	h.tokens.Set("oauth:state:"+state, 1, binding)
	redirect := h.providerRedirectURL(r, p.Type)
	cred := &oauth2.Credentials{
		ClientID:     prov.ClientID,
		ClientSecret: prov.ClientSecret,
		RedirectURL:  redirect,
	}
	returnURL := r.URL.Query().Get("returnUrl")
	http.Redirect(w, r, p.BuildAuthorizeURL(cred, state, "", returnURL), http.StatusFound)
}

// oauthStateBinding 返回请求携带的 OAuth state 绑定 cookie 值（无则空串）。
func (h *Handler) oauthStateBinding(r *http.Request) string {
	if c, err := r.Cookie(h.cfg.OAuthStateCookieName); err == nil {
		return c.Value
	}
	return ""
}

// GET /callback/{type} — 第三方授权回调
func (h *Handler) handleProviderCallback(w http.ResponseWriter, r *http.Request) {
	providerType := providerTypeFromPath(r.URL.Path)
	p, ok := h.resolveProvider(providerType)
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	state := r.URL.Query().Get("state")
	// 绑定流程使用与登录一致的 /callback/{type} 回调地址，通过 state 前缀区分：
	//   oauth:state:* → 未登录三方登录（绑定到发起授权的浏览器 cookie）
	//   oauth:bind:*  → 已登录安全中心绑定（绑定到发起绑定的会话）
	bindState := ""
	bindUserID := int64(0)
	switch {
	case h.tokens.Check("oauth:state:"+state, h.oauthStateBinding(r)):
		// 登录态 OAuth state：cookie 绑定校验通过后一次性消费（原子 GetDel），
		// 避免"先查后删"并发重放。校验失败说明回调不是发起授权的同一浏览器发起的。
		if _, ok := h.tokens.Take("oauth:state:" + state); !ok {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		// 消费成功：清理绑定 cookie，防止被重放/复用。
		http.SetCookie(w, &http.Cookie{
			Name: h.cfg.OAuthStateCookieName, Value: "", Path: "/",
			MaxAge: -1, Expires: time.Unix(0, 0), HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	case h.tokens.Check("oauth:bind:"+state, h.sessionID(r)):
		it, ok := h.tokens.Take("oauth:bind:" + state)
		if !ok || it.UserID == 0 {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		bindState = "bind"
		bindUserID = it.UserID
	default:
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	prov, err := h.loadProvider(providerType)
	if err != nil {
		providerErrorPage(w, http.StatusNotFound, "提供商不存在", "该第三方登录方式未配置或已移除，请联系站点管理员。", "/sign-in", "返回登录")
		return
	}
	if err := providerReadyErr(prov); err != nil {
		providerErrorPage(w, http.StatusBadRequest, "第三方登录暂不可用",
			providerFriendlyHint(prov),
			"/sign-in", "返回登录")
		return
	}
	cred := &oauth2.Credentials{
		ClientID:     prov.ClientID,
		ClientSecret: prov.ClientSecret,
		RedirectURL:  h.providerRedirectURL(r, p.Type),
	}
	token, extra, err := p.ExchangeCode(r.Context(), cred, code)
	if err != nil {
		// 上游错误可能含敏感信息（密钥、响应体细节）：只记日志，前端展示通用文案。
		log.Printf("❌ [OAuth] 授权码交换失败（provider=%s）: %v", providerType, err)
		providerErrorPage(w, http.StatusBadGateway, "登录失败", "授权码交换失败，请重试，或联系站点管理员。", "/sign-in", "返回登录")
		return
	}
	profile, err := p.FetchProfile(r.Context(), token, extra)
	if err != nil {
		log.Printf("❌ [OAuth] 获取用户信息失败（provider=%s）: %v", providerType, err)
		providerErrorPage(w, http.StatusBadGateway, "登录失败", "获取用户信息失败，请重试，或联系站点管理员。", "/sign-in", "返回登录")
		return
	}
	profile.Provider = providerType

	// 绑定流程：将第三方身份绑定到已登录用户
	if bindState == "bind" {
		if err := h.bindIdentity(bindUserID, profile); err != nil {
			providerErrorPage(w, http.StatusConflict, "绑定失败", err.Error(), "/settings/account", "返回安全中心")
			return
		}
		http.Redirect(w, r, "/settings/account", http.StatusFound)
		return
	}

	// 登录流程：自动注册或登录
	u, isNew, err := h.loginOrSignupWithProvider(r, profile)
	if err != nil {
		providerErrorPage(w, http.StatusBadGateway, "登录失败", err.Error(), "/sign-in", "返回登录")
		return
	}
	if _, err := h.issueSession(w, r, u, "thirdParty"); err != nil {
		providerErrorPage(w, http.StatusInternalServerError, "登录失败", "会话创建失败，请重试。", "/sign-in", "返回登录")
		return
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:     "login.success",
		Summary:  "第三方登录成功",
		Metadata: map[string]string{"method": "thirdParty", "provider": providerType},
	})
	if isNew {
		h.logEvent(r, u.ID, &models.Event{Type: "signup.success", Summary: "第三方注册成功", Metadata: map[string]string{"provider": providerType}})
	}
	// 跳回登录页 → 前端已通过 cookie 自动登录。return_url 仅允许同站相对路径，
	// 防止构造恶意 return_url 的第三方登录链接造成开放重定向。
	returnURL := parseReturnURL(r.URL.Query().Get("return_url"))
	http.Redirect(w, r, returnURL, http.StatusFound)
}

// GET /api/v1/login/provider/{type}/bind — 已登录用户绑定第三方（前端整页跳转）
func (h *Handler) handleProviderBind(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		// 与授权端点保持一致：回跳地址需完整且按 URL 规则转义，
		// 登录后才能真正回到绑定流程。
		http.Redirect(w, r, loginRedirectURL(r), http.StatusFound)
		return
	}
	providerType := providerTypeFromPath(r.URL.Path)
	p, ok := h.resolveProvider(providerType)
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	prov, err := h.loadProvider(providerType)
	if err != nil {
		providerErrorPage(w, http.StatusNotFound, "提供商不存在", "该第三方登录方式未配置或已移除，请联系站点管理员。", "/settings/account", "返回安全中心")
		return
	}
	if err := providerReadyErr(prov); err != nil {
		providerErrorPage(w, http.StatusBadRequest, "绑定暂不可用",
			providerFriendlyHint(prov),
			"/settings/account", "返回安全中心")
		return
	}
	state := auth.RandomToken(16)
	// 绑定流程的 state 绑定到当前登录会话：回调必须携带同一个会话 cookie 才能消费，
	// 防止攻击者盗用他人绑定回调 URL 把第三方身份绑到自己的账号。
	h.tokens.Set("oauth:bind:"+state, u.ID, h.sessionID(r))
	// 绑定与登录共用同一回调地址 /callback/{type}，以便在三方平台只需登记一个回调地址
	redirect := h.providerRedirectURL(r, p.Type)
	cred := &oauth2.Credentials{
		ClientID:     prov.ClientID,
		ClientSecret: prov.ClientSecret,
		RedirectURL:  redirect,
	}
	returnURL := "/settings/account"
	http.Redirect(w, r, p.BuildAuthorizeURL(cred, state, "", returnURL), http.StatusFound)
}

// GET /api/v1/me/identities — 已绑定身份列表
func (h *Handler) handleIdentitiesList(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var ids []models.Identity
	if err := h.db.NewSelect().Model(&ids).Where("user_id = ?", u.ID).Scan(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	if ids == nil {
		ids = []models.Identity{}
	}
	ok(w, r, ids)
}

// DELETE /api/v1/me/identities/{id} — 解绑第三方身份
func (h *Handler) handleIdentityDelete(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 解绑第三方登录方式是敏感操作：会话被盗后，攻击者可借此摘掉受害者的登录
	// 途径。必须先完成一次身份重验证（reauth），且令牌用后即焚。
	// 此前该端点只校验普通会话，前端虽已携带 X-OpenIdP-Reauth 却无人校验。
	if !h.requireReauth(w, r, u, curSessionID(cur)) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/me/identities/")
	res, err := h.db.NewDelete().Model((*models.Identity)(nil)).
		Where("id = ? AND user_id = ?", id, u.ID).Exec(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	// 删除失败（ID 不存在或不属于当前用户）必须如实返回，不能一律回 success，
	// 否则前端会显示「已解绑」而实际什么都没发生。
	if n, _ := res.RowsAffected(); n == 0 {
		fail(w, r, http.StatusNotFound, "identity.not_found", "未找到该绑定，可能已被解绑")
		return
	}
	ok(w, r, map[string]any{"success": true})
}

// ---- 辅助方法 ----

// cooldownCheck enforces a per-email send cooldown for verification-code
// requests (signup / password reset). Returns true and writes an error when
// the request is throttled, false otherwise.
func (h *Handler) cooldownCheck(w http.ResponseWriter, r *http.Request, email, purpose string) bool {
	var last models.VerificationCode
	err := h.db.NewSelect().Model(&last).
		Where("email = ? AND purpose = ?", email, purpose).
		Order("created_at DESC").Limit(1).Scan(context.Background())
	if err == nil && time.Since(last.CreatedAt) < codeCooldownSecs*time.Second {
		wait := codeCooldownSecs - int(time.Since(last.CreatedAt).Seconds())
		fail(w, r, http.StatusTooManyRequests, "email.code_cooldown", fmt.Sprintf("发送过于频繁，请 %d 秒后重试", wait))
		return true
	}
	return false
}

// persistCode stores a code in the DB (for restart-survival / tests).
func (h *Handler) persistCode(email, purpose string, minutes int, code string) {
	now := db.Now()
	vc := &models.VerificationCode{
		Email:     email,
		Purpose:   purpose,
		Code:      code,
		ExpiresAt: now.Add(time.Duration(minutes) * time.Minute),
		CreatedAt: now,
	}
	_, _ = h.db.NewInsert().Model(vc).Exec(context.Background())
}

// maxCodeAttempts 是单个验证码允许的错误尝试次数，超过即作废，防止爆破 6 位验证码。
const maxCodeAttempts = 5

// checkCode validates a code and consumes it exactly once.
//
// 数据库 `verification_codes` 表是验证码的唯一事实来源（source of truth），
// 不做内存回退，保证进程重启后已下发的验证码仍可校验。
// 验证码一旦消费即被作废，杜绝重放；错误尝试超过 maxCodeAttempts 也会作废。
func (h *Handler) checkCode(email, purpose, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}

	// 从数据库取最近一条未使用且未过期的记录，命中则校验并原子地标记 used，消费一次。
	var vc models.VerificationCode
	err := h.db.NewSelect().Model(&vc).
		Where("email = ? AND purpose = ? AND used = false AND expires_at > ?", email, purpose, db.Now()).
		Order("created_at DESC").Limit(1).Scan(context.Background())
	if err != nil {
		return false
	}
	if vc.Code != code {
		// 错误的验证码：原子累加尝试次数，并在同一条 SQL 中判断是否达到上限（并发安全，
		// 避免多个请求基于同一旧值判断导致 DB 中 attempts 远超上限才作废）。
		_, _ = h.db.NewUpdate().Model((*models.VerificationCode)(nil)).
			Set("attempts = attempts + 1, used = CASE WHEN attempts + 1 >= ? THEN true ELSE used END", maxCodeAttempts).
			Where("id = ?", vc.ID).Exec(context.Background())
		// 最近的未使用记录不匹配：不再尝试其他记录，避免并行重放/爆破。
		return false
	}
	// 原子条件更新：仅当验证码尚未被使用时才置为已用，防止并发重复消费（重放）。
	res, err := h.db.NewUpdate().Model(&vc).
		Set("used = true").
		Where("id = ? AND used = false", vc.ID).
		Exec(context.Background())
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false
	}
	return true
}

// loadProvider loads an OAuth provider by type from the DB and returns the
// client secret needed to exchange the authorization code.
// ClientSecret 密文落库；环境变量（如 GITEE_CLIENT_SECRET）优先覆盖。
func (h *Handler) loadProvider(providerType string) (*models.OAuthProvider, error) {
	var p models.OAuthProvider
	err := h.db.NewSelect().Model(&p).Where("provider_type = ?", providerType).Scan(context.Background())
	if err != nil {
		return nil, err
	}
	// env 明文优先（运维层可随时覆盖，不依赖数据库存储）
	if csec := h.cfg.ProviderClientSecrets[providerType]; csec != "" {
		p.ClientSecret = csec
	} else {
		p.ClientSecret = secretpkg.Decrypt(p.ClientSecret)
	}
	return &p, nil
}

// resolveProvider returns the oauth2.Provider definition for a provider type.
//
// 端点一律以数据库取值为准（内置提供商的端点由初始化写入库，管理员可在后台修改）；
// 数据库里该字段为空时回落到内置注册表的默认值，因此「清空 = 恢复内置默认」。
// 没有任何来源可取（既非内置、库中端点也不全）时返回 false。
func (h *Handler) resolveProvider(providerType string) (*oauth2.Provider, bool) {
	builtin, isBuiltin := oauth2.Get(providerType)
	prov, err := h.loadProvider(providerType)
	if err != nil {
		if !isBuiltin {
			return nil, false
		}
		// 库里查不到记录（尚未初始化）时退回纯内置定义。
		cp := *builtin
		return &cp, true
	}
	if !isBuiltin && !prov.Custom {
		return nil, false
	}
	// overrides：把数据库配置覆盖到内置默认值之上（两者都空则由下面的校验拦下）。
	overrides := func(target *oauth2.Provider) {
		if v := strings.TrimSpace(prov.AuthorizeURL); v != "" {
			target.AuthorizeURL = v
		}
		if v := strings.TrimSpace(prov.TokenURL); v != "" {
			target.TokenURL = v
		}
		if v := strings.TrimSpace(prov.UserInfoURL); v != "" {
			target.UserInfoURL = v
		}
		if v := strings.TrimSpace(prov.OpenIDURL); v != "" {
			target.OpenIDURL = v
		}
		if len(prov.Scopes) > 0 {
			target.Scopes = prov.Scopes
		}
		if v := strings.TrimSpace(prov.DocsURL); v != "" {
			target.DocsURL = v
		}
	}
	if isBuiltin {
		// 必须返回注册表对象的**拷贝**：Registry 里的 *Provider 是包级共享对象，
		// 而 AuthorizeURL / ExchangeCode 等调用会在并发请求中读取 p.HTTPClient。
		// 原地写 p.HTTPClient 会与这些读构成数据竞争（-race 可复现），
		// 两个用户同时点第三方登录即可能读到撕裂的接口值。
		cp := *builtin
		overrides(&cp)
		// 用户信息解析函数来自内置定义，端点改写不会影响解析逻辑。
		cp.HTTPClient = h.proxyClientForProvider(prov)
		if cp.AuthorizeURL == "" || cp.TokenURL == "" || cp.UserInfoURL == "" {
			return nil, false
		}
		return &cp, true
	}
	pv := oauth2.NewCustomProvider(prov.ProviderType, prov.DisplayName, prov.AuthorizeURL, prov.TokenURL, prov.UserInfoURL, prov.Scopes)
	pv.HTTPClient = h.proxyClientForProvider(prov)
	if pv.AuthorizeURL == "" || pv.TokenURL == "" || pv.UserInfoURL == "" {
		return nil, false
	}
	return pv, true
}

// requestBaseURL resolves the public base URL for the current request, based on
// the domain the user is actually visiting. This lets OAuth callbacks work when
// the site is reached via a custom domain (e.g. 1.com) even if SITE_URL still
// points at localhost.
//
// Resolution order:
//  1. localhost / private access → SITE_URL (dev convenience, matches classic behavior)
//  2. otherwise → scheme + host of the current request
//     - when TRUST_PROXY=true, X-Forwarded-Proto / X-Forwarded-Host are honoured
//     - otherwise scheme comes from TLS and host from the Host header
func (h *Handler) requestBaseURL(r *http.Request) string {
	// 已显式配置公网 SITE_URL 时优先使用它（受信任的配置），避免依赖客户端可控
	// 的 Host / X-Forwarded-* 头。仅当 SITE_URL 仍是 localhost 占位时，才退回
	// 动态拼接以支持自定义域名访问。
	if su := strings.TrimRight(h.cfg.SiteURL, "/"); !h.cfg.SiteURLIsPlaceholder() {
		return su
	}
	if isLocal(r) {
		if u := strings.TrimRight(h.cfg.SiteURL, "/"); u != "" {
			return u
		}
	}
	proto := ""
	host := ""
	// 仅当显式开启 TRUST_PROXY，且 TCP 对端确实落在可信代理网段内时，才采信转发头。
	// 缺少对端校验时，任何能在请求中塞入 X-Forwarded-Host 的人（例如绕过 CDN
	// 直连应用端口，或反代未剥离该头）都能把三方登录的 redirect_uri 改写到自己的
	// 域名——用户在第三方平台完成授权后，授权码会被投递到攻击者服务器。
	// 这与 middleware.ResolveClientIP 的判定保持一致：可信网段之外一律不采信。
	if h.cfg.TrustProxy && middleware.TrustedPeer(r, h.cfg.TrustedProxies) {
		proto = r.Header.Get("X-Forwarded-Proto")
		host = r.Header.Get("X-Forwarded-Host")
	}
	if host == "" {
		host = r.Host
	}
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	// 使用经过清洗的 host（含 X-Forwarded-Host），防止 Host 头注入影响回调地址。
	host = sanitizeHost(host)
	if host == "" {
		host = "localhost"
	}
	return proto + "://" + host
}

// providerRedirectURL builds the OAuth callback URL for login, based on the
// domain the user is actually visiting (so 1.com/api/oauth/callback/qq works even when
// SITE_URL is still localhost).
func (h *Handler) providerRedirectURL(r *http.Request, providerType string) string {
	return h.requestBaseURL(r) + "/api/oauth/callback/" + providerType
}

// loginOrSignupWithProvider finds or creates a user for a provider profile.
func (h *Handler) loginOrSignupWithProvider(r *http.Request, profile *oauth2.Profile) (*models.User, bool, error) {
	ctx := r.Context()
	var idn models.Identity
	err := h.db.NewSelect().Model(&idn).Where("provider = ? AND provider_uid = ?", profile.Provider, profile.ProviderUID).Scan(ctx)
	if err == nil {
		var u models.User
		if err := h.db.NewSelect().Model(&u).Where("id = ?", idn.UserID).Scan(ctx); err != nil {
			return nil, false, err
		}
		return &u, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	// 新用户：仅当三方返回的邮箱已通过该平台验证，才允许按邮箱自动关联已有账户。
	// 否则一律新建独立账号，避免攻击者伪造未认证邮箱接管他人账号（SSO 账号接管）。
	var u models.User
	created := false
	if profile.Email != "" && profile.EmailVerified {
		err = h.db.NewSelect().Model(&u).Where("lower(email) = lower(?)", profile.Email).Scan(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}
	if u.ID == 0 {
		username := safeUsername(profile.Provider, profile.ProviderUID)
		u = models.User{
			Username:      username,
			DisplayName:   auth.FirstNonEmpty(profile.DisplayName, username),
			Email:         profile.Email,
			EmailVerified: profile.EmailVerified,
			AvatarURL:     defaultAvatarURL,
			PasswordSet:   false,
		}
		if err := h.createUser(ctx, &u); err != nil {
			return nil, false, err
		}
		created = true
	}
	// 绑定身份
	ident := &models.Identity{
		ID:          auth.NewID(),
		UserID:      u.ID,
		Provider:    profile.Provider,
		ProviderUID: profile.ProviderUID,
		DisplayName: profile.DisplayName,
		AvatarURL:   profile.AvatarURL,
		Email:       profile.Email,
		CreatedAt:   db.Now(),
	}
	if _, err := h.db.NewInsert().Model(ident).Exec(ctx); err != nil {
		return nil, false, err
	}
	return &u, created, nil
}

// bindIdentity links a provider identity to an existing user.
func (h *Handler) bindIdentity(userID int64, profile *oauth2.Profile) error {
	ctx := context.Background()
	n, _ := h.db.NewSelect().Model((*models.Identity)(nil)).
		Where("provider = ? AND provider_uid = ?", profile.Provider, profile.ProviderUID).Count(ctx)
	if n > 0 {
		return errors.New("该第三方账号已绑定其他用户")
	}
	ident := &models.Identity{
		ID:          auth.NewID(),
		UserID:      userID,
		Provider:    profile.Provider,
		ProviderUID: profile.ProviderUID,
		DisplayName: profile.DisplayName,
		AvatarURL:   profile.AvatarURL,
		Email:       profile.Email,
		CreatedAt:   db.Now(),
	}
	_, err := h.db.NewInsert().Model(ident).Exec(ctx)
	return err
}

// safeUsername 从 provider 与 uid 生成符合用户名规则（仅字母数字，3-32 位）的账号名。
// 非字母数字字符直接丢弃，再补一段随机后缀降低碰撞概率；
// 可提取的字符过少时退化为纯随机账号名。
func safeUsername(provider, uid string) string {
	base := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, provider+uid)
	if len(base) > usernameMaxLength-6 {
		base = base[:usernameMaxLength-6]
	}
	if len(base) < usernameMinLength {
		// provider/uid 里几乎没有可用字符，退化为纯随机账号名。
		return "u" + auth.RandomHex(8)
	}
	return base + auth.RandomHex(3)
}

// parseReturnURL sanitizes a return URL to the same-origin path.
// 缺省与非法值统一回落到站点首页（/），登录页则为 /sign-in。
func parseReturnURL(raw string) string {
	if raw == "" {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	// 拒绝绝对 URL 与协议相对 URL（//host/path），防止开放重定向。
	// 同时拒绝以 \ 开头的变体：浏览器会把反斜杠归一化为正斜杠，\/host 等价于
	// //host，从而绕过上面对 // 的检查（见 RFC 3986 与 WHATWG URL 处理）。
	if u.IsAbs() || u.Host != "" || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "\\") {
		return "/"
	}
	// 拒绝包含反斜杠的路径（可能被浏览器重解释为 host 分隔）。
	if strings.Contains(raw, "\\") {
		return "/"
	}
	return raw
}
