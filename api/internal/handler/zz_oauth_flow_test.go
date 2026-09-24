package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---------------------------------------------------------------------------
// OAuth 2.0 / OIDC 授权码流程（authorization code flow）测试。
//
// 背景：仓库此前只覆盖了设备授权流（RFC 8628），而授权码流程是绝大多数
// 第三方应用接入时使用的主路径，却完全没有测试。本文件补齐该路径，并重点
// 验证「多用户」场景下的授权隔离：A 用户的授权不得被 B 用户查看或复用。
// ---------------------------------------------------------------------------

// newOAuthTestClient 插入一个测试用 OAuth 客户端。
// clientType 为 "public"（无密钥，强制 PKCE）或 "confidential"（有密钥）。
func newOAuthTestClient(t *testing.T, h *Handler, id, clientType string) *models.OAuthClient {
	t.Helper()
	c := &models.OAuthClient{
		ID:           id,
		Name:         "Test Client " + id,
		ClientType:   clientType,
		RedirectURIs: []string{"http://localhost/cb"},
		Scopes:       []string{"openid", "profile", "email"},
		CreatedAt:    time.Now().UTC(),
	}
	if clientType == "confidential" {
		secret := "test-secret"
		hash, err := auth.HashPassword(secret)
		if err != nil {
			t.Fatalf("hash client secret: %v", err)
		}
		c.SecretHash = hash
	}
	if _, err := h.db.NewInsert().Model(c).Exec(context.Background()); err != nil {
		t.Fatalf("insert oauth client: %v", err)
	}
	return c
}

// pkcePair 生成一组 PKCE code_verifier / code_challenge（S256）。
func pkcePair(verifier string) (string, string) {
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// loginAs 为指定用户建立会话，返回会话 ID 与 CSRF 令牌。
// 与 setupAdminSession 的区别：不提升为管理员，可创建任意普通用户。
func loginAs(t *testing.T, h *Handler, u *models.User) (sessID, csrf string) {
	t.Helper()
	sessID = auth.NewID()
	if _, err := h.db.NewInsert().Model(&models.Session{
		ID: sessID, SessionHash: hashSessionID(sessID), UserID: u.ID,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	csrf = auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)
	return sessID, csrf
}

// authorize 以给定会话发起授权请求，返回响应。
func authorize(h *Handler, sessID, query string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/login/oauth/authorize?"+query, nil)
	if sessID != "" {
		r.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	}
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	return w
}

// TestOAuthAuthorizeRedirectsToConsent 未授权用户首次访问授权端点应先跳到 consent 确认页。
func TestOAuthAuthorizeRedirectsToConsent(t *testing.T) {
	h, router := newTestHandler(t)
	_ = router
	newOAuthTestClient(t, h, "app-consent", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, _ := loginAs(t, h, alice)

	verifier, challenge := pkcePair("my-code-verifier-1234")
	q := url.Values{
		"client_id":             {"app-consent"},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"st-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := authorize(h, sessID, q.Encode())
	if w.Code != http.StatusFound {
		t.Fatalf("authorize = %d, want 302 (body=%s)", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/oauth/consent?request=") {
		t.Fatalf("expected redirect to consent page, got %q", loc)
	}
	_ = verifier
}

// TestOAuthPublicClientRequiresPKCE public 客户端（无 secret）必须携带 PKCE，
// 否则拒绝：防止授权码被截获后在无客户端认证的情况下被兑换。
func TestOAuthPublicClientRequiresPKCE(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-public", "public")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, _ := loginAs(t, h, alice)

	q := url.Values{
		"client_id":     {"app-public"},
		"redirect_uri":  {"http://localhost/cb"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	w := authorize(h, sessID, q.Encode())
	// 客户端已校验，错误按 OAuth 规范重定向回 redirect_uri 并带 error 参数
	if w.Code != http.StatusFound {
		t.Fatalf("public client without PKCE = %d, want 302 (body=%s)", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected invalid_request error, got %q", loc)
	}

	// 补齐 PKCE 后应放行（首跳 consent）
	_, challenge := pkcePair("verifier-abc")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	w = authorize(h, sessID, q.Encode())
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "/oauth/consent?request=") {
		t.Errorf("public client with PKCE should proceed to consent, got %d %q", w.Code, w.Header().Get("Location"))
	}
}

// TestOAuthRejectsNonWhitelistedRedirectURI 不在白名单的 redirect_uri 必须被拒绝。
// 这是开放重定向防护：未校验的 redirect_uri 不得用于跳转。
func TestOAuthRejectsNonWhitelistedRedirectURI(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-redir", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, _ := loginAs(t, h, alice)

	q := url.Values{
		"client_id":     {"app-redir"},
		"redirect_uri":  {"http://evil.example.com/steal"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	w := authorize(h, sessID, q.Encode())
	// 修复后：不可信 redirect_uri 一律返回 400 JSON，绝不带 Location 跳转
	if w.Code != http.StatusBadRequest {
		t.Fatalf("non-whitelisted redirect = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("must not redirect to non-whitelisted URI, got Location=%q", loc)
	}
}

// TestOAuthUnauthenticatedRedirectsToLogin 未登录访问授权端点应先引导登录。
func TestOAuthUnauthenticatedRedirectsToLogin(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-login", "confidential")

	q := url.Values{
		"client_id":     {"app-login"},
		"redirect_uri":  {"http://localhost/cb"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	w := authorize(h, "", q.Encode())
	if w.Code != http.StatusFound {
		t.Fatalf("anonymous authorize = %d, want 302 (body=%s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/sign-in") {
		t.Errorf("expected redirect to /sign-in, got %q", loc)
	}
}

// TestOAuthFullAuthorizationCodeFlow 完整授权码流程：
// 授权 → consent 同意 → 拿到 code → 用 code 换 token → 用 token 取 userinfo。
func TestOAuthFullAuthorizationCodeFlow(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-full", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrfU := loginAs(t, h, alice)

	verifier, challenge := pkcePair("verifier-full-flow-xyz")
	q := url.Values{
		"client_id":             {"app-full"},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"state-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := authorize(h, sessID, q.Encode())
	loc := w.Header().Get("Location")
	ticket := strings.TrimPrefix(loc, "/oauth/consent?request=")
	if ticket == loc {
		t.Fatalf("consent ticket missing, loc=%q", loc)
	}

	// consent 信息可读取，且返回的是当前用户（alice）
	w = call(h, sessID, csrfU, "GET", "/api/v1/oauth/consent?request="+ticket, "")
	if w.Code != http.StatusOK {
		t.Fatalf("consent info = %d (body=%s)", w.Code, w.Body.String())
	}
	var info struct {
		Data struct {
			Account struct {
				Username string `json:"username"`
			} `json:"account"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &info)
	if info.Data.Account.Username != "alice" {
		t.Errorf("consent info should show current user alice, got %q", info.Data.Account.Username)
	}

	// 同意授权
	w = call(h, sessID, csrfU, "POST", "/api/v1/oauth/consent",
		`{"request":"`+ticket+`","action":"allow"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("consent allow = %d (body=%s)", w.Code, w.Body.String())
	}
	var allow struct {
		Data struct {
			Redirect string `json:"redirect"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &allow); err != nil {
		t.Fatalf("parse consent allow: %v", err)
	}
	if allow.Data.Redirect == "" {
		t.Fatalf("consent allow should return redirect, got %s", w.Body.String())
	}
	// 重定向地址应带 code 与原始 state
	red, err := url.Parse(allow.Data.Redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := red.Query().Get("code")
	if code == "" {
		t.Errorf("redirect should carry code: %q", allow.Data.Redirect)
	}
	if got := red.Query().Get("state"); got != "state-abc" {
		t.Errorf("state should be preserved, got %q", got)
	}

	// 用 code 换 token（confidential 客户端需携带 secret）
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"app-full"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://localhost/cb"},
	}
	r := httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("token exchange = %d (body=%s)", w.Code, w.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("expected access token, got %q", w.Body.String())
	}

	// 用 access token 取 userinfo
	r = httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo = %d (body=%s)", w.Code, w.Body.String())
	}
	var ui struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ui); err != nil {
		t.Fatalf("parse userinfo: %v", err)
	}
	if ui.Sub != alice.Subject {
		t.Errorf("userinfo sub = %q, want %q", ui.Sub, alice.Subject)
	}
	// 授权 scope 为 "openid profile"（不含 email），email 不应返回
	if ui.Email != "" {
		t.Errorf("email should be omitted when not granted, got %q", ui.Email)
	}
}

// TestOAuthCodeIsSingleUse 授权码只能使用一次，重放必须失败。
func TestOAuthCodeIsSingleUse(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-replay", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrfU := loginAs(t, h, alice)

	verifier, challenge := pkcePair("verifier-replay-test")
	q := url.Values{
		"client_id":             {"app-replay"},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := authorize(h, sessID, q.Encode())
	ticket := strings.TrimPrefix(w.Header().Get("Location"), "/oauth/consent?request=")

	w = call(h, sessID, csrfU, "POST", "/api/v1/oauth/consent",
		`{"request":"`+ticket+`","action":"allow"}`)
	var allow struct {
		Data struct {
			Redirect string `json:"redirect"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &allow)
	red, _ := url.Parse(allow.Data.Redirect)
	code := red.Query().Get("code")

	base := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"app-replay"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://localhost/cb"},
	}
	// 第一次兑换应成功
	r := httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(base.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	var first struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &first)
	if first.AccessToken == "" {
		t.Fatalf("first exchange should succeed, got %s", w.Body.String())
	}

	// 重放同一 code 应失败
	r = httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(base.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	var second struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &second)
	if second.Error == "" {
		t.Errorf("replayed code should be rejected, got %s", w.Body.String())
	}
}

// TestOAuthWrongPKCEVerifierRejected PKCE verifier 不匹配时必须拒绝，
// 否则授权码截获攻击即可得逞。
func TestOAuthWrongPKCEVerifierRejected(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-pkce", "public")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrfU := loginAs(t, h, alice)

	_, challenge := pkcePair("correct-verifier")
	q := url.Values{
		"client_id":             {"app-pkce"},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := authorize(h, sessID, q.Encode())
	ticket := strings.TrimPrefix(w.Header().Get("Location"), "/oauth/consent?request=")
	w = call(h, sessID, csrfU, "POST", "/api/v1/oauth/consent",
		`{"request":"`+ticket+`","action":"allow"}`)
	var allow struct {
		Data struct {
			Redirect string `json:"redirect"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &allow)
	red, _ := url.Parse(allow.Data.Redirect)
	code := red.Query().Get("code")

	// 用错误的 verifier 兑换
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"app-pkce"},
		"code_verifier": {"wrong-verifier"},
		"redirect_uri":  {"http://localhost/cb"},
	}
	r := httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.AccessToken != "" {
		t.Errorf("wrong PKCE verifier must not yield a token")
	}
}

// ---------------------------------------------------------------------------
// 多用户授权隔离：验证用户之间的授权互不可见、互不可用。
// ---------------------------------------------------------------------------

// TestOAuthConsentTicketNotVisibleToOtherUser consent ticket 绑定到发起授权的会话，
// 其他用户拿着同一个 ticket 不能查看或操作（防授权请求被劫持）。
func TestOAuthConsentTicketNotVisibleToOtherUser(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-multi", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	bob := createTestUser(t, h.db, "bob", "Str0ngPassw0rd!")
	aliceSess, aliceCsrf := loginAs(t, h, alice)
	bobSess, bobCsrf := loginAs(t, h, bob)

	_, challenge := pkcePair("verifier-multi-user")
	q := url.Values{
		"client_id":             {"app-multi"},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	// alice 发起授权，取得 ticket
	w := authorize(h, aliceSess, q.Encode())
	loc := w.Header().Get("Location")
	ticket := strings.TrimPrefix(loc, "/oauth/consent?request=")
	if ticket == loc {
		t.Fatalf("no consent ticket, loc=%q", loc)
	}

	// bob 用同一 ticket 查看 consent 信息：应失败（ticket 属于 alice）
	w = call(h, bobSess, bobCsrf, "GET", "/api/v1/oauth/consent?request="+ticket, "")
	if w.Code == http.StatusOK {
		t.Errorf("bob must not read alice's consent ticket (got 200)")
	}

	// bob 用同一 ticket 点同意：应失败
	w = call(h, bobSess, bobCsrf, "POST", "/api/v1/oauth/consent",
		`{"request":"`+ticket+`","action":"allow"}`)
	if w.Code == http.StatusOK {
		t.Errorf("bob must not approve alice's consent ticket (got 200)")
	}

	// alice 本人仍可正常同意（确认上面的拒绝不是因为 ticket 本身失效）
	w = call(h, aliceSess, aliceCsrf, "POST", "/api/v1/oauth/consent",
		`{"request":"`+ticket+`","action":"allow"}`)
	if w.Code != http.StatusOK {
		t.Errorf("alice should approve her own ticket, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestOAuthGrantsAreIsolatedBetweenUsers 每个用户只能看到并撤销自己的授权，
// 撤销他人授权必须失败（IDOR 防护）。
func TestOAuthGrantsAreIsolatedBetweenUsers(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-iso", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	bob := createTestUser(t, h.db, "bob", "Str0ngPassw0rd!")
	aliceSess, aliceCsrf := loginAs(t, h, alice)
	bobSess, bobCsrf := loginAs(t, h, bob)

	// 分别为 alice / bob 建立 grant
	grantAlice := &models.Grant{
		ID: "grant-alice", UserID: alice.ID, ClientID: "app-iso",
		Scopes: []string{"openid", "profile"}, CreatedAt: time.Now().UTC(),
	}
	grantBob := &models.Grant{
		ID: "grant-bob", UserID: bob.ID, ClientID: "app-iso",
		Scopes: []string{"openid"}, CreatedAt: time.Now().UTC(),
	}
	if _, err := h.db.NewInsert().Model(grantAlice).Exec(context.Background()); err != nil {
		t.Fatalf("insert alice grant: %v", err)
	}
	if _, err := h.db.NewInsert().Model(grantBob).Exec(context.Background()); err != nil {
		t.Fatalf("insert bob grant: %v", err)
	}

	// alice 只能看到自己的 1 条授权
	w := call(h, aliceSess, aliceCsrf, "GET", "/api/v1/me/grants", "")
	if w.Code != http.StatusOK {
		t.Fatalf("alice grants = %d (body=%s)", w.Code, w.Body.String())
	}
	var aliceGrants struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &aliceGrants)
	if len(aliceGrants.Data) != 1 || aliceGrants.Data[0].ID != "grant-alice" {
		t.Errorf("alice should see only her own grant, got %+v", aliceGrants.Data)
	}

	// bob 试图撤销 alice 的授权：应失败
	w = call(h, bobSess, bobCsrf, "DELETE", "/api/v1/me/grants/grant-alice", "")
	if w.Code == http.StatusOK {
		t.Errorf("bob must not revoke alice's grant (got 200)")
	}
	// 确认 alice 的授权仍在
	exists, err := h.db.NewSelect().Model((*models.Grant)(nil)).
		Where("id = ?", "grant-alice").Exists(context.Background())
	if err != nil {
		t.Fatalf("check grant: %v", err)
	}
	if !exists {
		t.Errorf("alice's grant should still exist after bob's failed revoke")
	}

	// bob 撤销自己的授权：应成功
	w = call(h, bobSess, bobCsrf, "DELETE", "/api/v1/me/grants/grant-bob", "")
	if w.Code != http.StatusOK {
		t.Errorf("bob should revoke his own grant, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestOAuthSecondUserSeesOwnConsent 第二个用户走完整流程时，
// consent 页展示的必须是第二个用户自己的账号，而不是第一个用户的。
func TestOAuthSecondUserSeesOwnConsent(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-two", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	bob := createTestUser(t, h.db, "bob", "Str0ngPassw0rd!")
	aliceSess, _ := loginAs(t, h, alice)
	bobSess, bobCsrf := loginAs(t, h, bob)

	q := url.Values{
		"client_id":     {"app-two"},
		"redirect_uri":  {"http://localhost/cb"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	// alice 已完成授权（有 grant），直接签发 code，不再走 consent
	if _, err := h.db.NewInsert().Model(&models.Grant{
		ID: "grant-alice-two", UserID: alice.ID, ClientID: "app-two",
		Scopes: []string{"openid"}, CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	w := authorize(h, aliceSess, q.Encode())
	if loc := w.Header().Get("Location"); strings.HasPrefix(loc, "/oauth/consent") {
		t.Errorf("alice already granted, should skip consent, got %q", loc)
	}

	// bob 首次授权：应走 consent，且页面展示 bob 自己
	w = authorize(h, bobSess, q.Encode())
	loc := w.Header().Get("Location")
	ticket := strings.TrimPrefix(loc, "/oauth/consent?request=")
	if ticket == loc {
		t.Fatalf("bob should hit consent page, got %q", loc)
	}
	w = call(h, bobSess, bobCsrf, "GET", "/api/v1/oauth/consent?request="+ticket, "")
	if w.Code != http.StatusOK {
		t.Fatalf("bob consent info = %d (body=%s)", w.Code, w.Body.String())
	}
	var info struct {
		Data struct {
			Account struct {
				Username string `json:"username"`
			} `json:"account"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatalf("parse consent info: %v", err)
	}
	if info.Data.Account.Username != "bob" {
		t.Errorf("consent page should show bob, got %q", info.Data.Account.Username)
	}
}

// TestUserinfoRespectsScope 不同 scope 的令牌返回的字段应不同：
// 未授予 email 时不返回 email，防止越权读取用户资料。
func TestUserinfoRespectsScope(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-scope", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrfU := loginAs(t, h, alice)

	// 只申请 openid（不申请 email）
	verifier, challenge := pkcePair("verifier-scope-test")
	q := url.Values{
		"client_id":             {"app-scope"},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := authorize(h, sessID, q.Encode())
	ticket := strings.TrimPrefix(w.Header().Get("Location"), "/oauth/consent?request=")
	w = call(h, sessID, csrfU, "POST", "/api/v1/oauth/consent",
		`{"request":"`+ticket+`","action":"allow"}`)
	var allow struct {
		Data struct {
			Redirect string `json:"redirect"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &allow)
	red, _ := url.Parse(allow.Data.Redirect)
	code := red.Query().Get("code")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"app-scope"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://localhost/cb"},
	}
	r := httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	if tok.AccessToken == "" {
		t.Fatalf("token exchange failed: %s", w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	var ui map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &ui); err != nil {
		t.Fatalf("parse userinfo: %v", err)
	}
	if _, ok := ui["email"]; ok {
		t.Errorf("email must not be returned without email scope, got %v", ui)
	}
	if _, ok := ui["sub"]; !ok {
		t.Errorf("sub must always be returned, got %v", ui)
	}
}

// TestUserinfoRejectsInvalidToken 无效/已撤销的令牌访问 userinfo 应返回 401。
func TestUserinfoRejectsInvalidToken(t *testing.T) {
	h, _ := newTestHandler(t)

	// 无 Authorization 头
	r := httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("userinfo without token = %d, want 401", w.Code)
	}

	// 伪造令牌
	r = httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	r.Header.Set("Authorization", "Bearer forged-token-not-exist")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("userinfo with forged token = %d, want 401", w.Code)
	}
}

// TestOAuthDenyReturnsAccessDenied 用户拒绝授权时应带 access_denied 回跳。
func TestOAuthDenyReturnsAccessDenied(t *testing.T) {
	h, _ := newTestHandler(t)
	newOAuthTestClient(t, h, "app-deny", "confidential")
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrfU := loginAs(t, h, alice)

	_, challenge := pkcePair("verifier-deny")
	q := url.Values{
		"client_id":             {"app-deny"},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"deny-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := authorize(h, sessID, q.Encode())
	ticket := strings.TrimPrefix(w.Header().Get("Location"), "/oauth/consent?request=")

	w = call(h, sessID, csrfU, "POST", "/api/v1/oauth/consent",
		`{"request":"`+ticket+`","action":"deny"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("consent deny = %d (body=%s)", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			Redirect string `json:"redirect"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !strings.Contains(out.Data.Redirect, "error=access_denied") {
		t.Errorf("deny should redirect with access_denied, got %q", out.Data.Redirect)
	}
	if !strings.Contains(out.Data.Redirect, "state=deny-state") {
		t.Errorf("deny should preserve state, got %q", out.Data.Redirect)
	}
	// 拒绝后不应留下 grant
	n, err := h.db.NewSelect().Model((*models.Grant)(nil)).
		Where("user_id = ?", alice.ID).Count(context.Background())
	if err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if n != 0 {
		t.Errorf("denied consent should not create a grant, got %d", n)
	}
}
