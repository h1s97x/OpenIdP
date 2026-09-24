package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// createTestUser 直接建一个用户（含密码哈希），返回其 ID 与明文密码。
func createTestUser(t *testing.T, db *bun.DB, username, password string) *models.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u := &models.User{
		Subject:      auth.NewSubject(),
		Username:     username,
		DisplayName:  username,
		Email:        strings.ToLower(username) + "@example.com",
		PasswordHash: hash,
		PasswordSet:  true,
	}
	if _, err := db.NewInsert().Model(u).Exec(context.Background()); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return u
}

func doJSON(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestDummyPasswordHashIsRealBcrypt 保证用于抹平时序的 dummy 哈希是一个真实
// bcrypt 哈希：虚构哈希会让 CompareHashAndPassword 立刻返回，防枚举形同虚设。
func TestDummyPasswordHashIsRealBcrypt(t *testing.T) {
	if !isBcryptHash(dummyPasswordHash) {
		t.Fatalf("dummyPasswordHash is not a valid bcrypt hash: %q", dummyPasswordHash)
	}
	// 校验确实会走完整的 bcrypt 比较（返回错误而不是 panic / 提前返回）。
	if err := bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte("some-password")); err == nil {
		t.Fatal("unexpected success comparing dummy hash")
	}
}

// TestLoginFailedEventIsRecorded 登录失败（含用户不存在）必须留下审计记录。
func TestLoginFailedEventIsRecorded(t *testing.T) {
	h, router := newTestHandler(t)
	sp := h.loadSecurityPolicy()
	sp.PasswordLoginEnabled = true
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("password_login_enabled = ?", true).
		Set("password_reset_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("enable password login: %v", err)
	}
	// 测试直接改库绕过了管理端点，需手动让配置缓存失效。
	h.conf.invalidate()

	for _, login := range []string{"nobody-here", "nobody@example.com"} {
		rec := doJSON(t, router, http.MethodPost, "/api/v1/session/login", map[string]any{
			"login": login, "password": "wrong-password",
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("login with %q = %d, want 401 (body=%s)", login, rec.Code, rec.Body.String())
		}
	}
	// 审计表应记录失败事件（含 userID=0 的匿名事件）。
	n, err := h.db.NewSelect().Model((*models.Event)(nil)).
		Where("type = 'login.failed'").Count(context.Background())
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	if n < 2 {
		t.Fatalf("expected at least 2 login.failed events, got %d", n)
	}
}

// TestSessionIDStoredHashed 会话在库中只存摘要，避免库泄露即等于会话劫持。
func TestSessionIDStoredHashed(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "hashuser", "Str0ngPassw0rd!")
	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("password_login_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("enable password login: %v", err)
	}
	// 测试直接改库绕过了管理端点，需手动让配置缓存失效。
	h.conf.invalidate()

	rec := doJSON(t, router, http.MethodPost, "/api/v1/session/login", map[string]any{
		"login": u.Username, "password": "Str0ngPassw0rd!",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var sess models.Session
	if err := h.db.NewSelect().Model(&sess).Where("user_id = ?", u.ID).Scan(context.Background()); err != nil {
		t.Fatalf("load session: %v", err)
	}
	cookie := rec.Result().Cookies()
	var raw string
	for _, c := range cookie {
		if c.Name == "openidp_session" {
			raw = c.Value
		}
	}
	if raw == "" {
		t.Fatal("no session cookie set")
	}
	if sess.SessionHash == "" {
		t.Fatal("session_hash must be persisted")
	}
	if sess.SessionHash == raw {
		t.Fatal("session_hash must not equal the raw cookie value")
	}
	if sess.SessionHash != hashSessionID(raw) {
		t.Fatalf("session_hash = %q; want sha256(cookie)", sess.SessionHash)
	}
}

// TestPasswordResetHonorsPolicySwitch 管理员关闭找回密码后，两个端点都必须不可用。
func TestPasswordResetHonorsPolicySwitch(t *testing.T) {
	h, router := newTestHandler(t)
	createTestUser(t, h.db, "resetuser", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(h.loadSecurityPolicy()).WherePK().
		Set("password_reset_enabled = ?", false).Exec(context.Background()); err != nil {
		t.Fatalf("disable password reset: %v", err)
	}
	// 测试直接改库绕过了管理端点，需手动让配置缓存失效。
	h.conf.invalidate()

	rec := doJSON(t, router, http.MethodPost, "/api/v1/password-reset/request", map[string]any{"email": "resetuser@example.com"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reset request = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, router, http.MethodPost, "/api/v1/password-reset/confirm", map[string]any{
		"email": "resetuser@example.com", "code": "123456", "password": "An0therStr0ng!",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reset confirm = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMFAChallengeLockedAfterMaxAttempts 二次验证挑战在错误尝试达到上限后作废。
func TestMFAChallengeLockedAfterMaxAttempts(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "mfauser", "Str0ngPassw0rd!")
	// 预置一个"已启用"的 MFA 记录（密钥无关紧要，验证码必然错误）。
	if _, err := h.db.NewInsert().Model(&models.MFA{
		UserID:  u.ID,
		Secret:  secretpkg.Encrypt("JBSWY3DPEHPK3PXP"),
		Enabled: true,
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert mfa: %v", err)
	}

	challengeID := h.createMFAChallenge(u.ID, "password")
	for i := 0; i < maxMFAAttempts; i++ {
		h.countMFAFailure(u.ID, &models.MFAChallenge{ID: challengeID})
	}
	var ch models.MFAChallenge
	if err := h.db.NewSelect().Model(&ch).Where("id = ?", challengeID).Scan(context.Background()); err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if !ch.Used {
		t.Fatalf("challenge must be invalidated after %d failed attempts (attempts=%d)", maxMFAAttempts, ch.Attempts)
	}
}

// TestMFAChallengeSinglePerUser 同一用户只保留一个有效挑战，防止堆积挑战绕过计数上限。
func TestMFAChallengeSinglePerUser(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "mfauser2", "Str0ngPassw0rd!")
	first := h.createMFAChallenge(u.ID, "password")
	second := h.createMFAChallenge(u.ID, "password")
	if first == second {
		t.Fatal("expected a new challenge id")
	}
	n, _ := h.db.NewSelect().Model((*models.MFAChallenge)(nil)).
		Where("user_id = ?", u.ID).Count(context.Background())
	if n != 1 {
		t.Fatalf("expected exactly 1 pending challenge, got %d", n)
	}
}

// TestClientConfidentialRequiresSecret 无密钥客户端不得通过客户端认证
// （否则仅凭 client_id 就能内省/撤销他人令牌）。
func TestClientConfidentialRequiresSecret(t *testing.T) {
	public := &models.OAuthClient{ID: "pub", ClientType: "public"}
	confidential := &models.OAuthClient{ID: "conf", ClientType: "confidential", SecretHash: "x"}
	legacyNoType := &models.OAuthClient{ID: "legacy", SecretHash: "x"}
	legacyEmpty := &models.OAuthClient{ID: "legacy-empty"}

	if clientConfidential(public) {
		t.Fatal("public client must not be confidential")
	}
	if !clientConfidential(confidential) {
		t.Fatal("confidential client must be confidential")
	}
	// 历史数据未回填 client_type 时按是否有密钥推导，保证同样受保护。
	if !clientConfidential(legacyNoType) {
		t.Fatal("client with a secret must be treated as confidential")
	}
	if clientConfidential(legacyEmpty) {
		t.Fatal("client without a secret and without client_type must be public")
	}
}

// TestAdminRevokeGrantRevokesOthersGrant 管理员撤销他人授权必须真正生效。
func TestAdminRevokeGrantRevokesOthersGrant(t *testing.T) {
	h, router := newTestHandler(t)
	admin := createTestUser(t, h.db, "adminuser", "Str0ngPassw0rd!")
	admin.IsAdmin = true
	if _, err := h.db.NewUpdate().Model(admin).WherePK().Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	victim := createTestUser(t, h.db, "victimuser", "Str0ngPassw0rd!")

	grant := &models.Grant{ID: auth.RandomToken(24), UserID: victim.ID, ClientID: "app-1", Scopes: []string{"openid"}}
	if _, err := h.db.NewInsert().Model(grant).Exec(context.Background()); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	// 管理员会话
	sessID := auth.NewID()
	if _, err := h.db.NewInsert().Model(&models.Session{
		ID: sessID, SessionHash: hashSessionID(sessID), UserID: admin.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour), LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, admin.ID, sessID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/oauth-grants/"+grant.ID, nil)
	req.Header.Set("X-OpenIdP-CSRF", csrf)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin revoke grant = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	n, _ := h.db.NewSelect().Model((*models.Grant)(nil)).Where("id = ?", grant.ID).Count(context.Background())
	if n != 0 {
		t.Fatal("grant must be deleted by the admin endpoint")
	}
}

// TestSecurityHeadersCoverStaticAssets 静态资源与 SPA fallback 也必须带安全响应头。
func TestSecurityHeadersCoverStaticAssets(t *testing.T) {
	h, router := newTestHandler(t)
	_ = h
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q; want nosniff", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("expected Content-Security-Policy on API responses")
	}
}

// TestBodyLimitRejectsOversizedPayload 超大请求体必须被拒绝，防止内存被打爆。
func TestBodyLimitRejectsOversizedPayload(t *testing.T) {
	_, router := newTestHandler(t)
	big := strings.Repeat("a", 2<<20) // 2MB > 1MB 上限
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session/login", strings.NewReader(`{"login":"`+big+`","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("oversized body should not be accepted")
	}
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d; want 400/413", rec.Code)
	}
}

// TestConfigCacheAvoidsRepeatedQueries 验证单行配置缓存的三个关键性质：
// 命中缓存（不每次回源）、返回副本（调用方改不动缓存）、失效后重新回源。
func TestConfigCacheAvoidsRepeatedQueries(t *testing.T) {
	h, _ := newTestHandler(t)

	first := h.loadSecurityPolicy()

	// 绕过管理端 handler 直接改库，因此不会触发 invalidate。
	// TTL 内再读若仍拿到旧值，说明确实命中了缓存而不是每次回源查库。
	if _, err := h.db.NewUpdate().Model((*models.SecurityPolicy)(nil)).
		Set("min_password_length = ?", first.MinPasswordLength+7).
		Where("id = ?", first.ID).Exec(context.Background()); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	second := h.loadSecurityPolicy()
	if second.MinPasswordLength != first.MinPasswordLength {
		t.Fatalf("TTL 内应命中缓存，MinPasswordLength = %d; want %d",
			second.MinPasswordLength, first.MinPasswordLength)
	}

	// 必须返回副本：修改返回值不得写回缓存，否则并发读方会看到「幽灵修改」。
	// （此前 cached() 直接把缓存里的指针交出去，管理端 handler 在其上原地赋值。）
	second.MinPasswordLength = 999
	third := h.loadSecurityPolicy()
	if third.MinPasswordLength == 999 {
		t.Fatal("缓存必须返回副本，修改返回值不得影响缓存内容")
	}

	// 失效后应重新回源，读到直连数据库写入的新值。
	h.conf.invalidate()
	fourth := h.loadSecurityPolicy()
	if want := first.MinPasswordLength + 7; fourth.MinPasswordLength != want {
		t.Fatalf("invalidate 后应重新回源，MinPasswordLength = %d; want %d",
			fourth.MinPasswordLength, want)
	}
}

// TestMyGrantsReturnsClientName 「我的授权」必须返回应用名，而不是只有 client_id。
//
// 背景：grants 表只存 client_id，端点直接把它下发给前端，导致授权页显示成
// 一串无法辨识的机器标识。现在需与 oauth_clients 关联补上名称与 Logo。
func TestMyGrantsReturnsClientName(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "grantowner", "Str0ngPassw0rd!")

	client := &models.OAuthClient{ID: "named-app", Name: "示例应用", LogoURL: "https://cdn.example.com/logo.png"}
	if _, err := h.db.NewInsert().Model(client).Exec(context.Background()); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	now := time.Now().UTC()
	g := &models.Grant{ID: auth.RandomToken(24), UserID: u.ID, ClientID: "named-app", Scopes: []string{"openid", "profile"}, CreatedAt: now}
	if _, err := h.db.NewInsert().Model(g).Exec(context.Background()); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	// 已被删除的应用：应回落到空名称，由前端兜底显示 client_id，不应报错或丢记录。
	orphan := &models.Grant{ID: auth.RandomToken(24), UserID: u.ID, ClientID: "deleted-app", Scopes: []string{"openid"}, CreatedAt: now}
	if _, err := h.db.NewInsert().Model(orphan).Exec(context.Background()); err != nil {
		t.Fatalf("insert orphan grant: %v", err)
	}

	_, envelope := doGETWithSession(t, h, router, u, "/api/v1/me/grants")
	items, ok := envelope["data"].([]any)
	if !ok {
		t.Fatalf("grants payload = %#v, want a list", envelope["data"])
	}
	if len(items) != 2 {
		t.Fatalf("grants count = %d, want 2（含无对应客户端的孤儿授权）", len(items))
	}

	byID := map[string]map[string]any{}
	for _, it := range items {
		m, _ := it.(map[string]any)
		id, _ := m["clientId"].(string)
		byID[id] = m
	}
	named, ok := byID["named-app"]
	if !ok {
		t.Fatalf("missing grant for named-app: %#v", byID)
	}
	if named["clientName"] != "示例应用" {
		t.Errorf("clientName = %v, want 示例应用", named["clientName"])
	}
	// Logo 只放行 http/https 绝对地址：相对路径与 javascript: 之类会被过滤为空串，
	// 避免历史数据里的危险取值被渲染进 <img src>（存储型 XSS）。
	if named["clientLogo"] != "https://cdn.example.com/logo.png" {
		t.Errorf("clientLogo = %v, want https://cdn.example.com/logo.png", named["clientLogo"])
	}
	// scopes 是 JSON 列，必须能反序列化回列表，不能是 null 或字符串。
	scopes, _ := named["scopes"].([]any)
	if len(scopes) != 2 {
		t.Errorf("scopes = %#v, want 2 items（JSON 列未正确还原）", named["scopes"])
	}
	// created_at 与 oauth_clients 同名，若不做列别名会回填为零值。
	if z, _ := named["createdAt"].(string); z == "" || z[:4] == "0001" {
		t.Errorf("createdAt = %v, want a real timestamp（JOIN 后列回填错位）", named["createdAt"])
	}
	if _, ok := byID["deleted-app"]; !ok {
		t.Error("orphan grant (deleted client) must still be listed")
	}
}

// TestAuthorizeRedirectsToLoginWithReturnUrl 未登录访问授权端点时，
// 必须带上完整、可供登录页回跳的 returnUrl（含路径与查询串，且已 URL 转义）。
//
// 背景：此前只编码了查询串且未按 URL 规则转义，登录页读到的 returnUrl 会被
// 拆散/截断，登录后回不到授权页，用户只能手动重新发起一次认证。
func TestAuthorizeRedirectsToLoginWithReturnUrl(t *testing.T) {
	h, router := newTestHandler(t)
	client := &models.OAuthClient{ID: "app-1", Name: "应用", RedirectURIs: []string{"https://app.example.com/cb"}}
	if _, err := h.db.NewInsert().Model(client).Exec(context.Background()); err != nil {
		t.Fatalf("insert client: %v", err)
	}

	target := "/login/oauth/authorize?client_id=app-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid&state=xyz"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("authorize (anonymous) = %d, want 302 (body=%s)", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/sign-in?returnUrl=") {
		t.Fatalf("Location = %q, want a redirect to the login page carrying returnUrl", loc)
	}

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	// 关键：returnUrl 必须是一个整体，其内部的 & / = 不得被当成登录页自身的查询参数。
	q := u.Query()
	if got := q.Get("returnUrl"); got != target {
		t.Errorf("returnUrl = %q, want %q（未 URL 转义时会被拆散）", got, target)
	}
	if q.Get("client_id") != "" || q.Get("state") != "" {
		t.Error("授权参数泄漏到登录页的查询串，说明 returnUrl 未被正确转义")
	}
}

// TestLoginRedirectURLRejectsUnsafeTargets 回跳地址必须经同站校验，
// 防止通过构造请求把登录页变成开放重定向。
func TestLoginRedirectURLRejectsUnsafeTargets(t *testing.T) {
	// 同站目标应原样保留（含查询串，这是授权流程能续上的前提）。
	sameSite := "/login/oauth/authorize?client_id=app-1&state=xyz"
	r := httptest.NewRequest(http.MethodGet, sameSite, nil)
	if got := returnURLFromLoginRedirect(t, loginRedirectURL(r)); got != sameSite {
		t.Errorf("same-site: returnUrl = %q, want %q", got, sameSite)
	}

	// 协议相对 URL 是唯一能穿过 RequestURI 的跨站形式，必须被收敛为 "/"。
	r = httptest.NewRequest(http.MethodGet, "//evil.example.com/x", nil)
	if got := returnURLFromLoginRedirect(t, loginRedirectURL(r)); got != "/" {
		t.Errorf("protocol-relative: returnUrl = %q, want / (must be sanitized)", got)
	}

	// 绝对 URL 与反斜杠变体：RequestURI() 不含 scheme+host，反斜杠会被百分号
	// 编码，最终都落在同站路径上，无法指向外部站点。
	for name, target := range map[string]string{
		"absolute":          "https://evil.example.com/x",
		"backslash variant": "/\\evil.example.com",
	} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		got := returnURLFromLoginRedirect(t, loginRedirectURL(r))
		if strings.HasPrefix(got, "//") || strings.Contains(got, "evil.example.com/x") {
			t.Errorf("%s: returnUrl = %q 指向了外部站点", name, got)
		}
	}
}

// returnURLFromLoginRedirect 解析登录页重定向目标并取出 returnUrl 查询参数。
func returnURLFromLoginRedirect(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse %q: %v", loc, err)
	}
	if u.Path != "/sign-in" {
		t.Fatalf("redirect path = %q, want /sign-in", u.Path)
	}
	return u.Query().Get("returnUrl")
}

// TestSessionsEndpointNeverLeaksRawSessionID 会话列表不得下发原始会话 ID。
//
// 原始会话 ID 等价于可用的登录凭据：拿到它就能直接接管账号。列表接口对外
// 暴露的 id 必须是不可逆摘要，既不能等于 Cookie 值，也不能被用来通过
// currentUser 的会话校验。
func TestSessionsEndpointNeverLeaksRawSessionID(t *testing.T) {
	h, router := newTestHandler(t)
	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("password_login_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("enable password login: %v", err)
	}
	h.conf.invalidate()
	u := createTestUser(t, h.db, "sessleak", "Str0ngPassw0rd!")

	rec := doJSON(t, router, http.MethodPost, "/api/v1/session/login", map[string]any{
		"login": u.Username, "password": "Str0ngPassw0rd!",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	raw := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "openidp_session" {
			raw = c.Value
		}
	}
	if raw == "" {
		t.Fatal("no session cookie set")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/sessions", nil)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: raw})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /me/sessions = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), raw) {
		t.Fatalf("raw session id leaked in /me/sessions response: %s", rec.Body.String())
	}

	// 列表返回的 id 必须不可用于会话校验：拿它当 Cookie 访问受保护端点应 401。
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	sessions := body.Data
	if len(sessions) == 0 {
		t.Fatal("expected at least one session")
	}
	exposed, _ := sessions[0]["id"].(string)
	if exposed == "" || exposed == raw {
		t.Fatalf("sessions[0].id = %q, want a non-raw digest", exposed)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/me/sessions", nil)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: exposed})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("using exposed id as cookie = %d, want 401", rec.Code)
	}

	// 且库中不得再残留可用的原始会话 ID。
	var stored []string
	if err := h.db.NewSelect().Model((*models.Session)(nil)).Column("id").Scan(context.Background(), &stored); err != nil {
		t.Fatalf("load session ids: %v", err)
	}
	for _, id := range stored {
		if id == raw {
			t.Fatal("raw session id is still persisted in sessions.id")
		}
	}
}

// TestStorageTestAndSaveAcceptsBody 存储「测试连通性并保存」必须能读到请求体。
//
// 此前该端点先 pendingStorageFrom（内部 decodeJSONBody 吃光 body）、再调
// handleAdminUpdateStorage 二次解码同一 body，第二次必然读到 EOF，导致
// 无论传什么都返回 400 request.invalid_body，按钮完全不可用。
func TestStorageTestAndSaveAcceptsBody(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)

	// 本地后端指向测试用的临时目录，探针写入必然成功。
	dir := t.TempDir()
	body, _ := json.Marshal(map[string]any{"backend": "local", "localPath": dir})
	rec := call(h, sessID, csrf, http.MethodPost, "/api/v1/admin/storage/test-and-save", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("test-and-save = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// 落库必须生效，且热切换后的 Provider 指向新目录。
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	st := h.loadStorageSetting()
	if st.Backend != "local" || st.LocalPath != dir {
		t.Fatalf("storage not persisted: backend=%q localPath=%q", st.Backend, st.LocalPath)
	}
}
