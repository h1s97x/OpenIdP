package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// 本文件覆盖 2026-09-11 安全审查中修复的几个问题的回归测试。
// 每个测试都对应一处曾经的漏洞，改动相关逻辑时应当保持通过。

// newScopeTestClient 建一个只登记指定 scope 的机密客户端。
func newScopeTestClient(t *testing.T, h *Handler, id string, scopes []string) *models.OAuthClient {
	t.Helper()
	c := &models.OAuthClient{
		ID: id, Name: id, ClientType: "confidential",
		RedirectURIs: []string{"http://localhost/cb"},
		Scopes:       scopes,
		CreatedAt:    time.Now().UTC(),
	}
	if _, err := h.db.NewInsert().Model(c).Exec(context.Background()); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	return c
}

func authorizeURL(clientID, scope string) string {
	return "/login/oauth/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=http%3A%2F%2Flocalhost%2Fcb&scope=" + strings.ReplaceAll(scope, " ", "+")
}

// TestAuthorizeScopeConvergedToClientScopes 授权入口必须把请求的 scope 收敛到
// 客户端已登记的范围内。此前 scope 被原样透传，应用只要请求就能拿到超出登记
// 范围的权限（如 email / phone / offline_access）。
func TestAuthorizeScopeConvergedToClientScopes(t *testing.T) {
	h, sessID, _ := setupAdminSession(t)
	newScopeTestClient(t, h, "scope-converge", []string{"openid"})

	w := call(h, sessID, "", "GET", authorizeURL("scope-converge", "openid email profile phone address offline_access"), "")
	if w.Code != http.StatusFound {
		t.Fatalf("expected redirect to consent, got %d %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	const prefix = "/oauth/consent?request="
	if !strings.HasPrefix(loc, prefix) {
		t.Fatalf("expected consent redirect, got %q", loc)
	}
	req, ok := h.peekConsent(strings.TrimPrefix(loc, prefix))
	if !ok {
		t.Fatal("consent ticket not found")
	}
	if req.Scope != "openid" {
		t.Errorf("scope must be converged to client scopes, got %q", req.Scope)
	}
}

// TestAuthorizeScopeExpansionRequiresConsent 已有授权覆盖请求 scope 时才允许跳过
// 同意页；应用一旦扩大权限范围，必须重新征求用户同意，而不是静默签发。
func TestAuthorizeScopeExpansionRequiresConsent(t *testing.T) {
	h, sessID, _ := setupAdminSession(t)
	newScopeTestClient(t, h, "scope-expand", []string{"openid", "email"})

	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("username = ?", "smokeadmin").Scan(context.Background()); err != nil {
		t.Fatalf("load user: %v", err)
	}
	// 用户此前只同意过 openid
	if _, err := h.db.NewInsert().Model(&models.Grant{
		ID: auth.RandomToken(24), UserID: u.ID, ClientID: "scope-expand",
		Scopes: []string{"openid"}, CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert grant: %v", err)
	}

	// 同范围：应直接签发授权码（跳过同意页）
	w := call(h, sessID, "", "GET", authorizeURL("scope-expand", "openid"), "")
	if w.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("scope covered by grant should skip consent, got %q", loc)
	}

	// 扩大范围（新增 email）：必须重新进入同意页
	w = call(h, sessID, "", "GET", authorizeURL("scope-expand", "openid email"), "")
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/oauth/consent?request=") {
		t.Errorf("scope expansion must require consent, got %q", loc)
	}
}

// TestDeviceAuthorizationUnclaimedNotListedNorApprovable 未认领的设备授权不得出现
// 在任何用户的列表里，也不允许被直接批准——否则任意登录用户都能抢先把他人的
// 设备会话绑到自己账号上（会话混淆）。
func TestDeviceAuthorizationUnclaimedNotListedNorApprovable(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)
	const code = "ABCD2345"
	if _, err := h.db.NewInsert().Model(&models.DeviceAuthorization{
		DeviceCode: auth.RandomToken(32), UserCode: code,
		ClientID: "unclaimed-client", Scope: "openid",
		Status: models.DeviceAuthPending, Interval: 5,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert device auth: %v", err)
	}

	// 列表不得泄漏未认领记录的 user_code
	w := call(h, sessID, "", "GET", "/api/v1/oauth/device-authorizations", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list failed: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), code) {
		t.Errorf("unclaimed device authorization leaked into list: %s", w.Body.String())
	}

	// 未认领时不可批准
	w = call(h, sessID, csrf, "POST", "/api/v1/oauth/device-authorizations/"+code, `{"decision":"approve"}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("unclaimed device authorization must not be approvable, got %d %s", w.Code, w.Body.String())
	}

	// 输入 user_code 完成认领后，才能批准
	w = call(h, sessID, csrf, "POST", "/api/v1/oauth/device-authorizations", `{"userCode":"`+code+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verify (claim) failed: %d %s", w.Code, w.Body.String())
	}
	w = call(h, sessID, csrf, "POST", "/api/v1/oauth/device-authorizations/"+code, `{"decision":"approve"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("approve after claim failed: %d %s", w.Code, w.Body.String())
	}
}

// TestIdentityDeleteRequiresReauth 解绑第三方身份是敏感操作，必须携带有效且
// 一次性的 reauth 令牌。此前服务端完全不校验该令牌（前端却一直在发送）。
func TestIdentityDeleteRequiresReauth(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)

	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("username = ?", "smokeadmin").Scan(context.Background()); err != nil {
		t.Fatalf("load user: %v", err)
	}
	ident := &models.Identity{
		ID: auth.NewID(), UserID: u.ID, Provider: "github",
		ProviderUID: "gh-1", CreatedAt: time.Now().UTC(),
	}
	if _, err := h.db.NewInsert().Model(ident).Exec(context.Background()); err != nil {
		t.Fatalf("insert identity: %v", err)
	}

	doDelete := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, "/api/v1/me/identities/"+ident.ID, nil)
		r.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
		r.Header.Set("X-OpenIdP-CSRF", csrf)
		if token != "" {
			r.Header.Set("X-OpenIdP-Reauth", token)
		}
		w := httptest.NewRecorder()
		h.Router().ServeHTTP(w, r)
		return w
	}
	identityStillThere := func() bool {
		n, err := h.db.NewSelect().Model((*models.Identity)(nil)).Where("id = ?", ident.ID).Count(context.Background())
		return err == nil && n > 0
	}

	// 不带令牌：拒绝，且记录必须还在
	if w := doDelete(""); w.Code != http.StatusUnauthorized {
		t.Errorf("missing reauth token should be rejected, got %d %s", w.Code, w.Body.String())
	}
	if !identityStillThere() {
		t.Fatal("identity must not be deleted without reauth")
	}
	// 伪造令牌：同样拒绝
	if w := doDelete("totally-bogus"); w.Code != http.StatusUnauthorized {
		t.Errorf("bogus reauth token should be rejected, got %d %s", w.Code, w.Body.String())
	}
	if !identityStillThere() {
		t.Fatal("identity must not be deleted with an invalid reauth token")
	}

	// 有效令牌：放行并真正删除
	valid := auth.RandomToken(32)
	h.tokens.Set("reauth:"+valid, u.ID, sessID)
	if w := doDelete(valid); w.Code != http.StatusOK {
		t.Fatalf("valid reauth token should be accepted, got %d %s", w.Code, w.Body.String())
	}
	if identityStillThere() {
		t.Fatal("identity should have been deleted")
	}
}

// TestRequestBaseURLIgnoresForwardedHostFromUntrustedPeer 转发头只应采信来自可信
// 代理网段的对端。此前只要 TRUST_PROXY 为真就采信，任何人塞入 X-Forwarded-Host
// 都能把三方登录的 redirect_uri 改写到自己的域名，从而窃取授权码。
func TestRequestBaseURLIgnoresForwardedHostFromUntrustedPeer(t *testing.T) {
	h, _ := newTestHandler(t)
	h.cfg.TrustProxy = true
	h.cfg.TrustedProxies = nil
	// 确保走「非本机 + SITE_URL 为占位值」这条动态拼接分支
	h.cfg.SiteURL = "http://localhost:6099"

	makeReq := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/login/provider/github/authorize", nil)
		r.Host = "auth.example.com"
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-Host", "evil.example.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		return r
	}

	// 公网对端：转发头不可信，回落到经过清洗的 Host
	if got := h.requestBaseURL(makeReq("203.0.113.5:443")); strings.Contains(got, "evil.example.com") {
		t.Errorf("forwarded host from a public peer must be ignored, got %q", got)
	} else if !strings.Contains(got, "auth.example.com") {
		t.Errorf("should fall back to the sanitized Host, got %q", got)
	}

	// 可信代理对端（回环）：转发头可信，用于支持反代/自定义域名部署
	if got := h.requestBaseURL(makeReq("127.0.0.1:443")); !strings.Contains(got, "evil.example.com") {
		t.Errorf("forwarded host from a trusted proxy should be honored, got %q", got)
	}
}
