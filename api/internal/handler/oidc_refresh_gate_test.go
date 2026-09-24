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

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// newOfflineTestClient 插入一个可用 offline_access 的机密客户端。
func newOfflineTestClient(t *testing.T, h *Handler, id string, scopes []string) *models.OAuthClient {
	t.Helper()
	hash, err := auth.HashPassword("test-secret")
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	c := &models.OAuthClient{
		ID:           id,
		Name:         "Test Client " + id,
		ClientType:   "confidential",
		SecretHash:   hash,
		RedirectURIs: []string{"http://localhost/cb"},
		Scopes:       scopes,
		CreatedAt:    time.Now().UTC(),
	}
	if _, err := h.db.NewInsert().Model(c).Exec(context.Background()); err != nil {
		t.Fatalf("insert oauth client: %v", err)
	}
	return c
}

// exchangeCodeForToken 走完 authorize → consent → token 全流程，返回令牌响应体。
func exchangeCodeForToken(t *testing.T, h *Handler, clientID, clientSecret, scope string) map[string]any {
	t.Helper()
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrfU := loginAs(t, h, alice)

	verifier, challenge := pkcePair("verifier-offline-gate-1234")
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost/cb"},
		"response_type":         {"code"},
		"scope":                 {scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := authorize(h, sessID, q.Encode())
	ticket := strings.TrimPrefix(w.Header().Get("Location"), "/oauth/consent?request=")
	if ticket == "" || ticket == w.Header().Get("Location") {
		t.Fatalf("consent ticket missing, loc=%q", w.Header().Get("Location"))
	}

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
	red, err := url.Parse(allow.Data.Redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {red.Query().Get("code")},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
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
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return out
}

// TestTokenIssuesRefreshOnlyWithOfflineAccess 仅当 scope 包含 offline_access
// 时才签发刷新令牌；未申请离线访问时响应中不得出现 refresh_token。
func TestTokenIssuesRefreshOnlyWithOfflineAccess(t *testing.T) {
	h, _ := newTestHandler(t)
	newOfflineTestClient(t, h, "app-offline", []string{"openid", "profile", "offline_access"})

	if _, ok := exchangeCodeForToken(t, h, "app-offline", "test-secret", "openid profile offline_access")["refresh_token"]; !ok {
		t.Errorf("scope 含 offline_access 时必须返回 refresh_token")
	}

	h2, _ := newTestHandler(t)
	newOfflineTestClient(t, h2, "app-online", []string{"openid", "profile"})
	if _, ok := exchangeCodeForToken(t, h2, "app-online", "test-secret", "openid profile")["refresh_token"]; ok {
		t.Errorf("未申请 offline_access 时不得返回 refresh_token")
	}
}

// TestOfflineAccessPersistTokensSkipsRefresh 未申请离线访问时不应落库 refresh 记录。
func TestOfflineAccessPersistTokensSkipsRefresh(t *testing.T) {
	if offlineGranted("openid profile") {
		t.Errorf("openid profile 不应视为已授权离线访问")
	}
	if !offlineGranted("openid offline_access") {
		t.Errorf("openid offline_access 应视为已授权离线访问")
	}
}
