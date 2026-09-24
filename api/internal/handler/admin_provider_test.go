package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// publicProviderTypes 读取公开登录提供商列表里的 providerType 集合。
func publicProviderTypes(t *testing.T, router http.Handler) map[string]bool {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/login/providers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("login providers = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data []struct {
			ProviderType string `json:"providerType"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode providers: %v", err)
	}
	out := make(map[string]bool, len(envelope.Data))
	for _, p := range envelope.Data {
		out[p.ProviderType] = true
	}
	return out
}

// TestAdminProviderEnableRequiresCredentials 未配置凭据的提供商不允许被启用。
//
// 依据：ClientID / ClientSecret 缺任何一项都换不来 access_token，开启只会让登录页
// 与安全中心出现「点进去必然失败」的入口，而失败原因（凭据缺失）对普通用户不可见。
// 因此创建与更新两处都强制这条规则，公开列表也按同一条件过滤。
func TestAdminProviderEnableRequiresCredentials(t *testing.T) {
	h, router := newTestHandler(t)
	ctx := context.Background()
	admin := createTestUser(t, h.db, "provadmin", "Str0ngPassw0rd!")
	sessID, csrf := newAdminSession(t, h, admin)

	// 一个端点齐备、但没有任何凭据的自定义提供商（默认停用）。
	p := &models.OAuthProvider{
		ID: auth.NewID(), Name: "Oauth-testprov", ProviderType: "testprov", DisplayName: "测试提供商",
		AuthorizeURL: "https://example.com/authorize",
		TokenURL:     "https://example.com/token",
		UserInfoURL:  "https://example.com/userinfo",
		Custom:       true,
	}
	if _, err := h.db.NewInsert().Model(p).Exec(ctx); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	url := "/api/v1/admin/oauth-providers/" + p.ID

	// 1) 没有凭据直接开启 → 拒绝。
	if rec := doAdminRequest(t, router, h, http.MethodPatch, url, sessID, csrf, map[string]any{"enabled": true}); rec.Code != http.StatusBadRequest {
		t.Fatalf("enable without credentials = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// 2) 只填 ClientID、缺 Secret → 仍然拒绝。
	if rec := doAdminRequest(t, router, h, http.MethodPatch, url, sessID, csrf, map[string]any{"enabled": true, "clientId": "cid-1"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("enable with clientId only = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// 3) 凭据齐备后开启 → 接受，并且出现在公开列表里。
	if rec := doAdminRequest(t, router, h, http.MethodPatch, url, sessID, csrf, map[string]any{"enabled": true, "clientId": "cid-1", "clientSecret": "secret-1"}); rec.Code != http.StatusOK {
		t.Fatalf("enable with credentials = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if types := publicProviderTypes(t, router); !types["testprov"] {
		t.Fatal("configured provider must be listed publicly")
	}

	// 4) 创建时就以「已启用」提交但没填凭据 → 同样拒绝。
	create := map[string]any{
		"providerType": "anotherprov", "displayName": "另一个提供商",
		"authorizeUrl": "https://example.com/authorize", "tokenUrl": "https://example.com/token",
		"userInfoUrl": "https://example.com/userinfo", "enabled": true,
	}
	if rec := doAdminRequest(t, router, h, http.MethodPost, "/api/v1/admin/oauth-providers", sessID, csrf, create); rec.Code != http.StatusBadRequest {
		t.Fatalf("create enabled without credentials = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}

	// 5) 历史脏数据（直接改库造出的「已启用但无凭据」）必须被公开列表挡掉：
	//    用户侧不应出现任何不可用的提供商。
	legacy := &models.OAuthProvider{
		ID: auth.NewID(), Name: "Oauth-legacy", ProviderType: "legacyprov", DisplayName: "历史数据",
		AuthorizeURL: "https://example.com/authorize",
		TokenURL:     "https://example.com/token",
		UserInfoURL:  "https://example.com/userinfo",
		Enabled:      true, Custom: true,
	}
	if _, err := h.db.NewInsert().Model(legacy).Exec(ctx); err != nil {
		t.Fatalf("insert legacy provider: %v", err)
	}
	types := publicProviderTypes(t, router)
	if types["legacyprov"] {
		t.Fatal("enabled provider without credentials must not be listed publicly")
	}
	if !types["testprov"] {
		t.Fatal("configured provider must stay listed")
	}
}
