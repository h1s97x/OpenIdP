package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// setupAdminSession 建立测试库、管理员账号与已登录会话，返回 handler、会话 ID 与 CSRF 令牌。
func setupAdminSession(t *testing.T) (*Handler, string, string) {
	t.Helper()
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "smokeadmin", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(u).WherePK().Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	sessID := auth.NewID()
	if _, err := h.db.NewInsert().Model(&models.Session{
		ID: sessID, SessionHash: hashSessionID(sessID), UserID: u.ID,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)
	return h, sessID, csrf
}

// call 发起一次带会话与 CSRF 的请求。
func call(h *Handler, sessID, csrf, method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if sessID != "" {
		r.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	}
	if csrf != "" {
		r.Header.Set("X-OpenIdP-CSRF", csrf)
	}
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	return w
}

// pngBytes 是最小合法的 1x1 PNG，用于头像上传测试。
var pngBytes = []byte{
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
	0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
	0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
	0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
	0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
	0x42, 0x60, 0x82,
}

// uploadAvatar 上传头像并返回结果中的 avatarUrl。
func uploadAvatar(t *testing.T, h *Handler, sessID, csrf string) string {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(pngBytes); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/avatar", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	r.Header.Set("X-OpenIdP-CSRF", csrf)
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("avatar upload failed: %d %s", w.Code, w.Body.String())
	}
	var parsed struct {
		Data struct {
			AvatarURL string `json:"avatarUrl"`
		}
	}
	_ = json.Unmarshal(w.Body.Bytes(), &parsed)
	return parsed.Data.AvatarURL
}

// TestSmokeFileEndpoints 冒烟：内容寻址文件的上传/读取/缓存/Range 行为。
func TestSmokeFileEndpoints(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)

	// 站点默认关闭头像上传，先开启。
	st := h.loadSiteSetting()
	st.AvatarUploadEnabled = true
	if _, err := h.db.NewUpdate().Model(st).WherePK().Set("avatar_upload_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.conf.invalidate()

	avatarURL := uploadAvatar(t, h, sessID, csrf)
	if !strings.HasPrefix(avatarURL, "/api/v1/files/") {
		t.Fatalf("avatar URL should be content-addressed, got %q", avatarURL)
	}
	publicID := strings.TrimPrefix(avatarURL, "/api/v1/files/")
	if len(publicID) != 24 {
		t.Fatalf("publicId should be 24 chars, got %q (len=%d)", publicID, len(publicID))
	}

	// 免鉴权直读（不带任何 cookie / CSRF）
	r := httptest.NewRequest(http.MethodGet, avatarURL, nil)
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("anonymous file read failed: %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("unexpected content type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("expected immutable cache, got %q", cc)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header")
	}

	// 条件请求 → 304
	r = httptest.NewRequest(http.MethodGet, avatarURL, nil)
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusNotModified {
		t.Errorf("expected 304, got %d", w.Code)
	}

	// Range → 206
	r = httptest.NewRequest(http.MethodGet, avatarURL, nil)
	r.Header.Set("Range", "bytes=0-9")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusPartialContent {
		t.Errorf("expected 206, got %d %s", w.Code, w.Body.String())
	}

	// 不存在的文件 → 404（且不泄露存在性差异）
	r = httptest.NewRequest(http.MethodGet, "/api/v1/files/DOESNOTEXIST123456789", nil)
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing file, got %d", w.Code)
	}

	// 换头像后旧文件进入解绑状态（不立即删除）
	oldURL := avatarURL
	newURL := uploadAvatar(t, h, sessID, csrf)
	if newURL == oldURL {
		t.Fatal("expected new avatar URL after re-upload")
	}
	detached, _ := h.db.NewSelect().Model((*models.File)(nil)).
		Where("detached_at IS NOT NULL").Count(context.Background())
	if detached < 1 {
		t.Errorf("expected detached file after avatar change, got %d", detached)
	}
}

// TestSmokeAdminEndpoints 冒烟：新增管理端点均可达且返回 200。
func TestSmokeAdminEndpoints(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)
	cases := []struct{ method, path string }{
		{"GET", "/api/v1/me/notifications/unread-count"},
		{"GET", "/api/v1/admin/files"},
		{"GET", "/api/v1/admin/files/orphans"},
		{"POST", "/api/v1/admin/files/orphans/cleanup"},
		{"GET", "/api/v1/admin/storage"},
		{"GET", "/api/v1/admin/storage/stats"},
		{"GET", "/api/v1/admin/location"},
		{"POST", "/api/v1/admin/location/test"},
		{"GET", "/api/v1/admin/audit-events"},
		{"GET", "/api/v1/admin/audit-settings"},
		{"GET", "/api/v1/admin/data-cleanup"},
		{"POST", "/api/v1/admin/data-cleanup/run"},
		{"GET", "/api/v1/admin/system-status"},
		{"GET", "/api/v1/admin/oauth-scopes"},
		{"GET", "/api/v1/admin/notifications"},
		{"GET", "/api/v1/oauth/device-authorizations"},
		{"GET", "/api/v1/capabilities"},
	}
	for _, c := range cases {
		body := ""
		if c.method == "POST" {
			body = "{}"
		}
		w := call(h, sessID, csrf, c.method, c.path, body)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s = %d, want 200 (body=%s)", c.method, c.path, w.Code, w.Body.String())
		}
	}
}

// TestSmokeDiscoveryDeviceFlow 冒烟：discovery 声明设备授权且端点真实可用。
func TestSmokeDiscoveryDeviceFlow(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)

	w := call(h, "", "", "GET", "/.well-known/openid-configuration", "")
	var disc struct {
		GrantTypes []string `json:"grant_types_supported"`
		DeviceEP   string   `json:"device_authorization_endpoint"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("discovery parse: %v", err)
	}
	hasDevice := false
	for _, g := range disc.GrantTypes {
		if g == "urn:ietf:params:oauth:grant-type:device_code" {
			hasDevice = true
		}
	}
	if !hasDevice {
		t.Errorf("discovery should declare device_code grant: %+v", disc)
	}
	if disc.DeviceEP == "" {
		t.Errorf("discovery should expose device_authorization_endpoint")
	}

	// 注册一个客户端用于设备授权
	client := &models.OAuthClient{
		ID: "smoke-client", Name: "Smoke", ClientType: "public",
		RedirectURIs: []string{"http://localhost/cb"}, Scopes: []string{"openid", "email"},
		CreatedAt: time.Now().UTC(),
	}
	if _, err := h.db.NewInsert().Model(client).Exec(context.Background()); err != nil {
		t.Fatalf("insert client: %v", err)
	}

	form := url.Values{"client_id": {"smoke-client"}, "scope": {"openid email"}}
	r := httptest.NewRequest(http.MethodPost, "/api/login/oauth/device_authorization", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("device authorization failed: %d %s", w.Code, w.Body.String())
	}
	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &da); err != nil {
		t.Fatalf("parse device auth: %v", err)
	}
	if da.UserCode == "" || da.DeviceCode == "" {
		t.Fatalf("device auth missing codes: %s", w.Body.String())
	}
	// scope 应收敛到客户端已登记范围（越权 scope 被剔除）
	var stored models.DeviceAuthorization
	if err := h.db.NewSelect().Model(&stored).Where("device_code = ?", da.DeviceCode).Scan(context.Background()); err != nil {
		t.Fatalf("load device auth: %v", err)
	}
	if stored.Scope != "openid email" {
		t.Errorf("scope should be intersected to client scopes, got %q", stored.Scope)
	}
	// 越权 scope 校验：请求未登记的 phone 应被剔除
	form2 := url.Values{"client_id": {"smoke-client"}, "scope": {"openid phone address"}}
	r2 := httptest.NewRequest(http.MethodPost, "/api/login/oauth/device_authorization", strings.NewReader(form2.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	h.Router().ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("device authorization (scoped) failed: %d", w2.Code)
	}
	var da2 struct {
		DeviceCode string `json:"device_code"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &da2)
	var stored2 models.DeviceAuthorization
	_ = h.db.NewSelect().Model(&stored2).Where("device_code = ?", da2.DeviceCode).Scan(context.Background())
	if stored2.Scope != "openid" {
		t.Errorf("unregistered scopes should be dropped, got %q", stored2.Scope)
	}

	// 待确认时轮询应返回 authorization_pending
	form = url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da.DeviceCode},
		"client_id":   {"smoke-client"},
	}
	r = httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	var pend struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &pend)
	if pend.Error != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %q (body=%s)", pend.Error, w.Body.String())
	}

	// 用户需先输入设备上显示的 user_code 完成认领，之后才能批准。
	// 未认领的授权不对任何用户可见、也不可被批准——否则任意登录用户只要拿到
	// （或猜中）user_code，就能把他人的设备会话绑到自己账号上。
	w = call(h, sessID, csrf, "POST", "/api/v1/oauth/device-authorizations", `{"userCode":"`+da.UserCode+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("device verify failed: %d %s", w.Code, w.Body.String())
	}
	// 用户批准后应能换取令牌
	w = call(h, sessID, csrf, "POST", "/api/v1/oauth/device-authorizations/"+da.UserCode, `{"decision":"approve"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("device approve failed: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("expected access token, got %q", w.Body.String())
	}
}

// TestSmokeExportAndEvents 冒烟：导出为附件下载；事件支持分页且写入 session.* 事件。
func TestSmokeExportAndEvents(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)

	w := call(h, sessID, csrf, "GET", "/api/v1/me/export", "")
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("export should be attachment, got %q", cd)
	}

	w = call(h, sessID, csrf, "GET", "/api/v1/me/events?page=1&pageSize=5", "")
	if w.Code != http.StatusOK {
		t.Fatalf("events failed: %d %s", w.Code, w.Body.String())
	}
	var ev struct {
		Data struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ev); err != nil {
		t.Fatalf("parse events: %v", err)
	}
	if len(ev.Data.Items) > 5 {
		t.Errorf("pageSize not honored: got %d items", len(ev.Data.Items))
	}
}
