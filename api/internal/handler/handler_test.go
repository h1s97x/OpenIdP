package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/cache"
	"github.com/h1s97x/openidp/api/internal/config"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oidc"
)

// newTestHandler builds a Handler backed by an in-memory SQLite DB and an
// in-memory cache, suitable for endpoint-level tests.
func newTestHandler(t *testing.T) (*Handler, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	sqldb, err := openSQLiteTest(path)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	bdb := bun.NewDB(sqldb, sqlitedialect.New())
	// Windows 上未关闭的 SQLite 文件句柄会导致 TempDir 清理失败，显式关闭。
	t.Cleanup(func() { _ = bdb.Close() })
	if err := db.Migrate(context.Background(), bdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg := &config.Config{
		Addr:              ":6099",
		DataDir:           dir,
		SiteURL:           "http://localhost:6099",
		SiteDisplay:       "OpenIdP",
		SessionCookieName: "openidp_session",
		DeviceCookieName:  "openidp_device_id",
		CSRFHeader:        "X-OpenIdP-CSRF",
		SessionTTLDays:    14,
		DeviceTTLDays:     365,
	}
	c, _ := cache.New(cache.Options{}) // memory
	oidcProvider, err := oidc.NewProvider(filepath.Join(dir, "jwt"))
	if err != nil {
		t.Fatalf("oidc: %v", err)
	}
	h := New(bdb, cfg, oidcProvider, c)
	return h, h.Router()
}

func openSQLiteTest(path string) (*sql.DB, error) {
	sqldb, err := sql.Open(sqliteshim.DriverName(), "file:"+path+"?cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1)
	return sqldb, nil
}

func doGET(t *testing.T, router http.Handler, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	// The API wraps success payloads in {"data": v, "status": "ok"}.
	data, _ := envelope["data"].(map[string]any)
	return rec, data
}

// doGETWithSession 以「已登录」身份发起 GET 请求，返回解包后的完整响应信封
// （含 data 字段），供需要校验列表/嵌套结构的用例使用。
func doGETWithSession(t *testing.T, h *Handler, router http.Handler, u *models.User, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	sessID := auth.NewID()
	if _, err := h.db.NewInsert().Model(&models.Session{
		ID: sessID, SessionHash: hashSessionID(sessID), UserID: u.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour), LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: h.cfg.SessionCookieName, Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body=%s)", path, rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	return rec, envelope
}

func TestHealthEndpoint(t *testing.T) {
	_, router := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health status = %v, want ok", body["status"])
	}
}

func TestVersionEndpoint(t *testing.T) {
	_, router := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("version = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if body["version"] == "" {
		t.Fatal("expected a version field")
	}
}

func TestSetupStatusEndpoint(t *testing.T) {
	_, router := newTestHandler(t)
	_, body := doGET(t, router, "/api/v1/setup/status")
	// fresh DB has no users => not initialized
	if body["initialized"] != false {
		t.Fatalf("expected initialized=false on fresh db, got %v", body["initialized"])
	}
}
