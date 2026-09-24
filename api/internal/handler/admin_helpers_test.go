package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// 管理端点的测试辅助：提权 + 建立会话 + 带 CSRF 的请求封装。
// 备份、登录提供商等用例共用这几个函数，避免每处各写一份而漂移。

// newAdminSession 把用户提升为管理员并建立会话，返回会话 ID 与 CSRF 令牌。
func newAdminSession(t *testing.T, h *Handler, u *models.User) (string, string) {
	t.Helper()
	if _, err := h.db.NewUpdate().Model((*models.User)(nil)).
		Set("is_admin = ?", true).Where("id = ?", u.ID).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)
	return sessID, csrf
}

// doAdminRequest 以管理员身份发起请求（body 非空时按 JSON 编码）。
func doAdminRequest(t *testing.T, router http.Handler, h *Handler, method, path, sessID, csrf string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, jsonBody(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if sessID != "" {
		req.AddCookie(&http.Cookie{Name: h.cfg.SessionCookieName, Value: sessID})
	}
	if csrf != "" {
		req.Header.Set(h.cfg.CSRFHeader, csrf)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
