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

// emailVerifySession 为指定用户建立已登录会话，返回会话 ID 与 CSRF 令牌。
func emailVerifySession(t *testing.T, h *Handler, u *models.User) (string, string) {
	t.Helper()
	sessID := auth.NewID()
	if _, err := h.db.NewInsert().Model(&models.Session{
		ID: sessID, SessionHash: hashSessionID(sessID), UserID: u.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour), LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)
	return sessID, csrf
}

// TestEmailVerifySuccess 令牌正确且已登录时应成功，并把邮箱置为已验证。
// 端点免 CSRF（用户可能从邮件直接打开），故请求不带 CSRF 头也应通过。
func TestEmailVerifySuccess(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "verifyuser", "Str0ngPassw0rd!")
	sessID, _ := emailVerifySession(t, h, u)

	token := auth.RandomHex(24)
	h.tokens.Set("email:verify:"+token, u.ID, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verify", strings.NewReader(`{"token":"`+token+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	fresh := new(models.User)
	if err := h.db.NewSelect().Model(fresh).Where("id = ?", u.ID).Scan(context.Background()); err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if !fresh.EmailVerified {
		t.Fatal("email must be marked verified")
	}
}

// TestEmailVerifyTokenIsSingleUse 令牌一次性消费：重复提交同一令牌必须失败。
func TestEmailVerifyTokenIsSingleUse(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "onceuser", "Str0ngPassw0rd!")
	sessID, _ := emailVerifySession(t, h, u)

	token := auth.RandomHex(24)
	h.tokens.Set("email:verify:"+token, u.ID, "")
	body := `{"token":"` + token + `"}`

	first := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verify", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	router.ServeHTTP(first, req1)
	if first.Code != http.StatusOK {
		t.Fatalf("first verify = %d, want 200 (body=%s)", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verify", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	router.ServeHTTP(second, req2)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed verify = %d, want 400 (body=%s)", second.Code, second.Body.String())
	}
}

// TestEmailVerifyAnonymousGets401 未登录时返回 401，且令牌不被消费。
// 页面据此引导登录，登录后携带同一令牌回跳仍能验证成功。
func TestEmailVerifyAnonymousGets401(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "anonuser", "Str0ngPassw0rd!")

	token := auth.RandomHex(24)
	h.tokens.Set("email:verify:"+token, u.ID, "")
	body := `{"token":"` + token + `"}`

	anon := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(anon, req)
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous verify = %d, want 401 (body=%s)", anon.Code, anon.Body.String())
	}

	// 令牌未被消费：登录后重试仍成功。
	sessID, _ := emailVerifySession(t, h, u)
	retry := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verify", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	router.ServeHTTP(retry, req2)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after login = %d, want 200 (body=%s)", retry.Code, retry.Body.String())
	}
}

// TestEmailVerifyRejectsOtherUsersToken 他人令牌不得用于验证当前账号。
func TestEmailVerifyRejectsOtherUsersToken(t *testing.T) {
	h, router := newTestHandler(t)
	owner := createTestUser(t, h.db, "tokenowner", "Str0ngPassw0rd!")
	attacker := createTestUser(t, h.db, "attacker", "Str0ngPassw0rd!")
	sessID, _ := emailVerifySession(t, h, attacker)

	token := auth.RandomHex(24)
	h.tokens.Set("email:verify:"+token, owner.ID, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verify", strings.NewReader(`{"token":"`+token+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cross-user verify = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestEmailVerifyMissingToken 缺少令牌参数时返回 400。
func TestEmailVerifyMissingToken(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "notoken", "Str0ngPassw0rd!")
	sessID, _ := emailVerifySession(t, h, u)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verify", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing token = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
