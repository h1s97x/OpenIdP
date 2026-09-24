package handler

import (
	"context"
	"testing"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// TestValidateUsernameRejectsSpecialCharacters 用户名只允许半角字母与数字，
// 全角字符、下划线、中文、空格等一律拒绝。
func TestValidateUsernameRejectsSpecialCharacters(t *testing.T) {
	for _, name := range []string{"admin", "Admin", "ADMIN", "abc123", "Zhang3"} {
		if msg := validateUsername(name); msg != "" {
			t.Fatalf("validateUsername(%q) = %q, want empty", name, msg)
		}
	}
	invalid := []string{
		"admin_user", // 下划线
		"admin-user", // 连字符
		"admin.cn",   // 点号
		"admin cn",   // 空格
		" cnadmin",   // 前导空格
		"张三",         // 中文
		"ａｄｍｉｎ",      // 全角字母
		"admin！",     // 全角标点
		"Аdmin",      // 西里尔字母 А
		"admin​",     // 零宽空格
		"",           // 空
	}
	for _, name := range invalid {
		if msg := validateUsername(name); msg == "" {
			t.Fatalf("validateUsername(%q) = empty, want error", name)
		}
	}
}

// TestValidateUsernameLength 用户名长度必须在 3-32 之间。
func TestValidateUsernameLength(t *testing.T) {
	if msg := validateUsername("ab"); msg == "" {
		t.Fatal("2-character username should be rejected")
	}
	if msg := validateUsername("a"); msg == "" {
		t.Fatal("1-character username should be rejected")
	}
	if msg := validateUsername("abc"); msg != "" {
		t.Fatalf("3-character username = %q, want empty", msg)
	}
	if msg := validateUsername("01234567890123456789012345678901"); msg != "" {
		t.Fatalf("32-character username = %q, want empty", msg)
	}
	if msg := validateUsername("012345678901234567890123456789012"); msg == "" {
		t.Fatal("33-character username should be rejected")
	}
}

// TestSignupRejectsInvalidUsername 注册接口必须拒绝含特殊字符的用户名，
// 而不是把它写进库里。
func TestSignupRejectsInvalidUsername(t *testing.T) {
	h, router := newTestHandler(t)
	sp := h.loadSecurityPolicy()
	sp.SignupEnabled = true
	sp.SignupEmailVerification = false
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("signup_enabled = ?", true).
		Set("signup_email_verification = ?", false).Exec(context.Background()); err != nil {
		t.Fatalf("enable signup: %v", err)
	}
	h.conf.invalidate()

	for _, name := range []string{"bad_name", "张三", "a", "ＡＢＣ"} {
		rec := doJSON(t, router, "POST", "/api/v1/signup", map[string]any{
			"username": name,
			"email":    "case-" + name + "@example.com",
			"password": "Str0ngPassw0rd!",
		})
		if rec.Code != 400 {
			t.Fatalf("signup with %q = %d, want 400 (body=%s)", name, rec.Code, rec.Body.String())
		}
	}
	n, err := h.db.NewSelect().Model((*models.User)(nil)).Count(context.Background())
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 0 {
		t.Fatalf("no user should have been created, got %d", n)
	}
}

// TestUsernameIsCaseSensitive 用户名区分大小写：仅大小写不同的两个账号
// 可以并存，且各自用自己的密码登录，不会串号。
func TestUsernameIsCaseSensitive(t *testing.T) {
	h, router := newTestHandler(t)
	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("signup_enabled = ?", true).
		Set("signup_email_verification = ?", false).
		Set("password_login_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	h.conf.invalidate()

	signup := func(name, email, password string) int {
		rec := doJSON(t, router, "POST", "/api/v1/signup", map[string]any{
			"username": name,
			"email":    email,
			"password": password,
		})
		return rec.Code
	}
	if code := signup("admin", "admin@example.com", "Str0ngPassw0rd!"); code != 200 {
		t.Fatalf("signup admin = %d, want 200", code)
	}
	if code := signup("Admin", "admin2@example.com", "An0therPassw0rd!"); code != 200 {
		t.Fatalf("signup Admin = %d, want 200 (case-differing name should be allowed)", code)
	}

	login := func(login, password string) int {
		rec := doJSON(t, router, "POST", "/api/v1/session/login", map[string]any{
			"login": login, "password": password,
		})
		return rec.Code
	}
	if code := login("admin", "Str0ngPassw0rd!"); code != 200 {
		t.Fatalf("login admin with own password = %d, want 200", code)
	}
	if code := login("Admin", "An0therPassw0rd!"); code != 200 {
		t.Fatalf("login Admin with own password = %d, want 200", code)
	}
	// 大小写输错必须登录失败，不能落到另一个账号上。
	if code := login("Admin", "Str0ngPassw0rd!"); code != 401 {
		t.Fatalf("login Admin with admin's password = %d, want 401", code)
	}
	if code := login("ADMIN", "Str0ngPassw0rd!"); code != 401 {
		t.Fatalf("login ADMIN with admin's password = %d, want 401", code)
	}
}

// TestFindUserByAccountPrefersExactUsername 按账号定位用户时先按用户名精确匹配，
// 未命中才回落到邮箱匹配，保证大小写不同的账号不会互相命中。
func TestFindUserByAccountPrefersExactUsername(t *testing.T) {
	h, _ := newTestHandler(t)
	hash, err := auth.HashPassword("Str0ngPassw0rd!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	insert := func(username, email string) int64 {
		u := &models.User{
			Subject:      auth.NewSubject(),
			Username:     username,
			DisplayName:  username,
			Email:        email,
			PasswordHash: hash,
			PasswordSet:  true,
		}
		if _, err := h.db.NewInsert().Model(u).Exec(context.Background()); err != nil {
			t.Fatalf("insert %s: %v", username, err)
		}
		return u.ID
	}
	lowerID := insert("caseuser", "case.lower@example.com")
	upperID := insert("CaseUser", "case.upper@example.com")

	got, err := findUserByAccount(context.Background(), h.db, "caseuser")
	if err != nil {
		t.Fatalf("find caseuser: %v", err)
	}
	if got.ID != lowerID {
		t.Fatalf("find caseuser = id %d, want %d", got.ID, lowerID)
	}
	got, err = findUserByAccount(context.Background(), h.db, "CaseUser")
	if err != nil {
		t.Fatalf("find CaseUser: %v", err)
	}
	if got.ID != upperID {
		t.Fatalf("find CaseUser = id %d, want %d", got.ID, upperID)
	}
	// 邮箱匹配仍然大小写不敏感。
	got, err = findUserByAccount(context.Background(), h.db, "CASE.LOWER@EXAMPLE.COM")
	if err != nil {
		t.Fatalf("find by email: %v", err)
	}
	if got.ID != lowerID {
		t.Fatalf("find by email = id %d, want %d", got.ID, lowerID)
	}
}
