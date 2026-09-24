package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/sms"
)

// setSmsTestConfig 注入一个可用的假短信配置，并把发送结果替换为记录器。
func setSmsTestConfig(t *testing.T, h *Handler, mobile string) {
	t.Helper()
	h.sms.Store(&sms.Config{
		Enabled:   true,
		Provider:  "custom",
		CustomURL: "https://example.invalid/sms",
		CodeTTL:   5,
		Cooldown:  0,
	})
	h.smsSendHookForTest = func(phone, code string) (string, error) {
		if phone != mobile {
			t.Errorf("sent to unexpected phone: %s", phone)
		}
		return "biz-1", nil
	}
	t.Cleanup(func() { h.smsSendHookForTest = nil })
	t.Cleanup(func() { h.sms.Store(&sms.Config{}) })
}

// TestPhoneVerifyFlow 覆盖「填写手机号 → 发送验证码 → 校验通过 → 标记已验证」全流程。
func TestPhoneVerifyFlow(t *testing.T) {
	h, _ := newTestHandler(t)
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrf := loginAs(t, h, alice)
	mobile := "13800138000"
	setSmsTestConfig(t, h, mobile)

	w := call(h, sessID, csrf, "POST", "/api/v1/me/phone/send-code", `{"phone":"`+mobile+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("send-code status=%d body=%s", w.Code, w.Body.String())
	}

	// 直接从 DB 取出发送的验证码（persistCode 已落库）。
	var vc models.VerificationCode
	if err := h.db.NewSelect().Model(&vc).
		Where("email = ? AND purpose = ?", mobile, phonePurposeVerify).
		Order("created_at DESC").Limit(1).Scan(context.Background()); err != nil {
		t.Fatalf("code not persisted: %v", err)
	}

	w = call(h, sessID, csrf, "POST", "/api/v1/me/phone/verify", `{"phone":"`+mobile+`","code":"`+vc.Code+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", w.Code, w.Body.String())
	}
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", alice.ID).Scan(context.Background()); err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if u.Phone != mobile || !u.PhoneVerified {
		t.Fatalf("expected phone verified, got phone=%q verified=%v", u.Phone, u.PhoneVerified)
	}
}

// TestPhoneAddDisabledByPolicy 管理员关闭「允许添加手机号」后，写手机号的三个端点
// 都必须拒绝，且 capabilities 要如实回报不可用。
//
// 依据：界面上的入口隐藏只是约定，端点不拦的话，旧缓存的前端或直接调用接口
// 都能继续写入手机号 —— 那样这个开关就只是一层装饰。
func TestPhoneAddDisabledByPolicy(t *testing.T) {
	h, _ := newTestHandler(t)
	alice := createTestUser(t, h.db, "alicepolicy", "Str0ngPassw0rd!")
	sessID, csrf := loginAs(t, h, alice)
	setSmsTestConfig(t, h, "13800138000")

	// 管理员关闭开关（顺带覆盖 PATCH 对新字段的解析与落库）。
	admin := createTestUser(t, h.db, "policyadmin", "Str0ngPassw0rd!")
	adminSess, adminCSRF := newAdminSession(t, h, admin)
	if w := call(h, adminSess, adminCSRF, "PATCH", "/api/v1/admin/security-policy", `{"phoneAddEnabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("disable phone add: status=%d body=%s", w.Code, w.Body.String())
	}

	// capabilities 必须回报 phoneAdd=false（前端据此隐藏手机号入口）。
	w := call(h, sessID, csrf, "GET", "/api/v1/capabilities", "")
	if w.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d body=%s", w.Code, w.Body.String())
	}
	var caps struct {
		Data struct {
			Personal map[string]bool `json:"personal"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if caps.Data.Personal["phoneAdd"] {
		t.Fatal("capabilities must report phoneAdd=false when the policy disables it")
	}

	cases := []struct{ name, method, path, body string }{
		{"send-code", "POST", "/api/v1/me/phone/send-code", `{"phone":"13800138000"}`},
		{"verify", "POST", "/api/v1/me/phone/verify", `{"phone":"13800138000","code":"123456"}`},
		{"patch", "PATCH", "/api/v1/me/phone", `{"phone":"13800138000"}`},
	}
	for _, tc := range cases {
		if w := call(h, sessID, csrf, tc.method, tc.path, tc.body); w.Code != http.StatusForbidden {
			t.Fatalf("%s = %d, want 403 (body=%s)", tc.name, w.Code, w.Body.String())
		}
	}
	// 被拒绝的请求不得写库。
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", alice.ID).Scan(context.Background()); err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if u.Phone != "" || u.PhoneVerified {
		t.Fatalf("phone must stay untouched, got phone=%q verified=%v", u.Phone, u.PhoneVerified)
	}
}

// TestPhoneVerifyRejectsWrongCode 校验错误验证码不会标记已验证。
func TestPhoneVerifyRejectsWrongCode(t *testing.T) {
	h, _ := newTestHandler(t)
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrf := loginAs(t, h, alice)
	mobile := "13800138001"
	setSmsTestConfig(t, h, mobile)

	if w := call(h, sessID, csrf, "POST", "/api/v1/me/phone/send-code", `{"phone":"`+mobile+`"}`); w.Code != http.StatusOK {
		t.Fatalf("send-code status=%d", w.Code)
	}
	w := call(h, sessID, csrf, "POST", "/api/v1/me/phone/verify", `{"phone":"`+mobile+`","code":"000000"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("wrong code unexpectedly accepted")
	}
	var u models.User
	_ = h.db.NewSelect().Model(&u).Where("id = ?", alice.ID).Scan(context.Background())
	if u.PhoneVerified {
		t.Fatalf("phone must not be verified after wrong code")
	}
}

// TestSendCodeRequiresSmsConfigured 短信未配置时发送必须明确失败，而非静默成功。
func TestSendCodeRequiresSmsConfigured(t *testing.T) {
	h, _ := newTestHandler(t)
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	sessID, csrf := loginAs(t, h, alice)
	// 默认未配置短信服务。
	w := call(h, sessID, csrf, "POST", "/api/v1/me/phone/send-code", `{"phone":"13800138002"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when sms unconfigured, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestPatchPhoneResetsVerified 更换手机号必须重置验证状态。
func TestPatchPhoneResetsVerified(t *testing.T) {
	h, _ := newTestHandler(t)
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	// 预置一个已验证手机号。
	alice.Phone = "13800138003"
	alice.PhoneVerified = true
	if _, err := h.db.NewUpdate().Model(alice).WherePK().Exec(context.Background()); err != nil {
		t.Fatalf("seed phone: %v", err)
	}
	sessID, csrf := loginAs(t, h, alice)

	// 换成新号码：应重置为未验证。
	w := call(h, sessID, csrf, "PATCH", "/api/v1/me/phone", `{"phone":"13900139000"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("patch phone status=%d body=%s", w.Code, w.Body.String())
	}
	var u models.User
	_ = h.db.NewSelect().Model(&u).Where("id = ?", alice.ID).Scan(context.Background())
	if u.Phone != "13900139000" || u.PhoneVerified {
		t.Fatalf("changed phone must reset verification, got phone=%q verified=%v", u.Phone, u.PhoneVerified)
	}

	// profile PATCH 不再受理手机号：手机号只能在 /me/phone* 流程里维护。
	// 请求体里带上 phone 时应被忽略——既不改号码，也不重置验证状态。
	// 回归此前的缺陷：该端点无条件写回 Phone，前端一次「只改昵称」的保存
	// 就会把已有手机号清空并重置验证状态。
	alice.Phone = "13800138003"
	alice.PhoneVerified = true
	_, _ = h.db.NewUpdate().Model(alice).WherePK().Exec(context.Background())
	w = call(h, sessID, csrf, "PATCH", "/api/v1/me/profile", `{"displayName":"Alice","phone":"13700137000"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("profile patch status=%d body=%s", w.Code, w.Body.String())
	}
	_ = h.db.NewSelect().Model(&u).Where("id = ?", alice.ID).Scan(context.Background())
	if u.Phone != "13800138003" || !u.PhoneVerified {
		t.Fatalf("profile patch must ignore phone, got phone=%q verified=%v", u.Phone, u.PhoneVerified)
	}
}

// TestPhoneNormalize 覆盖手机号归一化规则。
func TestPhoneNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"13800138000", "13800138000", true},
		{"+8613800138000", "13800138000", true},
		{"138 0013 8000", "13800138000", true},
		{"23800138000", "", false},
		{"1380013800", "", false},
		{"abc", "", false},
	}
	for _, c := range cases {
		got, ok := sms.NormalizePhone(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NormalizePhone(%q)=(%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestOIDCPhoneVerifiedClaim 未验证手机号在 OIDC 中必须标记 phone_number_verified=false。
func TestOIDCPhoneVerifiedClaim(t *testing.T) {
	h, _ := newTestHandler(t)
	u := &models.User{
		Subject:       "sub-phone",
		Username:      "phoneuser",
		Email:         "phone@example.com",
		Phone:         "13800138009",
		PhoneVerified: false,
	}
	if _, err := h.db.NewInsert().Model(u).Exec(context.Background()); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	// 直接插入一个带 phone scope 的 access token。
	tok := &models.Token{
		ID:        "phone-access-token",
		Type:      "access",
		UserID:    u.ID,
		ClientID:  "client-x",
		Scope:     "openid phone",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	if _, err := h.db.NewInsert().Model(tok).Exec(context.Background()); err != nil {
		t.Fatalf("insert token: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tok.ID)
	w := httptest.NewRecorder()
	h.HandleUserInfo(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo status=%d body=%s", w.Code, w.Body.String())
	}
	var claims map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode claims: %v (%s)", err, w.Body.String())
	}
	if v, ok := claims["phone_number_verified"]; !ok || v != false {
		t.Fatalf("expected phone_number_verified=false, got %v (%s)", claims["phone_number_verified"], w.Body.String())
	}
}
