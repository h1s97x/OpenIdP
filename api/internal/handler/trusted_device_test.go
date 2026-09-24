package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// insertTestMFA 为测试用户启用二次验证。
func insertTestMFA(t *testing.T, db *bun.DB, userID int64) {
	t.Helper()
	if _, err := db.NewInsert().Model(&models.MFA{
		UserID:  userID,
		Secret:  secretpkg.Encrypt("JBSWY3DPEHPK3PXP"),
		Enabled: true,
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert mfa: %v", err)
	}
}

// enablePasswordLogin 打开密码登录开关并让配置缓存失效。
func enablePasswordLogin(t *testing.T, h *Handler) {
	t.Helper()
	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("password_login_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("enable password login: %v", err)
	}
	h.conf.invalidate()
}

// withDeviceCookie 给请求带上设备 Cookie。
func withDeviceCookie(req *http.Request, devID string) {
	req.AddCookie(&http.Cookie{Name: "openidp_device_id", Value: devID})
}

// TestTrustedDeviceSkipsMFA 已标记为可信的设备在密码登录时应跳过二次验证。
func TestTrustedDeviceSkipsMFA(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "trustuser", "Str0ngPassw0rd!")
	enablePasswordLogin(t, h)
	insertTestMFA(t, h.db, u.ID)

	const devID = "device-abc"

	// 未标记可信：应收到 MFA 挑战。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session/login",
		jsonBody(map[string]any{"login": u.Username, "password": "Str0ngPassw0rd!"}))
	req.Header.Set("Content-Type", "application/json")
	withDeviceCookie(req, devID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if !hasMFAChallenge(t, rec) {
		t.Fatalf("untrusted device must be challenged (code=%d body=%s)", rec.Code, rec.Body.String())
	}

	// 标记可信：通过登录态的 /me/trusted-devices 接口，走与前端一致的路径。
	markTrusted := func() {
		sessID := auth.NewID()
		insertSession(t, h.db, u.ID, sessID)
		csrf := auth.RandomToken(32)
		h.tokens.Set(csrf, u.ID, sessID)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/me/trusted-devices",
			jsonBody(map[string]any{"name": "My PC"}))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-OpenIdP-CSRF", csrf)
		r.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
		withDeviceCookie(r, devID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("mark trusted = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
	}
	markTrusted()

	// 同一设备再次登录：不应再要求二次验证。
	req = httptest.NewRequest(http.MethodPost, "/api/v1/session/login",
		jsonBody(map[string]any{"login": u.Username, "password": "Str0ngPassw0rd!"}))
	req.Header.Set("Content-Type", "application/json")
	withDeviceCookie(req, devID)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login on trusted device = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if hasMFAChallenge(t, rec) {
		t.Fatal("trusted device must not be challenged for MFA")
	}
}

// TestUntrustedDeviceStillNeedsMFA 其它设备（不同设备 Cookie）不得跳过二次验证，
// 否则可信设备会退化成"账号级关闭 MFA"。
func TestUntrustedDeviceStillNeedsMFA(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "trustuser2", "Str0ngPassw0rd!")
	enablePasswordLogin(t, h)
	insertTestMFA(t, h.db, u.ID)

	// 在 devA 上标记可信。
	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/trusted-devices",
		jsonBody(map[string]any{"name": "PC-A"}))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-OpenIdP-CSRF", csrf)
	r.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	withDeviceCookie(r, "devA")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("mark trusted = %d (body=%s)", w.Code, w.Body.String())
	}

	// 从 devB 登录：仍须二次验证。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session/login",
		jsonBody(map[string]any{"login": u.Username, "password": "Str0ngPassw0rd!"}))
	req.Header.Set("Content-Type", "application/json")
	withDeviceCookie(req, "devB")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if !hasMFAChallenge(t, rec) {
		t.Fatalf("another device must still be challenged (code=%d body=%s)", rec.Code, rec.Body.String())
	}
}

// TestExpiredTrustedDeviceDoesNotSkipMFA 过期的可信设备不得跳过二次验证。
func TestExpiredTrustedDeviceDoesNotSkipMFA(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "trustuser3", "Str0ngPassw0rd!")
	enablePasswordLogin(t, h)
	insertTestMFA(t, h.db, u.ID)

	const devID = "device-expired"
	if _, err := h.db.NewInsert().Model(&models.TrustedDevice{
		ID:        auth.NewID(),
		UserID:    u.ID,
		DeviceID:  devID,
		Name:      "Old PC",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
		CreatedAt: time.Now().UTC().AddDate(0, -1, 0),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert trusted device: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/session/login",
		jsonBody(map[string]any{"login": u.Username, "password": "Str0ngPassw0rd!"}))
	req.Header.Set("Content-Type", "application/json")
	withDeviceCookie(req, devID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if !hasMFAChallenge(t, rec) {
		t.Fatalf("expired trusted device must be challenged (code=%d body=%s)", rec.Code, rec.Body.String())
	}
}

// TestAddTrustedDeviceReusesDeviceAndHonorsTTL 重复标记同一设备不应堆出多条记录，
// 且有效期必须来自配置而不是写死三个月。
func TestAddTrustedDeviceReusesDeviceAndHonorsTTL(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "trustuser4", "Str0ngPassw0rd!")
	// 配置可信设备有效期为 30 天（后台安全策略优先于环境变量）。
	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("trusted_device_ttl_days = ?", 30).Exec(context.Background()); err != nil {
		t.Fatalf("set trusted device ttl: %v", err)
	}
	h.conf.invalidate()

	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)

	post := func(name string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/me/trusted-devices",
			jsonBody(map[string]any{"name": name}))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-OpenIdP-CSRF", csrf)
		r.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
		withDeviceCookie(r, "dev-dup")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := post("First"); w.Code != http.StatusOK {
		t.Fatalf("first mark = %d (body=%s)", w.Code, w.Body.String())
	}
	if w := post("Second"); w.Code != http.StatusOK {
		t.Fatalf("second mark = %d (body=%s)", w.Code, w.Body.String())
	}
	n, err := h.db.NewSelect().Model((*models.TrustedDevice)(nil)).
		Where("user_id = ?", u.ID).Count(context.Background())
	if err != nil {
		t.Fatalf("count trusted devices: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 trusted device for the same device cookie, got %d", n)
	}
	var td models.TrustedDevice
	if err := h.db.NewSelect().Model(&td).Where("user_id = ?", u.ID).Scan(context.Background()); err != nil {
		t.Fatalf("load trusted device: %v", err)
	}
	if td.DeviceID != "dev-dup" {
		t.Fatalf("device_id = %q, want dev-dup", td.DeviceID)
	}
	if td.Name != "Second" {
		t.Fatalf("name = %q, want Second (re-marking should update in place)", td.Name)
	}
	days := int(time.Until(td.ExpiresAt).Hours() / 24)
	if days < 29 || days > 30 {
		t.Fatalf("expires_at约 %d 天后到期，应约为配置值 30 天", days)
	}
}

// TestLoginPolicyWebAuthnFollowsSetting login-policy 的 webAuthn 必须反映
// 通行密钥开关，未开启时不得下发 true（登录页据此隐藏入口）。
func TestLoginPolicyWebAuthnFollowsSetting(t *testing.T) {
	_, router := newTestHandler(t)
	_, data := doGET(t, router, "/api/v1/login-policy")
	if data["webAuthn"] != false {
		t.Fatalf("webAuthn = %v, want false when passkeys are disabled", data["webAuthn"])
	}
}

// TestDeleteAccountRequiresPolicyEnabled 未开放自助注销时不接受请求。
func TestDeleteAccountRequiresPolicyEnabled(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "deluser", "Str0ngPassw0rd!")
	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/account-deletion",
		jsonBody(map[string]any{"password": "Str0ngPassw0rd!", "code": "123456"}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OpenIdP-CSRF", csrf)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("request account deletion = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestRequestAccountDeletionRequiresPassword 开放后必须校验当前密码：
// 密码错误时不得创建注销申请。
func TestRequestAccountDeletionRequiresPassword(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "deluser2", "Str0ngPassw0rd!")
	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("account_deletion_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("enable account deletion: %v", err)
	}
	h.conf.invalidate()
	// 启用 MFA：该断言验证的是「二次验证码错误时不得创建申请」，
	// 只有当账号确实具备第二因素时这个前提才成立（无第二因素时后端只校验密码）。
	insertTestMFA(t, h.db, u.ID)

	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)

	post := func(body map[string]any) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/me/account-deletion", jsonBody(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-OpenIdP-CSRF", csrf)
		req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(map[string]any{"password": "wrong-password", "code": "123456"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("request with wrong password = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	// 密码正确但二次验证码错误：同样不得创建申请。
	if rec := post(map[string]any{"password": "Str0ngPassw0rd!", "code": "000000"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("request with bad 2FA code = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	n, _ := h.db.NewSelect().Model((*models.AccountDeletionRequest)(nil)).
		Where("user_id = ?", u.ID).Count(context.Background())
	if n != 0 {
		t.Fatalf("no deletion request should be created, got %d", n)
	}
}

// TestRequestAccountDeletionPasswordOnlyWithoutSecondFactor 账号既未启用 MFA
// 也没有可用邮箱时，注销申请只应校验密码。
//
// 背景：旧实现无条件要求二次验证码，这类账号拿不出任何验证码，
// 会永久卡在 reauth.unavailable 上——既注销不了，也没有任何自救路径。
func TestRequestAccountDeletionPasswordOnlyWithoutSecondFactor(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "deluser_nofactor", "Str0ngPassw0rd!")
	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("account_deletion_enabled = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("enable account deletion: %v", err)
	}
	h.conf.invalidate()

	// 前置条件：该账号确实没有任何第二因素
	factors := h.loadSecondFactorOptions(u)
	if factors.Required {
		t.Fatalf("前置条件不成立：该账号不应具备第二因素，got methods=%v", factors.Methods)
	}

	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/account-deletion",
		jsonBody(map[string]any{"password": "Str0ngPassw0rd!", "code": ""}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OpenIdP-CSRF", csrf)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password-only request = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

// totpCodeNow 按 RFC 6238 计算给定密钥当前时间窗的 6 位验证码。
// 测试没有别的办法拿到「当前有效」的 MFA 码，只能自己算一个。
func totpCodeNow(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode test secret: %v", err)
	}
	var buf [8]byte
	counter := uint64(time.Now().Unix()) / 30
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[off])&0x7f)<<24 |
		uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 |
		uint32(sum[off+3])
	return fmt.Sprintf("%06d", val%1000000)
}

// TestSecondFactorMethodIsEnforced 指定 method 时只接受对应方式的验证码：
// 切到邮箱验证码后，即使账号启用了 MFA，MFA 码也不得通过。
//
// 否则界面上显示的校验方式与后端实际校验的不一致——用户按提示输入 MFA 码会
// 一直失败，切换入口也就形同虚设。
func TestSecondFactorMethodIsEnforced(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "sfuser", "Str0ngPassw0rd!")
	insertTestMFA(t, h.db, u.ID)

	// 该账号只启用了 MFA，邮箱不可用（测试环境未配置 SMTP）
	factors := h.loadSecondFactorOptions(u)
	if !factors.MFAEnabled {
		t.Fatal("前置条件不成立：该账号应已启用 MFA")
	}

	valid := totpCodeNow(t, "JBSWY3DPEHPK3PXP")
	// 先确认这个码在 MFA 方式下确实有效，否则后面的断言没有意义。
	if !h.verifySecondFactorMethod(u, valid, "mfa") {
		t.Fatalf("前置条件不成立：有效 MFA 码 %q 未能通过 method=mfa 校验", valid)
	}
	// 同一个码在 method=email 下必须被拒绝：邮箱验证码走的是另一套签发逻辑，
	// 若这里放行，等于切换方式后仍在隐式接受 MFA 码。
	if h.verifySecondFactorMethod(u, valid, "email") {
		t.Errorf("method=email 时不得接受 MFA 验证码 %q", valid)
	}
	// method 为空（自动选择）时按 MFA 优先，仍应通过。
	if !h.verifySecondFactorMethod(u, valid, "") {
		t.Error("method 为空时应自动选择 MFA 并通过校验")
	}
}

// TestCancelAccountDeletion 用户可在冷静期内撤回注销申请。
func TestCancelAccountDeletion(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "deluser3", "Str0ngPassw0rd!")
	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)

	if _, err := h.db.NewInsert().Model(&models.AccountDeletionRequest{
		ID:          auth.NewID(),
		UserID:      u.ID,
		Status:      models.DeletionStatusPending,
		ScheduledAt: time.Now().UTC().Add(time.Hour),
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert deletion request: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/account-deletion", nil)
	req.Header.Set("X-OpenIdP-CSRF", csrf)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: sessID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel deletion = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var dr models.AccountDeletionRequest
	if err := h.db.NewSelect().Model(&dr).Where("user_id = ?", u.ID).Scan(context.Background()); err != nil {
		t.Fatalf("load deletion request: %v", err)
	}
	if dr.Status != models.DeletionStatusCancelled {
		t.Fatalf("status = %q, want cancelled", dr.Status)
	}
	// 撤回后账号仍然存在。
	n, _ := h.db.NewSelect().Model((*models.User)(nil)).
		Where("id = ?", u.ID).Count(context.Background())
	if n != 1 {
		t.Fatalf("user must survive cancellation, got %d", n)
	}
}

// TestAdminApproveDeletionPurgesUser 管理员通过冷静期已满的申请后，
// 账号及其关联数据必须被级联删除。
func TestAdminApproveDeletionPurgesUser(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "deluser4", "Str0ngPassw0rd!")
	admin := createTestUser(t, h.db, "deladmin", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(admin).Set("is_admin = ?", true).WherePK().Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	adminSess := auth.NewID()
	insertSession(t, h.db, admin.ID, adminSess)
	adminCSRF := auth.RandomToken(32)
	h.tokens.Set(adminCSRF, admin.ID, adminSess)

	reqID := auth.NewID()
	if _, err := h.db.NewInsert().Model(&models.AccountDeletionRequest{
		ID:          reqID,
		UserID:      u.ID,
		Status:      models.DeletionStatusPending,
		ScheduledAt: time.Now().UTC().Add(-time.Minute), // 冷静期已结束
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert deletion request: %v", err)
	}
	if _, err := h.db.NewInsert().Model(&models.Grant{
		ID: auth.RandomToken(16), UserID: u.ID, ClientID: "app-1", Scopes: []string{"openid"},
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert grant: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/account-deletion-requests/"+reqID+"/approve", jsonBody(map[string]any{}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OpenIdP-CSRF", adminCSRF)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: adminSess})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve deletion = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	n, _ := h.db.NewSelect().Model((*models.User)(nil)).
		Where("id = ?", u.ID).Count(context.Background())
	if n != 0 {
		t.Fatal("user must be removed after approval")
	}
	g, _ := h.db.NewSelect().Model((*models.Grant)(nil)).
		Where("user_id = ?", u.ID).Count(context.Background())
	if g != 0 {
		t.Fatalf("grants must be cascade-deleted, got %d", g)
	}
}

// TestAdminRejectDeletionKeepsUser 管理员驳回后账号必须保留，且状态变为 rejected。
func TestAdminRejectDeletionKeepsUser(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "deluser5", "Str0ngPassw0rd!")
	admin := createTestUser(t, h.db, "deladmin2", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(admin).Set("is_admin = ?", true).WherePK().Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	adminSess := auth.NewID()
	insertSession(t, h.db, admin.ID, adminSess)
	adminCSRF := auth.RandomToken(32)
	h.tokens.Set(adminCSRF, admin.ID, adminSess)

	reqID := auth.NewID()
	if _, err := h.db.NewInsert().Model(&models.AccountDeletionRequest{
		ID:          reqID,
		UserID:      u.ID,
		Status:      models.DeletionStatusPending,
		ScheduledAt: time.Now().UTC().Add(-time.Minute),
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert deletion request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/account-deletion-requests/"+reqID+"/reject",
		jsonBody(map[string]any{"note": "疑似被盗号"}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OpenIdP-CSRF", adminCSRF)
	req.AddCookie(&http.Cookie{Name: "openidp_session", Value: adminSess})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject deletion = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	n, _ := h.db.NewSelect().Model((*models.User)(nil)).
		Where("id = ?", u.ID).Count(context.Background())
	if n != 1 {
		t.Fatalf("user must survive rejection, got %d", n)
	}
	var dr models.AccountDeletionRequest
	if err := h.db.NewSelect().Model(&dr).Where("id = ?", reqID).Scan(context.Background()); err != nil {
		t.Fatalf("load deletion request: %v", err)
	}
	if dr.Status != models.DeletionStatusRejected {
		t.Fatalf("status = %q, want rejected", dr.Status)
	}
}

// jsonBody 把任意值编码为请求体。
func jsonBody(v any) *strings.Reader {
	b, _ := json.Marshal(v)
	return strings.NewReader(string(b))
}

// insertSession 直接插入一条有效会话，供需要登录态的测试使用。
func insertSession(t *testing.T, db *bun.DB, userID int64, sessID string) {
	t.Helper()
	if _, err := db.NewInsert().Model(&models.Session{
		ID:          sessID,
		SessionHash: hashSessionID(sessID),
		UserID:      userID,
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
		LastSeenAt:  time.Now().UTC(),
		CreatedAt:   time.Now().UTC(),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert session: %v", err)
	}
}

// hasMFAChallenge 判定登录响应是否为「需要二次验证」。
func hasMFAChallenge(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	var envelope struct {
		Data struct {
			MFARequired bool `json:"mfaRequired"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode login response: %v (body=%s)", err, rec.Body.String())
	}
	return envelope.Data.MFARequired
}
