package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/cache"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/sms"
)

// ---------------------------------------------------------------------------
// 回归测试：本轮修复的问题
//
// 每个用例对应一个具体缺陷，命名直接描述「原本会怎样」，
// 避免日后被当成可随意删除的重复用例。
// ---------------------------------------------------------------------------

// TestSecondAccountOnSameBrowserCanLogin 回归：同一浏览器登录第二个账号不得 500。
//
// devices.id 曾是「浏览器 device cookie 值」，查询条件却带 user_id，
// 于是第二个账号查不到自己的设备行、插入时又撞上同一主键 → 登录直接失败。
func TestSecondAccountOnSameBrowserCanLogin(t *testing.T) {
	h, _ := newTestHandler(t)
	enablePasswordLogin(t, h)
	u1 := createTestUser(t, h.db, "firstuser", "Str0ngPassw0rd!")
	u2 := createTestUser(t, h.db, "seconduser", "Str0ngPassw0rd!")

	// 同一份 device cookie，模拟「家庭共用一台电脑」。
	deviceCookie := "shared-device-cookie"
	for _, u := range []*models.User{u1, u2} {
		body := `{"login":"` + u.Username + `","password":"Str0ngPassw0rd!"}`
		r := httptest.NewRequest(http.MethodPost, "/api/v1/session/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: h.cfg.DeviceCookieName, Value: deviceCookie})
		w := httptest.NewRecorder()
		h.Router().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("用户 %s 在同一浏览器登录返回 %d（body=%s）", u.Username, w.Code, w.Body.String())
		}
	}

	// 两个账号各自持有一条设备记录，且都指向同一个设备标识。
	n, err := h.db.NewSelect().Model((*models.Device)(nil)).
		Where("device_id = ?", deviceCookie).Count(context.Background())
	if err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if n != 2 {
		t.Fatalf("期望 2 条设备记录（每个账号一条），实际 %d 条", n)
	}
}

// TestDevicePrimaryKeyIsNotTheBrowserCookie 设备主键必须与设备标识解耦。
func TestDevicePrimaryKeyIsNotTheBrowserCookie(t *testing.T) {
	h, _ := newTestHandler(t)
	enablePasswordLogin(t, h)
	u := createTestUser(t, h.db, "deviceuser", "Str0ngPassw0rd!")

	body := `{"login":"` + u.Username + `","password":"Str0ngPassw0rd!"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/session/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: h.cfg.DeviceCookieName, Value: "cookie-value"})
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d (%s)", w.Code, w.Body.String())
	}

	var dev models.Device
	if err := h.db.NewSelect().Model(&dev).Where("user_id = ?", u.ID).Scan(context.Background()); err != nil {
		t.Fatalf("query device: %v", err)
	}
	if dev.DeviceID != "cookie-value" {
		t.Errorf("device_id 应为浏览器 cookie 值，实际 %q", dev.DeviceID)
	}
	// 主键不能等于设备标识：Cookie 值等价于凭据，直接落库等于库泄露即可伪造设备。
	if dev.ID == "cookie-value" {
		t.Errorf("设备主键仍然复用了浏览器 device cookie，应改为独立随机值")
	}
}

// TestRefreshTokenReuseRevokesFamily 回归：重放已轮换的 refresh token
// 必须吊销整个令牌家族，而不是只回一个 invalid_grant。
//
// 原先入口先判 `tok.Revoked`，而轮换后的墓碑恰恰就是 revoked=true，
// 导致下面的家族吊销逻辑恒不可达——安全承诺（RFC 6819 §5.2.2.3）与实现不符。
func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	h, _ := newTestHandler(t)
	newOfflineTestClient(t, h, "app-reuse", []string{"openid", "offline_access"})

	first := exchangeCodeForToken(t, h, "app-reuse", "test-secret", "openid offline_access")
	oldRefresh, _ := first["refresh_token"].(string)
	if oldRefresh == "" {
		t.Fatal("未拿到 refresh_token")
	}

	// 正常轮换一次：旧令牌成为墓碑。
	rotated := refreshToken(t, h, "app-reuse", "test-secret", oldRefresh)
	if rotated.Code != http.StatusOK {
		t.Fatalf("首次刷新失败 = %d (%s)", rotated.Code, rotated.Body.String())
	}
	newRefresh := parseRefresh(t, rotated)

	// 重放旧令牌：应触发家族吊销。
	replay := refreshToken(t, h, "app-reuse", "test-secret", oldRefresh)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("重放旧 refresh token 应被拒绝，实际 %d (%s)", replay.Code, replay.Body.String())
	}

	// 关键断言：轮换出的新令牌也必须已被吊销（家族整体失效）。
	reuse := refreshToken(t, h, "app-reuse", "test-secret", newRefresh)
	if reuse.Code == http.StatusOK {
		t.Fatal("重放旧令牌后，家族内其它令牌仍可刷新——家族吊销未生效")
	}

	// 且必须留下审计事件。
	n, err := h.db.NewSelect().Model((*models.Event)(nil)).
		Where("type = ?", "oauth.token_reuse").Count(context.Background())
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	if n == 0 {
		t.Error("令牌重用未留下审计事件")
	}
}

// TestMultipartBodyIsLimited 回归：multipart 请求体必须有总量上限。
//
// 此前 multipart 被 BodyLimit 豁免，而 ParseMultipartForm 的 maxMemory 只是
// 内存阈值、超出部分会落临时文件，导致服务端会先把整个超大请求体读完落盘，
// 最后才回一个「文件过大」。
func TestMultipartBodyIsLimited(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "big.png")
	if err != nil {
		t.Fatal(err)
	}
	// 远超附件上限（10MB + 余量）的请求体。
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for i := 0; i < 32; i++ {
		if _, err := fw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	_ = mw.Close()

	var read int64
	handler := middleware.BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 记录服务端实际读到的字节数：修复前这里会等于完整请求体（32MB+）。
		n, _ := io.Copy(io.Discard, r.Body)
		read = n
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/files", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if read >= int64(buf.Len()) {
		t.Fatalf("multipart 请求体未被限制：读取了 %d 字节，原始请求体 %d 字节", read, buf.Len())
	}
	// 上限应落在 10MB 附件 + 表单开销余量之内。
	if read > int64(12<<20) {
		t.Errorf("multipart 读取上限过大：%d 字节", read)
	}
}

// TestCORSAllowsPutForSeparatedDeployment 回归：CORS 预检必须放行 PUT。
// 前端有 5 个管理端 PUT 调用，预检被拦会让「前后端分离部署」整片管理功能不可用。
func TestCORSAllowsPutForSeparatedDeployment(t *testing.T) {
	mw := middleware.CORS([]string{"https://auth.example.com"})
	r := httptest.NewRequest(http.MethodOptions, "/api/v1/admin/storage", nil)
	r.Header.Set("Origin", "https://auth.example.com")
	r.Header.Set("Access-Control-Request-Method", http.MethodPut)
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)

	allowed := w.Header().Get("Access-Control-Allow-Methods")
	for _, m := range []string{"PUT", "PATCH", "DELETE", "POST", "GET"} {
		if !strings.Contains(allowed, m) {
			t.Errorf("允许的方法缺少 %s：%q", m, allowed)
		}
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("跨源请求需要携带凭据，Allow-Credentials = %q", got)
	}
}

// TestLogoutOnCustomDomainIsAllowed 回归：自定义域名下登出不应恒定 403。
//
// SITE_URL 保持默认占位值（http://localhost:6099）时，发现 / 授权 / 回调 /
// 通行密钥都按实际访问域名工作，唯独 end_session 拿占位值当基准 host，
// 于真实域名下任何登出请求都会被判为跨站。
func TestLogoutOnCustomDomainIsAllowed(t *testing.T) {
	h, _ := newTestHandler(t)
	// 默认配置：SITE_URL 为 localhost 占位值。
	if !h.cfg.SiteURLIsPlaceholder() {
		t.Fatalf("测试前提不成立：SiteURL 应为占位值，实际 %q", h.cfg.SiteURL)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/logout", nil)
	r.Host = "auth.example.com"
	r.Header.Set("Origin", "https://auth.example.com")
	r.Header.Set("Referer", "https://auth.example.com/settings")
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)

	if w.Code == http.StatusForbidden {
		t.Fatalf("自定义域名下登出被误判为跨站：%d (%s)", w.Code, w.Body.String())
	}
}

// TestLogoutStillBlocksRealCrossSite 同源校验本身不能被放宽：
// 真正的跨站登出请求依旧必须被拒绝。
func TestLogoutStillBlocksRealCrossSite(t *testing.T) {
	h, _ := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/api/logout", nil)
	r.Host = "auth.example.com"
	r.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("跨站登出应被拒绝，实际 %d", w.Code)
	}
}

// TestPurgeUserRemovesFiles 回归：账号注销必须一并清理该用户的上传文件。
//
// 头像在读取端点是免鉴权直出的，只删账号不删文件会让「已注销用户」的
// 头像 URL 继续对全网可访问。
func TestPurgeUserRemovesFiles(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "purgeuser", "Str0ngPassw0rd!")

	f := &models.File{
		PublicID:    "pub-purge-1",
		Backend:     "local",
		Key:         "avatar/2026/01/pub-purge-1",
		Purpose:     models.FilePurposeAvatar,
		MimeType:    "image/png",
		ByteSize:    4,
		ContentHash: "deadbeef",
		OwnerUserID: u.ID,
		CreatedAt:   db.Now(),
	}
	if _, err := h.db.NewInsert().Model(f).Exec(context.Background()); err != nil {
		t.Fatalf("insert file: %v", err)
	}

	if err := h.purgeUser(context.Background(), u); err != nil {
		t.Fatalf("purgeUser: %v", err)
	}

	n, err := h.db.NewSelect().Model((*models.File)(nil)).
		Where("owner_user_id = ?", u.ID).Count(context.Background())
	if err != nil {
		t.Fatalf("count files: %v", err)
	}
	if n != 0 {
		t.Errorf("注销后仍残留 %d 条文件记录，头像 URL 继续可访问", n)
	}
}

// TestStepUpTokenTTLMatchesAdvertised 回归：step-up 令牌的实际有效期
// 必须与响应体里承诺的 expiresAt 一致。
//
// 此前统一按 TokenStore 的默认 TTL（30 分钟）签发，而校验只看令牌自身过期时间，
// 于是「600 秒的窗口」实际是 1800 秒，敏感操作的重验证保护被放宽 3 倍。
func TestStepUpTokenTTLMatchesAdvertised(t *testing.T) {
	if stepUpTTLSeconds >= 30*60 {
		t.Fatalf("step-up TTL 不应等于令牌库默认值：%d", stepUpTTLSeconds)
	}
	c, _ := cache.New(cache.Options{})
	ts := middleware.NewTokenStore(c, 30*time.Minute)
	ts.SetWithTTL("stepup:tok", 1, "sess", time.Duration(stepUpTTLSeconds)*time.Second)
	// 立刻有效。
	if !ts.Check("stepup:tok", "sess") {
		t.Fatal("令牌应立即可用")
	}
}

// TestOAuthScopeDisableTakesEffect 回归：后台停用的权限项必须真正参与授权判定。
//
// 此前 setOAuthScopeEnabled 只改库，intersectScopes 只看客户端登记范围，
// 后台「关闭 email 权限」不会有任何效果——比没有开关更危险，因为它给出虚假的安全感。
func TestOAuthScopeDisableTakesEffect(t *testing.T) {
	h, _ := newTestHandler(t)
	ctx := context.Background()
	// 登记内置权限项清单，再按管理后台的方式停用 email。
	// 注意这里走 Update 而非 Insert：Enabled 带 default:true 标签，
	// Insert 零值会被省略并由数据库默认值填回，与后台「停用」的实际路径不同。
	scopes := defaultOAuthScopes()
	for i := range scopes {
		if _, err := h.db.NewInsert().Model(&scopes[i]).Ignore().Exec(ctx); err != nil {
			t.Fatalf("seed scope: %v", err)
		}
	}
	if _, err := h.db.NewUpdate().Model((*models.OAuthScope)(nil)).
		Set("enabled = ?", false).Where("name = ?", "email").Exec(ctx); err != nil {
		t.Fatalf("disable scope: %v", err)
	}
	got := h.intersectScopes(ctx, "openid email profile", []string{"openid", "email", "profile"})
	if strings.Contains(got, "email") {
		t.Errorf("已停用的 email 权限仍被放行：%q", got)
	}
	if !strings.Contains(got, "profile") {
		t.Errorf("未停用的 profile 不应被剔除：%q", got)
	}

	// 走管理端点的停用接口，确认它与授权判定是同一条链路。
	u := createTestUser(t, h.db, "scopeadmin", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(u).WherePK().Set("is_admin = ?", true).Exec(ctx); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	sessID, csrf := loginAs(t, h, u)
	if w := call(h, sessID, csrf, "POST", "/api/v1/admin/oauth-scopes/profile/disable", ""); w.Code != http.StatusOK {
		t.Fatalf("停用 profile 失败：%d (%s)", w.Code, w.Body.String())
	}
	got = h.intersectScopes(ctx, "openid email profile", []string{"openid", "email", "profile"})
	if strings.Contains(got, "profile") {
		t.Errorf("管理后台停用的 profile 仍被放行：%q", got)
	}
	// openid 是必选基础权限，接口应拒绝停用。
	if w := call(h, sessID, csrf, "POST", "/api/v1/admin/oauth-scopes/openid/disable", ""); w.Code == http.StatusOK {
		t.Error("openid 为必选权限，不应允许停用")
	}
	got = h.intersectScopes(ctx, "openid email profile", []string{"openid", "email", "profile"})
	if !strings.Contains(got, "openid") {
		t.Errorf("openid 必须始终保留：%q", got)
	}
}

// TestIntersectScopesKeepsOpenIDAlways openid 是必选基础权限，任何时候都保留。
func TestIntersectScopesKeepsOpenIDAlways(t *testing.T) {
	h, _ := newTestHandler(t)
	if got := h.intersectScopes(context.Background(), "openid", nil); got != "openid" {
		t.Errorf("openid 必须始终保留，实际 %q", got)
	}
}

// TestValidatePasswordRejectsOverlongInput 回归：超长密码必须被拒绝，
// 而不是静默截断或白烧一次 bcrypt。
func TestValidatePasswordRejectsOverlongInput(t *testing.T) {
	sp := &models.SecurityPolicy{MinPasswordLength: 8}
	long := strings.Repeat("a", maxPasswordBytes+1)
	if msg := validatePassword(sp, long); msg == "" {
		t.Error("超过 bcrypt 输入上限的密码应被拒绝")
	}
	// 边界值应通过。
	if msg := validatePassword(sp, strings.Repeat("a", maxPasswordBytes)); msg != "" {
		t.Errorf("恰好 %d 字节的密码应通过，实际 %q", maxPasswordBytes, msg)
	}
}

// TestValidatePasswordCountsRunesNotBytes 回归：密码长度按字符数计，
// 而不是字节数（中文密码此前会被判为「不够长」）。
func TestValidatePasswordCountsRunesNotBytes(t *testing.T) {
	sp := &models.SecurityPolicy{MinPasswordLength: 8}
	if msg := validatePassword(sp, "OpenIdP安全密码"); msg != "" {
		t.Errorf("8 个汉字（24 字节）应满足最小长度 8，实际被拒：%q", msg)
	}
}

// TestLoginPolicyReflectsPasswordSwitch 回归：login-policy 的 password
// 必须反映安全策略开关，而不是恒为 true。
func TestLoginPolicyReflectsPasswordSwitch(t *testing.T) {
	h, router := newTestHandler(t)
	_, data := doGET(t, router, "/api/v1/login-policy")
	if v, ok := data["password"].(bool); !ok || !v {
		t.Fatalf("默认应允许密码登录，实际 %v", data["password"])
	}

	sp := h.loadSecurityPolicy()
	if _, err := h.db.NewUpdate().Model(sp).WherePK().
		Set("password_login_enabled = ?", false).Exec(context.Background()); err != nil {
		t.Fatalf("disable password login: %v", err)
	}
	h.conf.invalidate()
	_, data = doGET(t, router, "/api/v1/login-policy")
	if v, _ := data["password"].(bool); v {
		t.Error("密码登录已关闭，login-policy 仍报告可用")
	}
}

// TestOAuthProviderLogoIsSanitized 回归：登录提供商 Logo 要下发到未登录的
// 登录页，必须与其他外部地址一样校验。
func TestOAuthProviderLogoIsSanitized(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "provalpha", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(u).WherePK().Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	sessID, csrf := loginAs(t, h, u)
	_ = sessID

	// 先注册一个自定义提供商。
	p := &models.OAuthProvider{
		ProviderType: "custom-x", DisplayName: "X", Custom: true,
		AuthorizeURL: "https://x.example.com/authorize",
		TokenURL:     "https://x.example.com/token",
		UserInfoURL:  "https://x.example.com/user",
	}
	if _, err := h.db.NewInsert().Model(p).Exec(context.Background()); err != nil {
		t.Fatalf("insert provider: %v", err)
	}

	w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-providers/custom-x",
		`{"logoUrl":"javascript:alert(1)"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("非法 Logo 地址不应被接受（%d, %s）", w.Code, w.Body.String())
	}
}

// TestAdminSiteRejectsInvalidLogoURL 站点 Logo / Favicon 同样要走 URL 校验。
func TestAdminSiteRejectsInvalidLogoURL(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "sitealpha", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(u).WherePK().Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	sessID, csrf := loginAs(t, h, u)

	w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/site", `{"logoUrl":"javascript:alert(1)"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("非法 Logo 地址不应被接受（%d, %s）", w.Code, w.Body.String())
	}
	w = call(h, sessID, csrf, "PATCH", "/api/v1/admin/site", `{"faviconUrl":"data:text/html,x"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("非法 Favicon 地址不应被接受（%d, %s）", w.Code, w.Body.String())
	}
}

// TestAdminCaptchaRejectsUnknownProvider 回归：provider 取值必须校验，
// 未知值会让两类验证被静默关掉，而界面显示「已保存」。
func TestAdminCaptchaRejectsUnknownProvider(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "captchaalpha", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(u).WherePK().Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	sessID, csrf := loginAs(t, h, u)

	w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/captcha", `{"provider":"totally-unknown"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未知 provider 应返回 400，实际 %d (%s)", w.Code, w.Body.String())
	}
}

// TestAuditRetentionSettingDrivesCleanup 回归：审计保留天数要真正参与清理判定。
func TestAuditRetentionSettingDrivesCleanup(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "audituser", "Str0ngPassw0rd!")
	old := db.Now().AddDate(0, 0, -30)
	if _, err := h.db.NewInsert().Model(&models.Event{
		UserID: u.ID, Type: "login.success", Summary: "old", CreatedAt: old,
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	// 保留 90 天：30 天前的事件应保留。
	if err := db.CleanupExpired(context.Background(), h.db, 90); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n := countEvents(t, h); n != 1 {
		t.Fatalf("保留期 90 天时事件不应被删，剩余 %d", n)
	}
	// 保留 7 天：30 天前的事件应被清理。
	if err := db.CleanupExpired(context.Background(), h.db, 7); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n := countEvents(t, h); n != 0 {
		t.Errorf("保留期 7 天时 30 天前的事件应被清理，剩余 %d", n)
	}
	// 保留 0（永久）：不清理任何事件。
	if _, err := h.db.NewInsert().Model(&models.Event{
		UserID: u.ID, Type: "login.success", Summary: "ancient", CreatedAt: db.Now().AddDate(0, 0, -365),
	}).Exec(context.Background()); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if err := db.CleanupExpired(context.Background(), h.db, 0); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n := countEvents(t, h); n != 1 {
		t.Errorf("保留期为 0 表示永久保留，事件不应被清理，剩余 %d", n)
	}
}

// TestLoginEventsOnlySkipsNonSecurityEvents 回归：开启「仅记录登录/安全事件」后，
// 非安全类事件不应落库。
func TestLoginEventsOnlySkipsNonSecurityEvents(t *testing.T) {
	h, _ := newTestHandler(t)
	a := h.loadAuditSetting()
	if _, err := h.db.NewUpdate().Model(a).WherePK().
		Set("login_events_only = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("set login_events_only: %v", err)
	}
	h.conf.invalidate()

	u := createTestUser(t, h.db, "loginctl", "Str0ngPassw0rd!")
	h.logEvent(nil, u.ID, &models.Event{Type: "admin.site_updated", Summary: "非安全类事件"})
	h.logEvent(nil, u.ID, &models.Event{Type: "login.success", Summary: "安全类事件"})

	var events []models.Event
	if err := h.db.NewSelect().Model(&events).Where("user_id = ?", u.ID).Scan(context.Background()); err != nil {
		t.Fatalf("select events: %v", err)
	}
	for _, e := range events {
		if !isSecurityEvent(e.Type) {
			t.Errorf("开启「仅记录登录/安全事件」后仍写入了非安全事件 %q", e.Type)
		}
	}
	if len(events) != 1 {
		t.Errorf("期望只保留 1 条安全事件，实际 %d 条", len(events))
	}
}

// ---- helpers ----

func refreshToken(t *testing.T, h *Handler, clientID, secret, refresh string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
		"client_secret": {secret},
	}
	r := httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, r)
	return w
}

func parseRefresh(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse refresh response: %v", err)
	}
	v, _ := out["refresh_token"].(string)
	return v
}

func countEvents(t *testing.T, h *Handler) int {
	t.Helper()
	n, err := h.db.NewSelect().Model((*models.Event)(nil)).Count(context.Background())
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

// smsConfigForTest 构造一份最小可用的短信配置（不实际发信）。
func smsConfigForTest() sms.Config {
	return sms.Config{Enabled: true, Provider: "custom", CodeTTL: 5, Cooldown: 60}
}

var _ = auth.NewID

// ---- 并发安全回归：管理后台保存配置与请求路径并发读写 ----

// TestConcurrentSettingsApplyAndRead 回归：管理员保存配置时必须与并发请求
// 安全共存。此前 captcha / turnstile / sms / store 都是普通字段，
// 「保存」会原地改写字段，而登录请求正在读同一字段，构成数据竞争
// （-race 可复现，极端情况下读到撕裂的配置）。
func TestConcurrentSettingsApplyAndRead(t *testing.T) {
	h, _ := newTestHandler(t)
	cfg := smsConfigForTest()
	h.sms.Store(&cfg)

	done := make(chan struct{})
	var wg sync.WaitGroup

	// 写侧：反复保存各类配置（等价于管理员连续点保存）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			select {
			case <-done:
				return
			default:
			}
			csrf := &models.CaptchaSetting{
				ID: 1, Provider: "geetest",
				GeetestCaptchaID: "id-x", UpdatedAt: db.Now(),
			}
			h.applyCaptchaSetting(csrf)
			h.applySmsSetting(&models.SmsSetting{ID: 1, Enabled: true, Provider: "custom"})
			h.setStorageProvider(h.providerFrom(&models.StorageSetting{Backend: "local"}))
		}
	}()

	// 读侧：并发读取这些配置（等价于并发请求）。
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = h.captchaCfg()
				_ = h.turnstileCfg()
				_ = h.smsCfg()
				_ = h.captchaConfigPayload()
				_ = h.smsUsable()
				_ = h.storageProvider()
			}
		}()
	}
	// 请求路径同样跑一遍（真实调用栈）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/login-policy", nil)
			rec := httptest.NewRecorder()
			h.Router().ServeHTTP(rec, req)
		}
	}()

	wg.Wait()
	close(done)
}

// TestConcurrentResolveProviderIsRaceFree 回归：内置提供商的定义对象在包级注册表里
// 共享，解析时必须返回拷贝。原地注入 HTTPClient 会与并发的
// BuildAuthorizeURL / ExchangeCode 读取构成数据竞争。
func TestConcurrentResolveProviderIsRaceFree(t *testing.T) {
	h, _ := newTestHandler(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				p, ok := h.resolveProvider("github")
				if !ok {
					t.Error("github 提供商应存在")
					return
				}
				// 读取被写过的字段，触发竞争检测。
				if p.Type == "" {
					t.Error("provider type 不应为空")
					return
				}
			}
		}()
	}
	// 写侧：在并发的读之间反复解析（每次都新建拷贝）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			h.resolveProvider("github")
		}
	}()
	wg.Wait()
}

// TestOAuthClientLogoEditableWithSitePath 回归：应用的 Logo 允许填站内路径
// （创建接口就这样校验），编辑接口却只认 http/https —— 后台打开一个
// 用站内路径的应用、原样保存就会撞 400，等于「一旦编辑就存不回去」。
func TestOAuthClientLogoEditableWithSitePath(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "clientlogo", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(u).WherePK().Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	sessID, csrf := loginAs(t, h, u)

	w := call(h, sessID, csrf, "POST", "/api/v1/admin/oauth-clients",
		`{"name":"站内图标应用","logoUrl":"/images/logo.svg","homepageUrl":"https://app.example.com","redirectUris":["https://app.example.com/cb"],"scopes":["openid"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("创建带站内 Logo 的应用应成功，实际 %d (%s)", w.Code, w.Body.String())
	}
	var created struct {
		Data struct {
			Client struct {
				ID string `json:"id"`
			} `json:"client"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.Data.Client.ID == "" {
		t.Fatalf("解析创建结果失败：%v (%s)", err, w.Body.String())
	}

	// 编辑时前端会把原值原样回填提交，必须同样被接受。
	w = call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-clients/"+created.Data.Client.ID,
		`{"logoUrl":"/images/logo.svg"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("站内 Logo 原样保存应成功，实际 %d (%s)", w.Code, w.Body.String())
	}
	// 但危险协议仍必须拒绝。
	w = call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-clients/"+created.Data.Client.ID,
		`{"logoUrl":"javascript:alert(1)"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("危险协议仍应被拒绝（%d, %s）", w.Code, w.Body.String())
	}
}

// TestOAuthLogoReadPathsAreSanitized 回归：Logo 会在多处渲染进 <img src>，
// 只校验写入不够 —— 历史数据或直接改库留下的取值必须在出库时再过滤一次。
func TestOAuthLogoReadPathsAreSanitized(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "logoread", "Str0ngPassw0rd!")
	if _, err := h.db.NewUpdate().Model(u).WherePK().Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	ctx := context.Background()
	bad := "javascript:alert(document.cookie)"

	// 直接改库写入危险取值，模拟历史数据。
	cli := &models.OAuthClient{ID: auth.NewID(), Name: "毒 Logo 应用", LogoURL: bad, CreatedAt: db.Now()}
	if _, err := h.db.NewInsert().Model(cli).Exec(ctx); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	p := &models.OAuthProvider{
		ID: auth.NewID(), Name: "毒 Logo 提供商", DisplayName: "X", ProviderType: "poison-x",
		LogoURL: bad, Enabled: true, AuthorizeURL: "https://x.example.com/authorize",
		TokenURL: "https://x.example.com/token", UserInfoURL: "https://x.example.com/user",
		CreatedAt: db.Now(),
	}
	if _, err := h.db.NewInsert().Model(p).Exec(ctx); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := h.db.NewInsert().Model(&models.Grant{
		ID: auth.NewID(), UserID: u.ID, ClientID: cli.ID, Scopes: []string{"openid"}, CreatedAt: db.Now(),
	}).Exec(ctx); err != nil {
		t.Fatalf("insert grant: %v", err)
	}

	sessID, csrf := loginAs(t, h, u)
	for _, tc := range []struct{ name, path string }{
		{"公开登录页提供商列表", "/api/v1/login/providers"},
		{"后台应用列表", "/api/v1/admin/oauth-clients"},
		{"后台提供商列表", "/api/v1/admin/oauth-providers"},
		{"后台授权列表", "/api/v1/admin/oauth-grants"},
	} {
		w := call(h, sessID, csrf, "GET", tc.path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d (%s)", tc.name, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "javascript:") {
			t.Errorf("%s 仍下发了危险 Logo：%s", tc.name, w.Body.String())
		}
	}
}
