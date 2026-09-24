package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/h1s97x/openidp/api/internal/mail"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oauth2"
)

// ---------------------------------------------------------------------------
// 登录提供商端点配置 + 通知渠道功能校验的回归测试。
//
// 每个用例命名直接描述「原本会怎样」，避免日后被当成可重复用例删掉。
// ---------------------------------------------------------------------------

// promoteToAdmin 把用户提升为管理员（这些端点只有管理员可用）。
func promoteToAdmin(t *testing.T, h *Handler, u *models.User) {
	t.Helper()
	if _, err := h.db.NewUpdate().Model(u).WherePK().
		Set("is_admin = ?", true).Exec(context.Background()); err != nil {
		t.Fatalf("promote admin: %v", err)
	}
}

// seedBuiltinProvider 写入一条内置提供商的库记录（模拟初始化完成后的状态），
// 端点取自内置注册表——与服务启动时 seed 的行为一致。
func seedBuiltinProvider(t *testing.T, h *Handler, providerType string) *models.OAuthProvider {
	t.Helper()
	def, ok := oauth2.Get(providerType)
	if !ok {
		t.Fatalf("内置注册表缺少 %q", providerType)
	}
	p := &models.OAuthProvider{
		ID:           "prov_" + providerType,
		Name:         "Oauth-" + providerType,
		DisplayName:  def.Name,
		ProviderType: providerType,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Enabled:      true,
		AuthorizeURL: def.AuthorizeURL,
		TokenURL:     def.TokenURL,
		UserInfoURL:  def.UserInfoURL,
		OpenIDURL:    def.OpenIDURL,
		Scopes:       def.Scopes,
		DocsURL:      def.DocsURL,
	}
	if _, err := h.db.NewInsert().Model(p).Exec(context.Background()); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	return p
}

// TestBuiltinProviderEndpointsAreReturnedToAdmin 内置提供商的端点必须下发到后台，
// 且带上内置默认值——管理员才能在界面上看到「当前值」与「默认值」的差异。
//
// 此前内置端点在接口里是**用注册表覆盖**返回的：库里那几列即便被改过也不生效，
// 管理员看到的永远是代码里的硬编码值，也没有任何修改入口。
func TestBuiltinProviderEndpointsAreReturnedToAdmin(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "provideradmin", "Str0ngPassw0rd!")
	promoteToAdmin(t, h, u)
	p := seedBuiltinProvider(t, h, "github")
	// 模拟管理员改过授权地址。
	if _, err := h.db.NewUpdate().Model(p).WherePK().
		Set("authorize_url = ?", "https://idp.internal.example.com/oauth/authorize").
		Exec(context.Background()); err != nil {
		t.Fatalf("update endpoint: %v", err)
	}

	sessID, csrf := loginAs(t, h, u)
	w := call(h, sessID, csrf, "GET", "/api/v1/admin/oauth-providers", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET providers = %d (%s)", w.Code, w.Body.String())
	}
	var envelope struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(envelope.Data) != 1 {
		t.Fatalf("期望 1 个提供商，实际 %d 个", len(envelope.Data))
	}
	item := envelope.Data[0]

	// 当前取值必须是库里的（改动后立即生效），不能被注册表默认值覆盖。
	if got := item["authorizeUrl"]; got != "https://idp.internal.example.com/oauth/authorize" {
		t.Errorf("authorizeUrl 应为数据库取值，实际 %v", got)
	}
	if item["builtin"] != true {
		t.Errorf("内置提供商应带 builtin=true，实际 %v", item["builtin"])
	}
	defs, ok := item["defaultEndpoints"].(map[string]any)
	if !ok {
		t.Fatalf("内置提供商应下发 defaultEndpoints，实际 %v", item["defaultEndpoints"])
	}
	def, _ := oauth2.Get("github")
	if defs["authorizeUrl"] != def.AuthorizeURL {
		t.Errorf("defaultEndpoints.authorizeUrl = %v, want %v", defs["authorizeUrl"], def.AuthorizeURL)
	}
	if defs["tokenUrl"] != def.TokenURL {
		t.Errorf("defaultEndpoints.tokenUrl = %v, want %v", defs["tokenUrl"], def.TokenURL)
	}
}

// TestBuiltinProviderEndpointOverrideTakesEffect 修改内置提供商的端点后，
// 运行期解析必须使用新端点（此前注册表硬编码值会盖掉库里的配置）。
func TestBuiltinProviderEndpointOverrideTakesEffect(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "overrideadmin", "Str0ngPassw0rd!")
	promoteToAdmin(t, h, u)
	seedBuiltinProvider(t, h, "github")

	sessID, csrf := loginAs(t, h, u)
	w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-providers/prov_github",
		`{"authorizeUrl":"https://idp.internal.example.com/oauth/authorize","tokenUrl":"https://idp.internal.example.com/oauth/token"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PATCH = %d (%s)", w.Code, w.Body.String())
	}

	pv, ok := h.resolveProvider("github")
	if !ok {
		t.Fatal("github 提供商应可解析")
	}
	if pv.AuthorizeURL != "https://idp.internal.example.com/oauth/authorize" {
		t.Errorf("授权地址应为管理员配置值，实际 %q", pv.AuthorizeURL)
	}
	if pv.TokenURL != "https://idp.internal.example.com/oauth/token" {
		t.Errorf("令牌地址应为管理员配置值，实际 %q", pv.TokenURL)
	}
	// 未改动的端点仍用内置默认值。
	if pv.UserInfoURL != "https://api.github.com/user" {
		t.Errorf("未改动的用户信息地址应为内置默认值，实际 %q", pv.UserInfoURL)
	}
	// 解析函数必须仍来自内置定义（端点改写不影响 profile 解析）。
	if pv.ParseUserInfo == nil {
		t.Error("内置提供商必须保留内置的用户信息解析函数")
	}
}

// TestBuiltinProviderEndpointBlankFallsBackToDefault 清空端点 = 恢复内置默认，
// 而不是把提供商改成不可用。
func TestBuiltinProviderEndpointBlankFallsBackToDefault(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "blankadmin", "Str0ngPassw0rd!")
	promoteToAdmin(t, h, u)
	p := seedBuiltinProvider(t, h, "gitee")
	if _, err := h.db.NewUpdate().Model(p).WherePK().
		Set("authorize_url = ?", "https://mirror.example.com/oauth/authorize").
		Exec(context.Background()); err != nil {
		t.Fatalf("update endpoint: %v", err)
	}

	sessID, csrf := loginAs(t, h, u)
	// 置空授权地址：保存后应回落到内置默认，而不是 400。
	w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-providers/prov_gitee",
		`{"authorizeUrl":""}`)
	if w.Code != http.StatusOK {
		t.Fatalf("清空端点应被接受（回落到内置默认），实际 %d (%s)", w.Code, w.Body.String())
	}
	pv, ok := h.resolveProvider("gitee")
	if !ok {
		t.Fatal("gitee 提供商应可解析")
	}
	def, _ := oauth2.Get("gitee")
	if pv.AuthorizeURL != def.AuthorizeURL {
		t.Errorf("清空后应使用内置默认授权地址 %q，实际 %q", def.AuthorizeURL, pv.AuthorizeURL)
	}
}

// TestProviderEndpointRejectsNonHTTP 端点会拼进浏览器跳转与服务端出站请求，
// 必须只接受 http/https 绝对地址（javascript: / data: / file: 一律拒绝）。
func TestProviderEndpointRejectsNonHTTP(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "endpointadmin", "Str0ngPassw0rd!")
	promoteToAdmin(t, h, u)
	seedBuiltinProvider(t, h, "github")
	sessID, csrf := loginAs(t, h, u)

	for _, bad := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"//evil.example.com/authorize",
		"not-a-url",
	} {
		body := `{"authorizeUrl":` + strconv_Quote(bad) + `}`
		w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-providers/prov_github", body)
		if w.Code == http.StatusOK {
			t.Errorf("非法授权地址 %q 不应被接受（%d, %s）", bad, w.Code, w.Body.String())
		}
	}
}

// TestProviderScopesRejectWhitespace 权限范围会以空格拼进 scope 参数，
// 含空白的条目必须被拒绝（否则一个 scope 会被拆成两个）。
func TestProviderScopesRejectWhitespace(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "scopeadmin2", "Str0ngPassw0rd!")
	promoteToAdmin(t, h, u)
	seedBuiltinProvider(t, h, "github")
	sessID, csrf := loginAs(t, h, u)

	w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-providers/prov_github",
		`{"scopes":["read:user","bad scope"]}`)
	if w.Code == http.StatusOK {
		t.Fatalf("含空白的 scope 不应被接受（%d, %s）", w.Code, w.Body.String())
	}
	// 合法取值应通过并去重。
	w = call(h, sessID, csrf, "PATCH", "/api/v1/admin/oauth-providers/prov_github",
		`{"scopes":["read:user","user:email","read:user"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("合法 scope 应被接受，实际 %d (%s)", w.Code, w.Body.String())
	}
	pv, _ := h.resolveProvider("github")
	if len(pv.Scopes) != 2 {
		t.Errorf("重复 scope 应被去重，实际 %v", pv.Scopes)
	}
}

// TestNotificationEmailCannotBeEnabledWithoutSMTP 未配置 SMTP 时，
// 开启邮件通知必须被服务端拒绝——前端禁用只是第一道提示，不能作为唯一防线。
func TestNotificationEmailCannotBeEnabledWithoutSMTP(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "notifuser", "Str0ngPassw0rd!")
	sessID, csrf := loginAs(t, h, u)

	if h.mailer.Enabled() {
		t.Fatal("测试前提：默认未配置 SMTP")
	}
	w := call(h, sessID, csrf, "PATCH", "/api/v1/me/notification-preferences",
		`{"newDeviceInApp":true,"newDeviceEmail":true,"privacyEmailReminder":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未配置 SMTP 时开启邮件通知应返回 400，实际 %d (%s)", w.Code, w.Body.String())
	}
	// 落库的值必须没变（不能出现「返回 400 但已写库」）。
	np := h.loadNotificationPrefs(u.ID)
	if np.NewDeviceEmail {
		t.Error("请求被拒后，邮件通知开关不应被写入")
	}
	// 未配置 SMTP 时新建的偏好行，隐私邮箱提醒默认即为关闭，
	// 不能带着一个「已开启但收不到」的默认值进入设置页。
	if np.PrivacyEmailReminder {
		t.Error("未配置 SMTP 时，隐私邮箱提醒的默认值应为关闭")
	}
}

// TestNotificationInAppStillSavesWithoutSMTP 未配置 SMTP 时，站内通知的保存
// 不能被连带拒绝——前端提交的是整份偏好快照，误伤会让所有偏好都改不动。
func TestNotificationInAppStillSavesWithoutSMTP(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "inappuser", "Str0ngPassw0rd!")
	sessID, csrf := loginAs(t, h, u)

	w := call(h, sessID, csrf, "PATCH", "/api/v1/me/notification-preferences",
		`{"newDeviceInApp":false,"newDeviceEmail":false,"privacyEmailReminder":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("关闭邮件通道的请求应被接受，实际 %d (%s)", w.Code, w.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data, _ := envelope["data"].(map[string]any)
	if v, _ := data["newDeviceInApp"].(bool); v {
		t.Error("站内通知开关应已关闭")
	}
	if v, _ := data["emailAvailable"].(bool); v {
		t.Error("未配置 SMTP 时 emailAvailable 应为 false")
	}
}

// TestNotificationEmailCanBeEnabledWithSMTP 配置了 SMTP 后，开启邮件通知应被允许，
// 且必须真的写库（避免「校验把正常路径也拦了」）。
func TestNotificationEmailCanBeEnabledWithSMTP(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "smtpuser", "Str0ngPassw0rd!")
	h.mailer.Reconfigure(mail.Config{Enabled: true, Host: "smtp.example.com", Port: 465, From: "noreply@example.com"})
	if !h.mailer.Enabled() {
		t.Fatal("测试前提：SMTP 应已就绪")
	}
	sessID, csrf := loginAs(t, h, u)

	w := call(h, sessID, csrf, "PATCH", "/api/v1/me/notification-preferences",
		`{"newDeviceEmail":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("已配置 SMTP 时开启邮件通知应成功，实际 %d (%s)", w.Code, w.Body.String())
	}
	if !h.loadNotificationPrefs(u.ID).NewDeviceEmail {
		t.Error("邮件通知开关应已写入数据库")
	}
}

// TestNotificationPrefsMaskEmailWhenSMTPUnavailable 未配置 SMTP 时，
// 即便库里存着「已开启」，下发给前端的也必须是关闭——否则界面显示「已开启」
// 而实际发信链路被 h.mailer.Enabled() 拦着，用户永远等不到邮件。
func TestNotificationPrefsMaskEmailWhenSMTPUnavailable(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "maskuser", "Str0ngPassw0rd!")
	// 直接写库：模拟「管理员停用 SMTP 之前用户就开着邮件通知」的历史数据。
	if _, err := h.db.NewInsert().Model(&models.NotificationPreference{
		UserID: u.ID, NewDeviceInApp: true, NewDeviceEmail: true, PrivacyEmailReminder: true,
	}).Exec(context.Background()); err != nil {
		t.Fatalf("seed prefs: %v", err)
	}
	if h.mailer.Enabled() {
		t.Fatal("测试前提：未配置 SMTP")
	}
	sessID, _ := loginAs(t, h, u)
	w := call(h, sessID, "", "GET", "/api/v1/me/notification-preferences", "")
	var envelope map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data, _ := envelope["data"].(map[string]any)
	if v, _ := data["newDeviceEmail"].(bool); v {
		t.Error("未配置 SMTP 时 newDeviceEmail 下发的应为关闭（生效值）")
	}
	if v, _ := data["privacyEmailReminder"].(bool); v {
		t.Error("未配置 SMTP 时 privacyEmailReminder 下发的应为关闭（生效值）")
	}
	if v, _ := data["emailAvailable"].(bool); v {
		t.Error("emailAvailable 应为 false")
	}
	// 站内通知不受影响。
	if v, _ := data["newDeviceInApp"].(bool); !v {
		t.Error("站内通知不应被邮件通道的可用性影响")
	}
}

// TestNotificationPrefsGetReportsEmailAvailability GET 必须下发邮件通道可用性，
// 前端据此把不可用的开关展示为禁用并说明原因。
func TestNotificationPrefsGetReportsEmailAvailability(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "availuser", "Str0ngPassw0rd!")
	sessID, _ := loginAs(t, h, u)

	w := call(h, sessID, "", "GET", "/api/v1/me/notification-preferences", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d (%s)", w.Code, w.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data, _ := envelope["data"].(map[string]any)
	if v, ok := data["emailAvailable"].(bool); !ok || v {
		t.Errorf("未配置 SMTP 时 emailAvailable 应为 false，实际 %v", data["emailAvailable"])
	}

	h.mailer.Reconfigure(mail.Config{Enabled: true, Host: "smtp.example.com", Port: 465})
	w = call(h, sessID, "", "GET", "/api/v1/me/notification-preferences", "")
	var envelope2 map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &envelope2)
	data2, _ := envelope2["data"].(map[string]any)
	if v, _ := data2["emailAvailable"].(bool); !v {
		t.Errorf("配置 SMTP 后 emailAvailable 应为 true，实际 %v", data2["emailAvailable"])
	}
}

// TestAdminMailCannotEnableWithoutHost 未填写 SMTP 主机时不允许开启邮件服务，
// 否则库里是「已启用」而实际发信仍被判定为不可用。
func TestAdminMailCannotEnableWithoutHost(t *testing.T) {
	h, sessID, csrf := setupAdminSession(t)
	w := call(h, sessID, csrf, "PATCH", "/api/v1/admin/mail", `{"enabled":true,"host":""}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未填主机时开启邮件服务应返回 400，实际 %d (%s)", w.Code, w.Body.String())
	}
	// 填了主机即可开启。
	w = call(h, sessID, csrf, "PATCH", "/api/v1/admin/mail",
		`{"enabled":true,"host":"smtp.example.com","port":465,"fromEmail":"noreply@example.com"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("填写主机后应可开启，实际 %d (%s)", w.Code, w.Body.String())
	}
	if !h.mailer.Enabled() {
		t.Error("保存后邮件服务应立即可用")
	}
}

// TestResolveProviderFallsBackToBuiltinWhenRowMissing 库里还没有该提供商的记录时
// （尚未初始化），解析必须回落到内置定义而不是直接失败。
func TestResolveProviderFallsBackToBuiltinWhenRowMissing(t *testing.T) {
	h, _ := newTestHandler(t)
	pv, ok := h.resolveProvider("github")
	if !ok {
		t.Fatal("库中无记录时应回落到内置定义")
	}
	def, _ := oauth2.Get("github")
	if pv.AuthorizeURL != def.AuthorizeURL || pv.TokenURL != def.TokenURL {
		t.Errorf("回落的端点应与内置定义一致，实际 %q / %q", pv.AuthorizeURL, pv.TokenURL)
	}
	// 未知类型必须失败。
	if _, ok := h.resolveProvider("no-such-provider"); ok {
		t.Error("未知提供商不应解析成功")
	}
}

// TestProviderEndpointSanitizer 端点清洗的边界：空串合法（未覆盖）、
// 超长与含控制字符非法、http/https 合法。
func TestProviderEndpointSanitizer(t *testing.T) {
	for _, tc := range []struct {
		in   string
		ok   bool
		want string
	}{
		{"", true, ""},
		{"   ", true, ""},
		{"  https://idp.example.com/oauth/authorize  ", true, "https://idp.example.com/oauth/authorize"},
		{"http://idp.internal:8080/oauth", true, "http://idp.internal:8080/oauth"},
		{"javascript:alert(1)", false, ""},
		{"ftp://idp.example.com/x", false, ""},
		{"https://idp.example.com/a\nb", false, ""},
		{"https://" + strings.Repeat("a", 600) + ".com", false, ""},
	} {
		got, ok := sanitizeProviderEndpoint(tc.in)
		if ok != tc.ok {
			t.Errorf("sanitizeProviderEndpoint(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("sanitizeProviderEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// strconv_Quote 用 JSON 规则转义字符串（避免测试里手写转义出错）。
func strconv_Quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
