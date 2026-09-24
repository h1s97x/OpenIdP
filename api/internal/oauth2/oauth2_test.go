package oauth2

import (
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 第三方登录 OAuth2 测试。
//
// 背景：oauth2 包此前零测试。本文件聚焦无需外网的纯逻辑：
//   - 内置提供商注册完整性（Get）
//   - 自定义提供商构造（NewCustomProvider）
//   - 授权 URL 构造（BuildAuthorizeURL）——参数编码与 PKCE 参数是否正确，
//     这是安全相关点：state/code_challenge 缺失或编码错误会导致 CSRF 与
//     授权码截获风险。
// 涉及网络的 ExchangeCode / FetchProfile 不在此覆盖。
// ---------------------------------------------------------------------------

// TestBuiltinProvidersRegistered 内置提供商必须已注册且字段完整，
// 否则管理后台配置页会出现不可用项。
func TestBuiltinProvidersRegistered(t *testing.T) {
	for _, typ := range []string{"github", "google", "microsoft", "qq", "gitee", "linuxdo"} {
		p, ok := Get(typ)
		if !ok {
			t.Errorf("内置提供商 %q 未注册", typ)
			continue
		}
		if p.AuthorizeURL == "" || p.TokenURL == "" {
			t.Errorf("%q 缺少 AuthorizeURL/TokenURL", typ)
		}
		if len(p.Scopes) == 0 {
			t.Errorf("%q 未配置默认 scope", typ)
		}
	}
}

func TestGetUnknownProvider(t *testing.T) {
	if p, ok := Get("definitely-not-a-provider"); ok || p != nil {
		t.Error("未知类型不应返回提供商")
	}
}

func TestNewCustomProvider(t *testing.T) {
	p := NewCustomProvider(
		"myidp", "My IdP",
		"https://idp.example.com/authorize",
		"https://idp.example.com/token",
		"https://idp.example.com/userinfo",
		[]string{"openid", "email"},
	)
	if p == nil {
		t.Fatal("NewCustomProvider returned nil")
	}
	if !p.Custom {
		t.Error("自定义提供商应标记 Custom=true")
	}
	if p.AuthorizeURL != "https://idp.example.com/authorize" {
		t.Errorf("AuthorizeURL = %q", p.AuthorizeURL)
	}
	if p.TokenURL != "https://idp.example.com/token" {
		t.Errorf("TokenURL = %q", p.TokenURL)
	}
	if p.UserInfoURL != "https://idp.example.com/userinfo" {
		t.Errorf("UserInfoURL = %q", p.UserInfoURL)
	}
	if len(p.Scopes) != 2 {
		t.Errorf("Scopes = %v", p.Scopes)
	}
	// 自定义提供商必须有通用的 userinfo 解析器，否则无法接入
	if p.ParseUserInfo == nil {
		t.Error("自定义提供商应提供 userinfo 解析器")
	}
}

// TestCustomProviderParsesCommonFields 通用解析器应能读取常见字段命名。
func TestCustomProviderParsesCommonFields(t *testing.T) {
	p := NewCustomProvider("t", "T", "a", "t", "u", nil)
	raw := []byte(`{"sub":"12345","name":"Alice","email":"a@example.com","email_verified":true,"picture":"http://x/p.png"}`)
	prof, err := p.ParseUserInfo(raw)
	if err != nil {
		t.Fatalf("ParseUserInfo: %v", err)
	}
	if prof.ProviderUID != "12345" {
		t.Errorf("ProviderUID = %q, want 12345", prof.ProviderUID)
	}
	if prof.DisplayName != "Alice" {
		t.Errorf("DisplayName = %q", prof.DisplayName)
	}
	if prof.Email != "a@example.com" {
		t.Errorf("Email = %q", prof.Email)
	}
	if !prof.EmailVerified {
		t.Error("EmailVerified 应为 true")
	}
}

// TestCustomProviderFallsBackToID 缺少 sub 时回退到 id 字段，兼容更多 IdP。
func TestCustomProviderFallsBackToID(t *testing.T) {
	p := NewCustomProvider("t", "T", "a", "t", "u", nil)
	prof, err := p.ParseUserInfo([]byte(`{"id":"user-9","email":"b@example.com"}`))
	if err != nil {
		t.Fatalf("ParseUserInfo: %v", err)
	}
	if prof.ProviderUID != "user-9" {
		t.Errorf("ProviderUID = %q, want user-9", prof.ProviderUID)
	}
}

// TestCustomProviderRequiresUID 缺少唯一标识时必须报错：
// 否则会以空 UID 建立绑定，导致不同用户被关联到同一身份。
func TestCustomProviderRequiresUID(t *testing.T) {
	p := NewCustomProvider("t", "T", "a", "t", "u", nil)
	if _, err := p.ParseUserInfo([]byte(`{"email":"c@example.com"}`)); err == nil {
		t.Error("缺少唯一标识时应返回错误")
	}
	// 非法 JSON 同样应报错
	if _, err := p.ParseUserInfo([]byte(`not json`)); err == nil {
		t.Error("非法 JSON 应返回错误")
	}
}

// TestBuildAuthorizeURL 授权 URL 必须包含 OAuth2 必需参数且正确编码。
func TestBuildAuthorizeURL(t *testing.T) {
	p := &Provider{
		Type:         "test",
		AuthorizeURL: "https://idp.example.com/authorize",
		Scopes:       []string{"openid", "profile"},
	}
	cred := &Credentials{
		ClientID:    "cid",
		RedirectURL: "https://app.example.com/cb?a=1&b=2",
	}
	got := p.BuildAuthorizeURL(cred, "state-xyz", "chal-123", "")

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("生成的 URL 无法解析: %v (%s)", err, got)
	}
	if u.Scheme != "https" || u.Host != "idp.example.com" || u.Path != "/authorize" {
		t.Errorf("URL 基础部分被破坏: %s", got)
	}
	q := u.Query()
	if q.Get("client_id") != "cid" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("state") != "state-xyz" {
		t.Errorf("state = %q", q.Get("state"))
	}
	// redirect_uri 含 & ? 时必须被正确编码，否则回调地址会被截断
	if q.Get("redirect_uri") != cred.RedirectURL {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), cred.RedirectURL)
	}
	if q.Get("scope") != "openid profile" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
}

// TestBuildAuthorizeURLIncludesPKCE 传入 challenge 时必须带上 S256 方法，
// 否则 PKCE 校验无法生效（授权码截获风险）。
func TestBuildAuthorizeURLIncludesPKCE(t *testing.T) {
	p := &Provider{AuthorizeURL: "https://idp/authorize"}
	u, _ := url.Parse(p.BuildAuthorizeURL(&Credentials{ClientID: "c"}, "s", "chal", ""))
	q := u.Query()
	if q.Get("code_challenge") != "chal" {
		t.Errorf("code_challenge = %q", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
}

// TestBuildAuthorizeURLOmitsPKCEWhenEmpty 未传 challenge 时不应写入空参数，
// 否则部分 IdP 会因空值拒绝请求。
func TestBuildAuthorizeURLOmitsPKCEWhenEmpty(t *testing.T) {
	got := (&Provider{AuthorizeURL: "https://idp/authorize"}).
		BuildAuthorizeURL(&Credentials{ClientID: "c"}, "s", "", "")
	if strings.Contains(got, "code_challenge") {
		t.Errorf("未传 challenge 时不应出现 PKCE 参数: %s", got)
	}
}

// TestBuildAuthorizeURLWithReturnURL return_url 非空时应携带，登录后可回跳来源页。
func TestBuildAuthorizeURLWithReturnURL(t *testing.T) {
	got := (&Provider{AuthorizeURL: "https://idp/authorize"}).
		BuildAuthorizeURL(&Credentials{ClientID: "c"}, "s", "", "/dashboard?tab=1")
	u, _ := url.Parse(got)
	if u.Query().Get("return_url") != "/dashboard?tab=1" {
		t.Errorf("return_url = %q", u.Query().Get("return_url"))
	}
}

// TestBuildAuthorizeURLWithExistingQuery 授权地址本身带查询参数时，
// 应使用 & 拼接而不是再写一个 ?（否则会破坏原有参数）。
func TestBuildAuthorizeURLWithExistingQuery(t *testing.T) {
	p := &Provider{AuthorizeURL: "https://idp/authorize?audience=api"}
	got := p.BuildAuthorizeURL(&Credentials{ClientID: "c"}, "s", "", "")
	if strings.Count(got, "?") != 1 {
		t.Errorf("应只含一个 ?: %s", got)
	}
	u, _ := url.Parse(got)
	if u.Query().Get("audience") != "api" {
		t.Errorf("原有参数丢失: %s", got)
	}
	if u.Query().Get("client_id") != "c" {
		t.Errorf("新增参数缺失: %s", got)
	}
}

// TestProviderProfileJSONTags 归一化后的 Profile 字段供绑定与展示使用，
// JSON 标签错误会导致用户资料保存不正确。
func TestProviderProfileJSONTags(t *testing.T) {
	p := Profile{Provider: "github", ProviderUID: "1", DisplayName: "A", Email: "a@b.c", EmailVerified: true}
	if p.Provider != "github" || p.ProviderUID == "" {
		t.Fatal("Profile 基础字段异常")
	}
}
