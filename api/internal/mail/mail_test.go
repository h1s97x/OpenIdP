package mail

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 邮件模块测试。
//
// 背景：mail 包此前零测试。它包含两个容易被忽略但很关键的纯函数：
//   - sanitizeHeaderValue：防止邮件头注入（CRLF 注入可伪造收件人/主题）
//   - renderTemplate：验证码/验证链接邮件的正文渲染
// 两者都不依赖 SMTP，适合单测覆盖。
// ---------------------------------------------------------------------------

func TestNewSenderDisabledByDefault(t *testing.T) {
	s := New(Config{})
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.Enabled() {
		t.Error("未配置 Host 时不应视为启用")
	}
}

// TestEnabledRequiresHost 主机是启用的必要条件。
// 注意：New 会在 Enabled 未显式设置时按 Host 推导（见 New 注释），
// 因此"只设 Host"同样视为启用，这是既有设计。
func TestEnabledRequiresHost(t *testing.T) {
	// 只开开关没主机 → 不启用
	if (New(Config{Enabled: true})).Enabled() {
		t.Error("缺 Host 时不应启用")
	}
	// 两者齐备 → 启用
	if !(New(Config{Enabled: true, Host: "smtp.example.com"})).Enabled() {
		t.Error("开关与 Host 都具备时应启用")
	}
	// 只设 Host（New 推导出 Enabled）→ 也应启用
	if !(New(Config{Host: "smtp.example.com"})).Enabled() {
		t.Error("New 应按 Host 推导出 Enabled")
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	s := New(Config{})
	// From 缺省应有兜底，避免出现空发件人被 SMTP 服务器拒绝
	if s.From() == "" {
		t.Error("From 应有默认值")
	}
	// SiteName 缺省回退到品牌名
	if s.FromName() == "" {
		t.Error("FromName 应有默认值")
	}
}

func TestReconfigureSwapsConfig(t *testing.T) {
	s := New(Config{})
	if s.Enabled() {
		t.Fatal("前置条件：初始应未启用")
	}
	s.Reconfigure(Config{Enabled: true, Host: "smtp.example.com", Port: 587, From: "a@b.com"})
	if !s.Enabled() {
		t.Error("Reconfigure 后应启用")
	}
	if s.Host() != "smtp.example.com" {
		t.Errorf("Host = %q", s.Host())
	}
	if s.From() != "a@b.com" {
		t.Errorf("From = %q", s.From())
	}
}

func TestFromNameFallsBackToSiteName(t *testing.T) {
	// FromName 为空时回退到 SiteName
	s := New(Config{From: "noreply@example.com", SiteName: "OpenIdP"})
	if s.FromName() != "OpenIdP" {
		t.Errorf("未设 FromName 时应回退到 SiteName，实际 %q", s.FromName())
	}
	s.Reconfigure(Config{From: "noreply@example.com", SiteName: "OpenIdP", FromName: "OpenIdP"})
	if s.FromName() != "OpenIdP" {
		t.Errorf("FromName = %q", s.FromName())
	}
}

// TestSanitizeHeaderValueBlocksCRLF 邮件头注入防护：
// 换行符必须被剔除，否则攻击者可注入额外头（如 Bcc）或伪造主题。
func TestSanitizeHeaderValueBlocksCRLF(t *testing.T) {
	cases := []string{
		"alice@example.com\nBcc: attacker@example.com",
		"alice@example.com\r\nBcc: attacker@example.com",
		"a\nb",
		"a\rb",
		"\n",
		"\r\n",
	}
	for _, in := range cases {
		got := sanitizeHeaderValue(in)
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("sanitizeHeaderValue(%q) = %q，仍含 CR/LF", in, got)
		}
	}
}

func TestSanitizeHeaderValueKeepsNormalValue(t *testing.T) {
	in := "OpenIdP <noreply@example.com>"
	if got := sanitizeHeaderValue(in); got != in {
		t.Errorf("合法值不应被改写: %q -> %q", in, got)
	}
}

func TestRandomCodeIsDigits(t *testing.T) {
	for i := 0; i < 20; i++ {
		code := randomCode(6)
		if len(code) != 6 {
			t.Fatalf("randomCode(6) 长度 = %d", len(code))
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("randomCode 含非数字: %q", code)
			}
		}
	}
}

func TestDefaultTemplateNonEmpty(t *testing.T) {
	if strings.TrimSpace(DefaultTemplate()) == "" {
		t.Error("默认模板不应为空")
	}
}

// TestRenderTemplateSubstitutesPlaceholders 模板渲染必须把占位符替换为实际值，
// 否则用户收到的邮件里会出现 {{code}} 之类的原始标记。
func TestRenderTemplateSubstitutesPlaceholders(t *testing.T) {
	out := renderTemplate(TemplateData{
		SiteName: "OpenIdP",
		Code:     "123456",
		Action:   "login",
		Minutes:  10,
	}, "")
	if strings.Contains(out, "{{") {
		t.Errorf("渲染结果仍含未替换的占位符: %s", out)
	}
	for _, want := range []string{"123456", "OpenIdP"} {
		if !strings.Contains(out, want) {
			t.Errorf("渲染结果缺少 %q: %s", want, out)
		}
	}
}

// TestRenderTemplateWithCustom 自定义模板同样要完成替换。
func TestRenderTemplateWithCustom(t *testing.T) {
	out := renderTemplate(TemplateData{
		SiteName: "OpenIdP",
		Code:     "654321",
		Minutes:  5,
	}, "您的验证码是 {{code}}（{{minutes}} 分钟内有效）")
	if strings.Contains(out, "{{") {
		t.Errorf("自定义模板仍有未替换占位符: %s", out)
	}
	if !strings.Contains(out, "654321") || !strings.Contains(out, "5") {
		t.Errorf("自定义模板渲染异常: %s", out)
	}
}

func TestRenderTestTemplate(t *testing.T) {
	out := renderTestTemplate("OpenIdP", "https://example.com", "")
	if strings.TrimSpace(out) == "" {
		t.Error("测试邮件模板不应为空")
	}
	// 自定义测试模板应优先使用
	custom := renderTestTemplate("OpenIdP", "https://example.com", "自定义内容 {{siteName}}")
	if !strings.Contains(custom, "OpenIdP") || strings.Contains(custom, "{{") {
		t.Errorf("自定义测试模板渲染异常: %s", custom)
	}
}

func TestHostOnly(t *testing.T) {
	// 基于 net.SplitHostPort 语义：带方括号的 IPv6 会被去掉方括号
	cases := map[string]string{
		"smtp.example.com:587": "smtp.example.com",
		"smtp.example.com":     "smtp.example.com",
		"[::1]:25":             "::1",
		":587":                 "",
		"":                     "",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
