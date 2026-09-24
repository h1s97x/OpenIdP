package captcha

import (
	"context"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 人机验证（极验 v4 / Turnstile）测试。
//
// 背景：captcha 包此前零测试。本文件聚焦无需外网的纯逻辑：
//   - 证明的结构完整性判定（Valid）——空证明必须被拒绝，否则等于"没验证也能过"
//   - 各流程是否要求验证（Required）——登录/注册/找回密码三个开关互不干扰
//   - 签名与下发配置（sign / CaptchaConfigPayload）——密钥不得出现在下发给前端的配置里
// 涉及真实网络调用的 TestConnection / Verify 不在此覆盖。
// ---------------------------------------------------------------------------

func TestCaptchaValidRequiresAllFields(t *testing.T) {
	full := &Captcha{
		LotNumber:     "lot-1",
		CaptchaOutput: "out-1",
		PassToken:     "tok-1",
		GenTime:       "1700000000",
	}
	if !full.Valid() {
		t.Fatal("完整证明应判定为有效")
	}

	// 任一字段缺失都应判为无效（否则服务端校验可被绕过）
	fields := []struct {
		name string
		mut  func(c *Captcha)
	}{
		{"缺 LotNumber", func(c *Captcha) { c.LotNumber = "" }},
		{"缺 CaptchaOutput", func(c *Captcha) { c.CaptchaOutput = "" }},
		{"缺 PassToken", func(c *Captcha) { c.PassToken = "" }},
		{"缺 GenTime", func(c *Captcha) { c.GenTime = "" }},
	}
	for _, f := range fields {
		c := *full
		f.mut(&c)
		if c.Valid() {
			t.Errorf("%s 时应判为无效", f.name)
		}
	}

	// nil 指针不应 panic
	var nilC *Captcha
	if nilC.Valid() {
		t.Error("nil 证明应判为无效")
	}
}

func TestGeetestRequiredPerFlow(t *testing.T) {
	cfg := &Config{
		Enabled:                  true,
		CaptchaID:                "id",
		CaptchaKey:               "key",
		RequiredForLogin:         true,
		RequiredForSignup:        false,
		RequiredForPasswordReset: true,
	}
	p := geetestProvider{cfg: cfg}

	if !p.Enabled() {
		t.Fatal("已配置应视为启用")
	}
	if !p.Required(FlowLogin) {
		t.Error("登录流程应要求验证")
	}
	if p.Required(FlowSignup) {
		t.Error("注册流程未开启，不应要求验证")
	}
	if !p.Required(FlowPasswordReset) {
		t.Error("找回密码流程应要求验证")
	}
}

// TestNewProviderSkipsDisabledProviders 未启用的提供商不得被选中：
// 否则会出现"required 开着但前端不渲染控件"的死局（用户永远无法完成验证）。
// NewProvider 是这道保障：Enabled 为假时一律降级到 noopProvider。
func TestNewProviderSkipsDisabledProviders(t *testing.T) {
	allOn := &Config{
		CaptchaID: "id", CaptchaKey: "key", Enabled: false,
		RequiredForLogin: true, RequiredForSignup: true, RequiredForPasswordReset: true,
	}
	p := NewProvider(allOn, nil)
	if p.Name() != "none" {
		t.Errorf("未启用的极验应降级为 none，实际 %q", p.Name())
	}
	if p.Enabled() || p.Required(FlowLogin) {
		t.Error("noopProvider 不应启用，也不应要求任何流程")
	}

	// 未启用的 Turnstile 同样降级
	if p := NewProvider(nil, &TurnstileConfig{Enabled: false, SiteKey: "s", SecretKey: "k"}); p.Name() != "none" {
		t.Errorf("未启用的 Turnstile 应降级为 none，实际 %q", p.Name())
	}

	// 全部为空配置 → none
	if p := NewProvider(nil, nil); p.Name() != "none" {
		t.Errorf("无配置时应为 none，实际 %q", p.Name())
	}
}

// TestNewProviderPrefersTurnstile 两者都启用时优先 Turnstile（见 NewProvider 注释）。
func TestNewProviderPrefersTurnstile(t *testing.T) {
	p := NewProvider(
		&Config{Enabled: true, CaptchaID: "g", CaptchaKey: "k"},
		&TurnstileConfig{Enabled: true, SiteKey: "s", SecretKey: "k"},
	)
	if p.Name() != "turnstile" {
		t.Errorf("两者都启用时应优先 turnstile，实际 %q", p.Name())
	}
}

// TestNewProviderSelectsEnabledGeetest 仅极验启用时选中极验。
func TestNewProviderSelectsEnabledGeetest(t *testing.T) {
	p := NewProvider(&Config{Enabled: true, CaptchaID: "g", CaptchaKey: "k", RequiredForLogin: true}, nil)
	if p.Name() != "geetest" {
		t.Errorf("应选中 geetest，实际 %q", p.Name())
	}
	if !p.Required(FlowLogin) {
		t.Error("已启用且开启登录验证时应返回 true")
	}
}

// TestNoopProviderIsPermissive 空实现必须放行（用于"未配置人机验证"的部署），
// 且 Verify 返回 true——否则未配置的站点会全面拒绝登录/注册。
func TestNoopProviderIsPermissive(t *testing.T) {
	var p noopProvider
	if p.Enabled() {
		t.Error("noopProvider 不应报告启用")
	}
	ok, err := p.Verify(context.Background(), nil, "127.0.0.1")
	if !ok || err != nil {
		t.Errorf("noopProvider.Verify = (%v, %v), want (true, nil)", ok, err)
	}
	if payload := p.ConfigPayload(); payload["provider"] != "none" {
		t.Errorf("noopProvider payload = %+v", payload)
	}
}

func TestGeetestName(t *testing.T) {
	if got := (geetestProvider{cfg: &Config{}}).Name(); got != "geetest" {
		t.Errorf("Name = %q, want geetest", got)
	}
}

// TestConfigPayloadLeaksNoSecret 下发给前端的配置绝不能包含密钥，
// 否则前端可自行构造签名通过校验。
func TestConfigPayloadLeaksNoSecret(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		CaptchaID:  "my-captcha-id",
		CaptchaKey: "SUPER-SECRET-KEY",
		BindMode:   "bind",
	}
	payload := cfg.CaptchaConfigPayload()

	// 密钥不得出现在下发内容中（逐值检查，避免 JSON 转义导致的误判）
	for _, v := range payload {
		if s, ok := v.(string); ok && strings.Contains(s, "SUPER-SECRET-KEY") {
			t.Errorf("下发配置泄露了密钥: %+v", payload)
		}
	}
	// 必要字段应存在，供前端渲染（公钥以 siteKey 下发）
	if payload["siteKey"] != "my-captcha-id" {
		t.Errorf("siteKey = %v, want my-captcha-id", payload["siteKey"])
	}
	if payload["provider"] != "geetest" {
		t.Errorf("provider = %v, want geetest", payload["provider"])
	}
	// BindMode 缺省时应兜底为 bind
	if (&Config{Enabled: true}).CaptchaConfigPayload()["product"] != "bind" {
		t.Error("product 缺省应兜底为 bind")
	}
}

func TestSignIsDeterministicAndNonEmpty(t *testing.T) {
	cfg := &Config{CaptchaID: "id", CaptchaKey: "key"}
	a := cfg.sign("lot-123")
	b := cfg.sign("lot-123")
	if a == "" {
		t.Fatal("签名不应为空")
	}
	if a != b {
		t.Error("相同输入应产生相同签名（确定性）")
	}
	// 不同输入应产生不同签名
	if a == cfg.sign("lot-456") {
		t.Error("不同 lot_number 应产生不同签名")
	}
}

func TestSignDiffersByKey(t *testing.T) {
	a := (&Config{CaptchaKey: "key-a"}).sign("lot")
	b := (&Config{CaptchaKey: "key-b"}).sign("lot")
	if a == b {
		t.Error("不同密钥应产生不同签名")
	}
}

// TestVerifyRejectsWhenUnconfigured 未配置（无 ID/Key）时校验应明确失败，
// 而不是"放行"（fail-open 会让人机验证形同虚设）。
func TestVerifyRejectsWhenUnconfigured(t *testing.T) {
	cfg := &Config{} // 未启用
	ok, err := cfg.Verify(context.Background(), &Captcha{
		LotNumber: "l", CaptchaOutput: "o", PassToken: "p", GenTime: "1",
	})
	if ok {
		t.Error("未配置时不应放行校验")
	}
	if err == nil {
		t.Error("未配置时应返回错误，而不是静默返回 false")
	}
}

// TestVerifyRejectsMissingProof 已启用但客户端未提交证明时必须失败。
func TestVerifyRejectsMissingProof(t *testing.T) {
	cfg := &Config{Enabled: true, CaptchaID: "id", CaptchaKey: "key"}
	ok, err := cfg.Verify(context.Background(), nil)
	if ok {
		t.Error("未提交证明时不应通过")
	}
	if err == nil {
		t.Error("未提交证明时应返回错误")
	}
}

// TestTurnstileProviderBasics 覆盖 Turnstile 提供商的基础行为。
func TestTurnstileProviderBasics(t *testing.T) {
	p := turnstileProvider{cfg: &TurnstileConfig{Enabled: true, SiteKey: "site", SecretKey: "secret"}}
	if p.Name() != "turnstile" {
		t.Errorf("Name = %q, want turnstile", p.Name())
	}
	if !p.Enabled() {
		t.Error("已配置应视为启用")
	}
	// 下发配置同样不得泄露密钥
	for _, v := range p.ConfigPayload() {
		if s, ok := v.(string); ok && strings.Contains(s, "secret") {
			t.Errorf("Turnstile 下发配置泄露密钥: %+v", p.ConfigPayload())
		}
	}
}

func TestTurnstileDisabled(t *testing.T) {
	p := turnstileProvider{cfg: &TurnstileConfig{Enabled: false}}
	if p.Enabled() {
		t.Error("未启用标志下不应视为启用")
	}
}

func TestDefaultAPIDomain(t *testing.T) {
	if DefaultAPIDomain == "" {
		t.Error("默认 API 域名不应为空")
	}
	if !strings.HasPrefix(DefaultAPIDomain, "http") {
		t.Errorf("默认 API 域名应带协议: %q", DefaultAPIDomain)
	}
}
