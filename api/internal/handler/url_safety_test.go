package handler

import "testing"

// TestSanitizeExternalURL 覆盖存储型 XSS 的常见绕过形态：
// 只有 http/https 的绝对地址才应通过，空串视为「未填写」而非非法。
func TestSanitizeExternalURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"   ", "", true},
		{"https://app.example.com/home", "https://app.example.com/home", true},
		{"http://app.example.com", "http://app.example.com", true},
		{"  https://app.example.com/x  ", "https://app.example.com/x", true},
		{"HTTPS://APP.EXAMPLE.COM", "HTTPS://APP.EXAMPLE.COM", true},
		// 危险协议：会被浏览器当作可执行脚本 / 内联数据。
		{"javascript:alert(document.cookie)", "", false},
		{"JaVaScRiPt:alert(1)", "", false},
		{"data:text/html,<script>alert(1)</script>", "", false},
		{"vbscript:msgbox(1)", "", false},
		{"file:///etc/passwd", "", false},
		// 协议相对与相对路径：不是可展示的外部地址。
		{"//evil.example.com", "", false},
		{"/admin/settings", "", false},
		{"app.example.com", "", false},
		// 有 scheme 无 host。
		{"http:///no-host", "", false},
		// 不可解析的 URL。
		{"http://[::1", "", false},
	}
	for _, c := range cases {
		got, ok := sanitizeExternalURL(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("sanitizeExternalURL(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestSanitizeAssetURL 品牌资源地址额外允许站内绝对路径，
// 但协议相对地址与危险协议依旧必须拒绝。
func TestSanitizeAssetURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"   ", "", true},
		{"/images/logo.svg", "/images/logo.svg", true},
		{"https://cdn.example.com/logo.svg", "https://cdn.example.com/logo.svg", true},
		// 协议相对：看起来像站内路径，实际指向外部站点，必须拒绝。
		{"//evil.example.com/logo.svg", "", false},
		// 反斜杠同理：浏览器把 "\" 当作 "/" 规整，
		// "/\evil.example.com/x.svg" 最终会变成 https://evil.example.com/x.svg。
		{"/\\evil.example.com/logo.svg", "", false},
		{"/images\\logo.svg", "", false},
		{"javascript:alert(1)", "", false},
		{"data:image/svg+xml,<svg onload=alert(1)>", "", false},
		{"logo.svg", "", false},
	}
	for _, c := range cases {
		got, ok := sanitizeAssetURL(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("sanitizeAssetURL(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
