package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newReq 构造一个用于 IP 解析的测试请求。
func newReq(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/session/ip", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestResolveClientIP(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		headers map[string]string
		cfg     ClientIPConfig
		want    string
	}{
		// ---- 不信任代理：一律用 TCP 对端 ----
		{
			name: "TRUST_PROXY=none 时忽略转发头",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7",
				"EO-Client-IP":    "198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: false},
			want: "127.0.0.1",
		},
		{
			name: "未开启 TRUST_PROXY 时 IPv6 对端也正确去端口",
			addr: "[2001:db8::1]:54321",
			cfg:  ClientIPConfig{TrustProxy: false},
			want: "2001:db8::1",
		},

		// ---- IPv6 解析（修掉方括号残留的缺陷）----
		{
			name: "IPv6 带端口对端不残留方括号",
			addr: "[::1]:6099",
			cfg:  ClientIPConfig{TrustProxy: false},
			want: "::1",
		},
		{
			name: "IPv6 裸地址对端",
			addr: "::1",
			cfg:  ClientIPConfig{TrustProxy: false},
			want: "::1",
		},

		// ---- CDN 专用真实 IP 头优先 ----
		{
			name: "EdgeOne 使用 EO-Client-IP",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"EO-Client-IP":    "198.51.100.7",
				"X-Forwarded-For": "9.9.9.9, 198.51.100.7, 203.0.113.5",
			},
			cfg:  ClientIPConfig{TrustProxy: true, Header: "EO-Client-IP"},
			want: "198.51.100.7",
		},
		{
			name: "阿里云 ESA 使用 ali-real-client-ip",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"Ali-Real-Client-Ip": "198.51.100.7",
				"X-Forwarded-For":    "9.9.9.9, 198.51.100.7, 203.0.113.5",
			},
			cfg:  ClientIPConfig{TrustProxy: true, Header: "ali-real-client-ip"},
			want: "198.51.100.7",
		},
		{
			name: "专用头缺失时回退到 XFF",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7, 192.168.1.5",
			},
			cfg:  ClientIPConfig{TrustProxy: true, Header: "EO-Client-IP"},
			want: "198.51.100.7",
		},
		{
			name: "专用头为非法 IP 时跳过并回退到 XFF",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"EO-Client-IP":    "not-an-ip",
				"X-Forwarded-For": "198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: true, Header: "EO-Client-IP"},
			want: "198.51.100.7",
		},
		{
			name: "无任何转发头时回退到对端地址",
			addr: "127.0.0.1:54321",
			cfg:  ClientIPConfig{TrustProxy: true, Header: "EO-Client-IP"},
			want: "127.0.0.1",
		},

		// ---- 默认内网可信网段：无需任何配置即可安全采信 ----
		{
			name: "内网对端默认采信转发头（零配置）",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.7",
		},
		{
			name: "Docker 网关对端（172.17.x）默认采信转发头",
			addr: "172.17.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.7",
		},
		{
			name: "IPv6 内网对端（fc00::/7）默认采信转发头",
			addr: "[fd00::1]:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.7",
		},

		// ---- 公网对端：默认不采信转发头，伪造无效 ----
		{
			name: "公网直连时伪造头不被采信（零配置防伪造）",
			addr: "198.51.100.66:54321",
			headers: map[string]string{
				"X-Forwarded-For": "1.1.1.1",
				"EO-Client-IP":    "1.1.1.1",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.66",
		},
		{
			name: "TRUSTED_PROXIES 扩充后公网对端可被显式信任",
			addr: "198.51.100.66:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"198.51.100.66"},
			},
			want: "198.51.100.7",
		},

		// ---- CDN 专用头嗅探链：未显式配置 Header 时按固定顺序探测 ----
		{
			name: "默认嗅探 CF-Connecting-IP",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"CF-Connecting-IP": "198.51.100.7",
				"X-Forwarded-For":  "9.9.9.9",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.7",
		},
		{
			name: "默认嗅探 EO-Connecting-IP",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"EO-Connecting-IP": "198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.7",
		},
		{
			name: "显式配置的 Header 优先于嗅探链",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"CF-Connecting-IP": "9.9.9.9",
				"EO-Client-IP":     "198.51.100.7",
				"X-Forwarded-For":  "9.9.9.9",
			},
			cfg:  ClientIPConfig{TrustProxy: true, Header: "EO-Client-IP"},
			want: "198.51.100.7",
		},
		{
			name: "嗅探链跳过非法头值回退到 XFF",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"CF-Connecting-IP": "garbage",
				"X-Forwarded-For":  "198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.7",
		},

		// ---- XFF 从右往左：跳过可信跳与内网脏数据，抗伪造 ----
		{
			name: "配置可信代理后 XFF 从右往左定位真实客户端",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7, 203.0.113.5",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"127.0.0.1/8", "203.0.113.0/24"},
			},
			want: "198.51.100.7",
		},
		{
			name: "客户端前插伪造 IP 时不生效",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "9.9.9.9, 198.51.100.7, 203.0.113.5",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"127.0.0.1/8", "203.0.113.0/24"},
			},
			want: "198.51.100.7",
		},
		{
			name: "可信代理支持裸 IP 写法",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.7, 203.0.113.5",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"127.0.0.1", "203.0.113.5"},
			},
			want: "198.51.100.7",
		},
		{
			name: "XFF 只剩内网条目时取最左侧的初始客户端",
			addr: "10.0.0.2:54321",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.10, 10.0.0.8",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"127.0.0.1/8", "10.0.0.0/8"},
			},
			want: "192.168.1.10",
		},
		{
			name: "绕过 Nginx 直连时伪造头不被采信",
			addr: "198.51.100.66:54321",
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
				"EO-Client-IP":    "1.1.1.1",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				Header:         "EO-Client-IP",
				TrustedProxies: []string{"127.0.0.1/8"},
			},
			want: "198.51.100.66",
		},
		{
			name: "对端为可信代理才采信专用头",
			addr: "10.0.0.5:54321",
			headers: map[string]string{
				"EO-Client-IP": "198.51.100.7",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				Header:         "EO-Client-IP",
				TrustedProxies: []string{"10.0.0.0/8"},
			},
			want: "198.51.100.7",
		},
		{
			name: "XFF 中的非法条目被跳过",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "garbage, 198.51.100.7, 203.0.113.5",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"127.0.0.1/8", "203.0.113.0/24"},
			},
			want: "198.51.100.7",
		},
		{
			name: "XFF 全部非法时回退到对端",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "garbage, junk",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "127.0.0.1",
		},
		{
			name: "反代把内网地址写进 XFF 时自动跳过取公网值",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "172.17.0.1, 198.51.100.7",
			},
			cfg:  ClientIPConfig{TrustProxy: true},
			want: "198.51.100.7",
		},
		{
			name: "客户端伪造的最左值不生效（XFF 右读）",
			addr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 203.0.113.5",
			},
			cfg: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"203.0.113.0/24"},
			},
			want: "198.51.100.7",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveClientIP(newReq(tc.addr, tc.headers), tc.cfg)
			if got != tc.want {
				t.Errorf("ResolveClientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNormaliseIP 覆盖 RemoteAddr 的各种书写形式，特别是此前的 IPv6 缺陷。
func TestNormaliseIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:56789":    "1.2.3.4",
		"1.2.3.4":          "1.2.3.4",
		"[::1]:6099":       "::1",
		"[::1]":            "::1",
		"::1":              "::1",
		"[2001:db8::1]:80": "2001:db8::1",
		"":                 "",
		"  ":               "",
	}
	for in, want := range cases {
		if got := normaliseIP(in); got != want {
			t.Errorf("normaliseIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseProxies 覆盖网段解析，非法配置应被忽略而非使解析整体失效。
func TestParseProxies(t *testing.T) {
	nets := parseProxies([]string{"127.0.0.1", " 10.0.0.0/8 ", "", "not-a-cidr", "::1", "2001:db8::/32"})
	if len(nets) != 4 {
		t.Fatalf("parseProxies() 返回 %d 个网段，期望 4（空值与非法值应被忽略）", len(nets))
	}
	for _, addr := range []string{"127.0.0.1", "10.1.2.3", "::1", "2001:db8::5"} {
		if !inNets(nets, addr) {
			t.Errorf("inNets() 对 %q 应为 true", addr)
		}
	}
	for _, addr := range []string{"198.51.100.7", "garbage"} {
		if inNets(nets, addr) {
			t.Errorf("inNets() 对 %q 应为 false", addr)
		}
	}
}

// TestHeaderCandidates 覆盖专用头读取顺序：显式配置最优先，其余按固定顺序。
func TestHeaderCandidates(t *testing.T) {
	if got := headerCandidates("EO-Client-IP"); got[0] != "EO-Client-IP" {
		t.Errorf("显式配置的专用头应最优先，实际 %v", got)
	}
	seen := map[string]bool{}
	for _, name := range headerCandidates("CF-Connecting-IP") {
		if seen[name] {
			t.Errorf("专用头顺序中出现重复项 %q", name)
		}
		seen[name] = true
	}
	if !seen["CF-Connecting-IP"] || !seen["EO-Client-IP"] || !seen["ali-real-client-ip"] {
		t.Errorf("嗅探链应包含常见 CDN 专用头，实际 %v", headerCandidates(""))
	}
}
