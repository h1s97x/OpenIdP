package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTrustedPeerOnlyAcceptsLoopbackAndPrivate 只有落在可信网段内的对端才允许
// 采信其转发头。该判定是 requestBaseURL / 客户端 IP 解析的共同前置条件。
func TestTrustedPeerOnlyAcceptsLoopbackAndPrivate(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		want   bool
	}{
		{"loopback v4", "127.0.0.1:1234", true},
		{"loopback v6", "[::1]:1234", true},
		{"rfc1918 192.168", "192.168.1.10:5555", true},
		{"rfc1918 10", "10.0.0.7:5555", true},
		{"rfc1918 172.16", "172.16.5.5:5555", true},
		{"public ip", "203.0.113.5:443", false},
		{"public dns", "8.8.8.8:443", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.remote
			if got := TrustedPeer(r, nil); got != c.want {
				t.Errorf("TrustedPeer(%q) = %v, want %v", c.remote, got, c.want)
			}
		})
	}

	// 显式配置的额外可信网段（如 CDN 回源网段）应被接受。
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:443"
	if !TrustedPeer(r, []string{"203.0.113.0/24"}) {
		t.Error("explicitly configured trusted proxy CIDR should be accepted")
	}
	// 未配置时同一地址必须被拒绝。
	if TrustedPeer(r, nil) {
		t.Error("public peer must not be trusted by default")
	}
}
