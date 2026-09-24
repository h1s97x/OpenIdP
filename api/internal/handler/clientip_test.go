package handler

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// setLocationSetting 写入「归属地」配置（客户端 IP 头 / 可信代理网段），
// 与管理后台 handleAdminUpdateLocation 的写入方式保持一致。
func setLocationSetting(t *testing.T, h *Handler, header, trusted string) {
	t.Helper()
	ls := h.loadLocationSetting()
	ls.RealIPHeader = strings.TrimSpace(header)
	ls.TrustedProxies = strings.TrimSpace(trusted)
	ls.UpdatedAt = time.Now().UTC()
	if _, err := h.db.NewUpdate().Model(ls).WherePK().Exec(context.Background()); err != nil {
		t.Fatalf("写入归属地配置失败: %v", err)
	}
	// 与管理后台保存后一致：清掉进程内缓存，让改动立即生效。
	h.conf.invalidate()
}

// TestClientIPConfigPrecedence 校验环境变量与管理后台配置的优先级：
// 后台非空配置生效，留空则回退到环境变量。
func TestClientIPConfigPrecedence(t *testing.T) {
	h, _ := newTestHandler(t)
	h.cfg.TrustProxy = true
	h.cfg.ClientIPHeader = "CF-Connecting-IP"

	// 后台未配置 → 沿用环境变量。
	if got := h.clientIPConfig(); got.Header != "CF-Connecting-IP" || len(got.TrustedProxies) != 0 {
		t.Fatalf("后台未配置时期望沿用环境变量，实际 header=%q trusted=%v", got.Header, got.TrustedProxies)
	}

	// 后台配置真实 IP 头 → 优先于环境变量。
	setLocationSetting(t, h, "EO-Client-IP", "")
	if got := h.clientIPConfig(); got.Header != "EO-Client-IP" {
		t.Fatalf("后台真实 IP 头应为 EO-Client-IP，实际 %q", got.Header)
	}

	// 后台配置可信代理 → 按逗号拆分。
	setLocationSetting(t, h, "EO-Client-IP", "127.0.0.1/8, 10.0.0.0/8")
	cfg := h.clientIPConfig()
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != "127.0.0.1/8" || cfg.TrustedProxies[1] != "10.0.0.0/8" {
		t.Fatalf("可信代理应按逗号拆分，实际 %v", cfg.TrustedProxies)
	}

	// 后台清空 → 回退到环境变量，而不是残留上次的值。
	setLocationSetting(t, h, "", "")
	if got := h.clientIPConfig(); got.Header != "CF-Connecting-IP" || len(got.TrustedProxies) != 0 {
		t.Fatalf("后台清空后应回退到环境变量，实际 header=%q trusted=%v", got.Header, got.TrustedProxies)
	}
}

// resolveIP 跑一遍 withClientIP 中间件，返回解析出的客户端 IP。
func resolveIP(h *Handler, remoteAddr string, headers map[string]string) string {
	got := ""
	h.withClientIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = clientIP(r)
	})).ServeHTTP(httptest.NewRecorder(), newIPRequest(remoteAddr, headers))
	return got
}

func newIPRequest(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/session/ip", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestWithClientIPUsesAdminRealIPHeader 是本次修复的核心回归用例：
// 管理后台填写的「客户端 IP 请求头」必须真正参与解析（此前只持久化、从不生效）。
func TestWithClientIPUsesAdminRealIPHeader(t *testing.T) {
	h, _ := newTestHandler(t)
	h.cfg.TrustProxy = true
	h.cfg.ClientIPHeader = "CF-Connecting-IP"
	setLocationSetting(t, h, "EO-Client-IP", "127.0.0.1/8")

	got := resolveIP(h, "127.0.0.1:54321", map[string]string{
		// 客户端在最左侧塞入伪造值；专用头不可被追加，应胜出。
		"X-Forwarded-For": "9.9.9.9, 198.51.100.7",
		"EO-Client-IP":    "198.51.100.7",
	})
	if got != "198.51.100.7" {
		t.Fatalf("clientIP() = %q, want 198.51.100.7（后台配置的真实 IP 头未生效）", got)
	}
}

// TestWithClientIPRejectsUntrustedPeer 校验可信代理网段：
// 对端不在名单内时，伪造的转发头必须被忽略。
func TestWithClientIPRejectsUntrustedPeer(t *testing.T) {
	h, _ := newTestHandler(t)
	h.cfg.TrustProxy = true
	h.cfg.ClientIPHeader = "EO-Client-IP"
	setLocationSetting(t, h, "EO-Client-IP", "10.0.0.0/8")

	// 对端 203.0.113.9 不在可信网段 → 一律回退到 TCP 对端，伪造头无效。
	got := resolveIP(h, "203.0.113.9:54321", map[string]string{
		"EO-Client-IP":    "1.1.1.1",
		"X-Forwarded-For": "127.0.0.1",
	})
	if got != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want 203.0.113.9（不可信对端的伪造头被采信了）", got)
	}

	// 对端 10.1.2.3 在可信网段 → 采信真实 IP 头。
	got = resolveIP(h, "10.1.2.3:54321", map[string]string{
		"EO-Client-IP": "198.51.100.7",
	})
	if got != "198.51.100.7" {
		t.Fatalf("clientIP() = %q, want 198.51.100.7", got)
	}
}

// TestWithClientIPTrustProxyDisabled 未开启 TRUST_PROXY 时不得采信任何转发头。
func TestWithClientIPTrustProxyDisabled(t *testing.T) {
	h, _ := newTestHandler(t)
	h.cfg.TrustProxy = false
	setLocationSetting(t, h, "EO-Client-IP", "")

	got := resolveIP(h, "127.0.0.1:54321", map[string]string{
		"EO-Client-IP":    "198.51.100.7",
		"X-Forwarded-For": "198.51.100.7",
	})
	if got != "127.0.0.1" {
		t.Fatalf("clientIP() = %q, want 127.0.0.1（TRUST_PROXY=false 时不应采信转发头）", got)
	}
}

// TestWithClientIPIPv6Peer 覆盖此前 IPv6 对端残留方括号的缺陷。
func TestWithClientIPIPv6Peer(t *testing.T) {
	h, _ := newTestHandler(t)
	h.cfg.TrustProxy = false

	got := resolveIP(h, "[2001:db8::1]:54321", nil)
	if got != "2001:db8::1" {
		t.Fatalf("clientIP() = %q, want 2001:db8::1（IPv6 对端解析有误）", got)
	}
	// 解析结果必须是可被 net.ParseIP 接受的裸 IP：残留方括号会让
	// SETUP_ALLOW_REMOTE=false 的本机判断与归属地解析在 IPv6 下失效。
	if net.ParseIP(got) == nil {
		t.Fatalf("clientIP() = %q 不是合法 IP", got)
	}
}
