// Package proxyutil 提供基于 ProxySetting 的出站 HTTP 客户端构造，
// 供第三方登录提供商的令牌/用户信息请求按需走代理。
package netutil

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// DialTimeout / RequestTimeout 出站代理请求的超时上限。
const (
	DialTimeout    = 10 * time.Second
	RequestTimeout = 15 * time.Second
)

// HTTPClient 构造走指定代理 URL 的 *http.Client。
// proxyURL 形如 http://host:port、http://user:pass@host:port、socks5://...；
// 传空串时返回直连客户端（与普通请求一致）。
func HTTPClient(proxyURL string) (*http.Client, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return &http.Client{Timeout: RequestTimeout}, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url: %w", err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		transport.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		dialer, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: DialTimeout})
		if err != nil {
			return nil, fmt.Errorf("socks5 dialer: %w", err)
		}
		cd, ok := dialer.(proxy.ContextDialer)
		if ok {
			transport.DialContext = cd.DialContext
		} else {
			transport.Dial = dialer.Dial
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
	return &http.Client{Timeout: RequestTimeout, Transport: transport}, nil
}

// TestConnectivity 经代理请求外部地址，返回 HTTP 状态码与耗时，用于「测试连通性」。
// target 为空时使用 https://www.google.com/generate_204。
func TestConnectivity(ctx context.Context, proxyURL, target string) (int, time.Duration, error) {
	if strings.TrimSpace(target) == "" {
		target = "https://www.google.com/generate_204"
	}
	client, err := HTTPClient(proxyURL)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "openidp-proxy-check")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, time.Since(start), nil
}
