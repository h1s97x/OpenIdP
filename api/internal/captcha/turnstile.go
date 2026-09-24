package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Cloudflare Turnstile (人机验证) server-side verification.
//
//	POST https://challenges.cloudflare.com/turnstile/v0/siteverify
//	  secret, response, remoteip
//
// Reference: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/

// TurnstileConfig holds Cloudflare Turnstile credentials from the environment.
type TurnstileConfig struct {
	// SiteKey is the public Turnstile site key (rendered in the widget).
	SiteKey string
	// SecretKey is the server-side secret key.
	SecretKey string
	// Enabled reports whether Turnstile is configured.
	Enabled bool
	// RequiredForLogin / RequiredForSignup / RequiredForPasswordReset gate
	// whether the widget must be presented for these flows.
	RequiredForLogin         bool
	RequiredForSignup        bool
	RequiredForPasswordReset bool
	// VerifyURL overrides the siteverify endpoint (for tests/proxies).
	VerifyURL string
}

// DefaultVerifyURL is the built-in Cloudflare Turnstile siteverify endpoint.
// 内置默认 siteverify 域名（可在管理后台覆盖）。
const DefaultVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// TestConnection verifies the Turnstile site key / secret key by sending a
// dummy response to the siteverify endpoint. Since the site key / secret key
// are checked before the (fake) response token:
//
//	secret 无效 → error-codes 含 invalid-input-secret / bad-request
//	secret 有效 → error-codes 含 invalid-input-response（假 token 预期失败）
//	域名不可达 → 返回连接错误
//
// Used by the admin console's 测试连接 button.
func TestTurnstileConnection(ctx context.Context, siteKey, secretKey, verifyURL string) (map[string]any, error) {
	if strings.TrimSpace(siteKey) == "" || strings.TrimSpace(secretKey) == "" {
		return nil, ErrIncomplete
	}
	base := strings.TrimRight(verifyURL, "/")
	if base == "" {
		base = DefaultVerifyURL
	}
	form := url.Values{}
	form.Set("secret", secretKey)
	form.Set("response", "dummy-test-token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Turnstile siteverify HTTP %d: %s", resp.StatusCode, string(body))
	}
	var vr siteVerifyResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return nil, fmt.Errorf("Turnstile siteverify 响应解析失败: %s", string(body))
	}
	codeKey := ""
	for _, c := range vr.ErrorCodes {
		switch c {
		case "invalid-input-secret", "bad-request", "timeout-or-duplicate", "internal-error":
			codeKey = c
		}
	}
	if codeKey == "" {
		// 没有“凭据错误”类错误码 → secret 校验通过（假 token 只会触发 invalid-input-response）。
		return map[string]any{
			"ok":       true,
			"provider": "turnstile",
			"detail":   "连接成功，Site Key / Secret Key 有效（响应=" + string(body) + "）",
		}, nil
	}
	return nil, fmt.Errorf("Turnstile 凭据无效（%s），请检查 Site Key / Secret Key", codeKey)
}

// siteVerifyResponse mirrors the Turnstile siteverify response body.
type siteVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// Verify validates a Turnstile token. When Turnstile is not configured it
// returns ErrNotConfigured so callers can decide how to handle the flow.
func (c *TurnstileConfig) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if !c.Enabled {
		return false, ErrNotConfigured
	}
	if strings.TrimSpace(token) == "" {
		return false, ErrIncomplete
	}
	endpoint := c.VerifyURL
	if endpoint == "" {
		endpoint = DefaultVerifyURL
	}

	form := url.Values{}
	form.Set("secret", c.SecretKey)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("turnstile siteverify HTTP %d: %s", resp.StatusCode, string(body))
	}
	var vr siteVerifyResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return false, err
	}
	if !vr.Success {
		// 区分"未完成"与"验证被拒绝"：失败时携带错误码，便于前端/日志诊断。
		code := strings.Join(vr.ErrorCodes, ", ")
		if code == "" {
			code = "unknown"
		}
		return false, fmt.Errorf("turnstile siteverify rejected: %s", code)
	}
	return true, nil
}

// CaptchaConfigPayload builds the unified captcha config block for login-policy.
func (c *TurnstileConfig) CaptchaConfigPayload() map[string]any {
	return map[string]any{
		"enabled":                  c.Enabled,
		"provider":                 "turnstile",
		"siteKey":                  c.SiteKey,
		"requiredForLogin":         c.RequiredForLogin,
		"requiredForSignup":        c.RequiredForSignup,
		"requiredForPasswordReset": c.RequiredForPasswordReset,
	}
}
