// Package captcha implements GeeTest v4 (极验四代) captcha verification
// for login/signup flows. Server-side validation calls GeeTest's validate API:
//
//	POST https://gcaptcha4.geetest.com/validate
//	  captcha_id, lot_number, captcha_output, pass_token, gen_time, sign_token
//
// Reference: https://docs.geetest.com/gt4/deploy/server
package captcha

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config holds GeeTest credentials from environment variables.
type Config struct {
	// CaptchaID is the GeeTest captcha_id (from the GeeTest console).
	CaptchaID string
	// CaptchaKey is the GeeTest captcha_key used to sign validation requests.
	CaptchaKey string
	// Enabled reports whether server-side verification is configured.
	Enabled bool
	// RequiredForLogin / RequiredForSignup / RequiredForPasswordReset gate
	// whether the captcha must be presented for these flows.
	RequiredForLogin         bool
	RequiredForSignup        bool
	RequiredForPasswordReset bool
	// BindMode selects the GeeTest v4 product type rendered in the web widget.
	// "bind"（滑动验证·绑定模式）内嵌滑块；"popup" 为弹出式；"float" 为浮动式。
	BindMode string
	// APIDomain overrides the default validate endpoint (for proxies/testing).
	// 默认 https://gcaptcha4.geetest.com
	APIDomain string
}

// Captcha is a client-provided GeeTest v4 proof.
type Captcha struct {
	LotNumber     string `json:"lot_number"`
	CaptchaOutput string `json:"captcha_output"`
	PassToken     string `json:"pass_token"`
	GenTime       string `json:"gen_time"`
}

// Valid reports whether the proof is structurally complete.
func (c *Captcha) Valid() bool {
	return c != nil && c.LotNumber != "" && c.CaptchaOutput != "" && c.PassToken != "" && c.GenTime != ""
}

// verifyResponse is the GeeTest validate API response.
// 注意：极验 v4 的响应中 status 类型不固定（可能是数字也可能是字符串），
// 这里不声明 status 字段——未在结构中声明的多余字段会被 json 解析器安全忽略，
// 从而避免“status 类型不一致”导致整个校验结果反序列化失败。
type verifyResponse struct {
	Result        string `json:"result"` // success | fail
	Reason        string `json:"reason"`
	CaptchaID     string `json:"captcha_id"`
	CaptchaOutput string `json:"captcha_output"`
	GenTime       string `json:"gen_time"`
	LotNumber     string `json:"lot_number"`
	PassToken     string `json:"pass_token"`
}

// DefaultAPIDomain is the built-in GeeTest v4 API domain.
// 极验 v4 官方 API 域名（内置默认，可在管理后台覆盖）。
const DefaultAPIDomain = "https://gcaptcha4.geetest.com"

// TestConnection verifies that the given GeeTest credentials resolve and the
// API domain is reachable. It calls the v4 "load" endpoint which returns
// success only for a valid captcha_id, and fails on bad credentials or an
// unreachable domain. Used by the admin console's 测试连接 button.
func TestConnection(ctx context.Context, apiDomain, captchaID, captchaKey string) (map[string]any, error) {
	captchaID = strings.TrimSpace(captchaID)
	captchaKey = strings.TrimSpace(captchaKey)
	if captchaID == "" || captchaKey == "" {
		return nil, ErrIncomplete
	}
	base := strings.TrimRight(apiDomain, "/")
	if base == "" {
		base = DefaultAPIDomain
	}
	// 极验 v4 load 接口：请求极验初始化参数，校验 captcha_id 是否有效。
	// 形如 https://gcaptcha4.geetest.com/load?captcha_id={id}&t=...&sign_token=...
	// sign_token = HMAC-SHA256(captcha_key, "PUT_" + t)（load 接口使用）。
	t := strconv.FormatInt(int64(time.Now().UTC().Unix()), 10) // 秒级时间戳
	signBuf := "PUT_" + t
	mac := hmac.New(sha256.New, []byte(captchaKey))
	mac.Write([]byte(signBuf))
	signToken := hex.EncodeToString(mac.Sum(nil))

	params := url.Values{}
	params.Set("captcha_id", captchaID)
	params.Set("t", t)
	params.Set("sign_token", signToken)
	params.Set("lang", "cn")
	endpoint := base + "/load?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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
		// 403 通常是 captcha_id 无效/域名被拒绝；其它状态同诊断。
		return nil, fmt.Errorf("极验 load 接口 HTTP %d（%s）——请检查 captcha_id / captcha_key 是否正确，或当前网络是否能访问极验服务", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed map[string]any
	// 极验 load 接口返回的是 JSONP 包裹的 JSON（形如 ({"status":"success",...})），
	// 剥离首尾的括号后再解析，避免 json.Unmarshal 失败导致测试连接误判“异常”。
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "" && ((trimmed[0] == '(' && strings.HasSuffix(trimmed, ")")) || (trimmed[0] == '[')) {
		if trimmed[0] == '(' {
			trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		}
	}
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, fmt.Errorf("geetest load 响应解析失败: %s", string(body))
	}
	// 极验 load 成功时 result=success；captcha_id 无效或密钥不匹配时 result=fail。
	if result := parsed["result"]; result != "success" {
		reason := ""
		if str, ok := parsed["reason"].(string); ok {
			reason = str
		}
		// 欢迎码: 也接受 status==success 通过（部分环境返回 status）
		if status, ok := parsed["status"].(string); ok && status == "success" {
			return map[string]any{"ok": true, "provider": "geetest", "detail": "连接成功，captcha_id 有效"}, nil
		}
		msg := "极验初始化失败（result=" + fmt.Sprint(result) + "，请检查 captcha_id / captcha_key / 域名）"
		if reason != "" {
			msg += "；原因：" + reason
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return map[string]any{"ok": true, "provider": "geetest", "detail": "连接成功，captcha_id 有效"}, nil
}

// Verify validates a GeeTest v4 captcha proof. When the server is not
// configured (no captcha credentials) it returns an "unconfigured" error so
// callers can decide whether to treat the flow as open.
func (c *Config) Verify(ctx context.Context, proof *Captcha) (bool, error) {
	if !c.Enabled {
		return false, ErrNotConfigured
	}
	if !proof.Valid() {
		return false, ErrIncomplete
	}
	if c.APIDomain == "" {
		c.APIDomain = DefaultAPIDomain
	}
	// 防御性裁剪：captcha_id / 私钥常因复制粘贴或 .env 末尾空白而带入不可见字符，
	// 这会直接导致极验校验 sign_token 不匹配。运行时虽经 FirstNonEmpty 裁剪，
	// 这里再裁一次以确保用于签名的取值必然是干净字符串。
	captchaID := strings.TrimSpace(c.CaptchaID)
	endpoint := strings.TrimRight(strings.TrimSpace(c.APIDomain), "/") + "/validate"

	form := url.Values{}
	form.Set("captcha_id", captchaID)
	form.Set("lot_number", proof.LotNumber)
	form.Set("captcha_output", proof.CaptchaOutput)
	form.Set("pass_token", proof.PassToken)
	form.Set("gen_time", proof.GenTime)
	form.Set("sign_token", c.sign(proof.LotNumber))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 极验服务位于境外，国内网络可能慢；给足 15 秒避免“awaiting headers 超时”
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
		return false, fmt.Errorf("geetest validate HTTP %d: %s", resp.StatusCode, string(body))
	}
	var vr verifyResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return false, err
	}
	if vr.Result != "success" {
		// 极验明确拒绝：区分"未完成"与"验证失败"，便于前端展示准确原因。
		reason := vr.Reason
		// sign_token error 的根因几乎总是“私钥 captcha_key 与 captcha_id 不是同一套”，
		// 把原因翻译成可操作提示，避免管理员在代码层面反复排查。
		if strings.Contains(strings.ToLower(reason), "sign_token") {
			reason = "sign_token error（极验 captcha_key 与 captcha_id 不匹配：请确认后台填写的私钥属于该 captcha_id，且保存时密钥字段已填写）"
		}
		return false, errors.New("geetest validation rejected: " + reason)
	}
	return true, nil
}

// sign computes sign_token = HMAC-SHA256(captcha_key, lot_number).
// 入参均先做 TrimSpace，规避复制粘贴/配置文件末尾空白破坏 HMAC。
func (c *Config) sign(lotNumber string) string {
	key := strings.TrimSpace(c.CaptchaKey)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(strings.TrimSpace(lotNumber)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Errors
var (
	ErrNotConfigured = fmt.Errorf("geetest not configured")
	ErrIncomplete    = fmt.Errorf("geetest proof is incomplete")
)

// CaptchaConfigPayload builds the captcha config block for login-policy.
func (c *Config) CaptchaConfigPayload() map[string]any {
	product := c.BindMode
	if product == "" {
		product = "bind"
	}
	return map[string]any{
		"enabled":                  c.Enabled,
		"provider":                 "geetest",
		"siteKey":                  c.CaptchaID,
		"product":                  product,
		"requiredForLogin":         c.RequiredForLogin,
		"requiredForSignup":        c.RequiredForSignup,
		"requiredForPasswordReset": c.RequiredForPasswordReset,
	}
}
