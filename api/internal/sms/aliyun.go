package sms

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// aliyunProvider 对接阿里云号码认证服务（dypnsapi）的短信认证。
//
//	POST https://dypnsapi.aliyuncs.com/  (RPC 风格，2017-05-25)
//	  Action=SendSmsVerifyCode
//	  PhoneNumber=..., SignName=..., TemplateCode=..., TemplateParam=...
//
// 使用 RPC V1 签名（HMAC-SHA1）。验证码由 OpenIdP 自己生成并通过 TemplateParam
// 传入（ReturnVerifyCode 场景由调用方模板决定），校验在本地完成。
type aliyunProvider struct{ cfg *Config }

// DefaultAliyunEndpoint 是阿里云号码认证服务的默认接入点。
const DefaultAliyunEndpoint = "https://dypnsapi.aliyuncs.com"

func (p *aliyunProvider) Name() string { return "aliyun" }

func (p *aliyunProvider) Enabled() bool {
	c := p.cfg
	return c != nil && c.AliyunAccessKeyID != "" && c.AliyunAccessKeySecret != "" &&
		c.AliyunSignName != "" && c.AliyunTemplateCode != ""
}

func (p *aliyunProvider) endpoint() string {
	if strings.TrimSpace(p.cfg.AliyunEndpoint) != "" {
		return strings.TrimSpace(p.cfg.AliyunEndpoint)
	}
	return DefaultAliyunEndpoint
}

func (p *aliyunProvider) Send(ctx context.Context, phone, code string) (string, error) {
	if !p.Enabled() {
		return "", ErrIncomplete
	}
	params := map[string]string{
		"Action":           "SendSmsVerifyCode",
		"Version":          "2017-05-25",
		"RegionId":         "cn-hangzhou",
		"PhoneNumber":      phone,
		"SignName":         p.cfg.AliyunSignName,
		"TemplateCode":     p.cfg.AliyunTemplateCode,
		"TemplateParam":    fmt.Sprintf(`{"code":"%s"}`, code),
		"Format":           "JSON",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	body, err := aliyunRPC(ctx, p.endpoint(), p.cfg.AliyunAccessKeyID, p.cfg.AliyunAccessKeySecret, params)
	if err != nil {
		return "", err
	}
	var resp struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
		Model     struct {
			BizID string `json:"BizId"`
		} `json:"Model"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("aliyun sms response parse: %w (%s)", err, string(body))
	}
	if resp.Code != "OK" {
		return "", fmt.Errorf("aliyun sms rejected: %s %s", resp.Code, resp.Message)
	}
	return resp.Model.BizID, nil
}

func (p *aliyunProvider) TestConnection(ctx context.Context) error {
	if !p.Enabled() {
		return ErrIncomplete
	}
	// 阿里云没有轻量探测接口，用一个必然失败但能区分鉴权的请求做校验：
	// 签名错误返回 InvalidAccessKeyId/SignatureDoesNotMatch，凭据有效则返回参数错误。
	params := map[string]string{
		"Action":           "SendSmsVerifyCode",
		"Version":          "2017-05-25",
		"RegionId":         "cn-hangzhou",
		"PhoneNumber":      "10000000000",
		"SignName":         p.cfg.AliyunSignName,
		"TemplateCode":     p.cfg.AliyunTemplateCode,
		"TemplateParam":    `{"code":"0000"}`,
		"Format":           "JSON",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	body, err := aliyunRPC(ctx, p.endpoint(), p.cfg.AliyunAccessKeyID, p.cfg.AliyunAccessKeySecret, params)
	if err != nil {
		return err
	}
	var resp struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	_ = json.Unmarshal(body, &resp)
	switch resp.Code {
	case "InvalidAccessKeyId.NotFound", "SignatureDoesNotMatch", "InvalidAccessKeyId":
		return fmt.Errorf("aliyun 凭据校验失败：%s %s", resp.Code, resp.Message)
	}
	return nil
}

func (p *aliyunProvider) ConfigPayload() map[string]any {
	return map[string]any{
		"provider":              "aliyun",
		"enabled":               p.Enabled(),
		"aliyunAccessKeyId":     p.cfg.AliyunAccessKeyID,
		"hasAliyunSecret":       p.cfg.AliyunAccessKeySecret != "",
		"aliyunSignName":        p.cfg.AliyunSignName,
		"aliyunTemplateCode":    p.cfg.AliyunTemplateCode,
		"aliyunEndpoint":        p.cfg.AliyunEndpoint,
		"aliyunEndpointDefault": DefaultAliyunEndpoint,
	}
}

// aliyunRPC 执行一次阿里云 RPC 调用并返回响应体。
func aliyunRPC(ctx context.Context, endpoint, accessKeyID, accessKeySecret string, params map[string]string) ([]byte, error) {
	params["AccessKeyId"] = accessKeyID
	// RPC V1 签名：先按参数名排序拼接待签名串，再 HMAC-SHA1 后 Base64。
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteString("&")
		}
		canonical.WriteString(percentEncode(k))
		canonical.WriteString("=")
		canonical.WriteString(percentEncode(params[k]))
	}
	stringToSign := "POST&%2F&" + percentEncode(canonical.String())
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	params["Signature"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
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
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("aliyun http %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// percentEncode 按阿里云 RPC 规范编码（RFC 3986 + 特殊字符替换）。
func percentEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}
