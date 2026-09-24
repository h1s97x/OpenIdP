package sms

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// volcProvider 对接火山引擎短信（OpenAPI V4 签名）。
type volcProvider struct{ cfg *Config }

const defaultVolcEndpoint = "https://sms.volcengineapi.com"

func (p *volcProvider) Name() string { return "volcengine" }

func (p *volcProvider) Enabled() bool {
	c := p.cfg
	return c != nil && c.VolcAccessKeyID != "" && c.VolcAccessKeySecret != "" &&
		c.VolcSmsAccount != "" && c.VolcSign != "" && c.VolcTemplateID != ""
}

func (p *volcProvider) region() string {
	if strings.TrimSpace(p.cfg.VolcRegion) != "" {
		return strings.TrimSpace(p.cfg.VolcRegion)
	}
	return "cn-north-1"
}

func (p *volcProvider) Send(ctx context.Context, phone, code string) (string, error) {
	if !p.Enabled() {
		return "", ErrIncomplete
	}
	// 火山短信使用 GET 传入查询参数，模板参数为 JSON 字符串。
	q := "Action=SendSms&Version=2020-01-01&" + strings.Join([]string{
		"SmsAccount=" + p.cfg.VolcSmsAccount,
		"Sign=" + p.cfg.VolcSign,
		"TemplateId=" + p.cfg.VolcTemplateID,
		"PhoneNumbers=" + phone,
		"TemplateParam=" + fmt.Sprintf(`{"code":"%s"}`, code),
	}, "&")
	body, err := p.do(ctx, "/", q)
	if err != nil {
		return "", err
	}
	var resp struct {
		ResponseMetadata struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			RequestID string `json:"RequestId"`
		} `json:"ResponseMetadata"`
		Result struct {
			MessageID []string `json:"MessageID"`
		} `json:"Result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("volc sms parse: %w (%s)", err, string(body))
	}
	if resp.ResponseMetadata.Error != nil {
		return "", fmt.Errorf("volc sms rejected: %s %s", resp.ResponseMetadata.Error.Code, resp.ResponseMetadata.Error.Message)
	}
	if len(resp.Result.MessageID) > 0 {
		return resp.Result.MessageID[0], nil
	}
	return "", nil
}

func (p *volcProvider) TestConnection(ctx context.Context) error {
	if !p.Enabled() {
		return ErrIncomplete
	}
	body, err := p.do(ctx, "/", "Action=SendSms&Version=2020-01-01&SmsAccount="+p.cfg.VolcSmsAccount)
	if err != nil {
		return err
	}
	var resp struct {
		ResponseMetadata struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"ResponseMetadata"`
	}
	_ = json.Unmarshal(body, &resp)
	if resp.ResponseMetadata.Error != nil {
		switch resp.ResponseMetadata.Error.Code {
		case "SignatureDoesNotMatch", "InvalidAccessKey", "InvalidAccessKeyId":
			return fmt.Errorf("volc 凭据校验失败：%s %s", resp.ResponseMetadata.Error.Code, resp.ResponseMetadata.Error.Message)
		}
	}
	return nil
}

func (p *volcProvider) ConfigPayload() map[string]any {
	return map[string]any{
		"provider":        "volcengine",
		"enabled":         p.Enabled(),
		"volcAccessKeyId": p.cfg.VolcAccessKeyID,
		"hasVolcSecret":   p.cfg.VolcAccessKeySecret != "",
		"volcSmsAccount":  p.cfg.VolcSmsAccount,
		"volcSign":        p.cfg.VolcSign,
		"volcTemplateId":  p.cfg.VolcTemplateID,
		"volcRegion":      p.cfg.VolcRegion,
	}
}

// do 以火山引擎 OpenAPI V4（HMAC-SHA256）签名发起 GET 请求。
func (p *volcProvider) do(ctx context.Context, path, query string) ([]byte, error) {
	host := "sms.volcengineapi.com"
	service := "volcSMS"
	now := time.Now().UTC()
	date := now.Format("20060102")
	xDate := now.Format("20060102T150405Z")
	credentialScope := date + "/" + p.region() + "/" + service + "/request"

	// 规范化查询串：按参数名排序（这里直接沿用传入顺序后再排序）。
	q := strings.TrimPrefix(query, "?")
	canonicalQuery := canonicalizeQuery(q)
	hashedPayload := sha256hex([]byte(""))

	canonicalHeaders := "host:" + host + "\n" +
		"x-content-sha256:" + hashedPayload + "\n" +
		"x-date:" + xDate + "\n"
	signedHeaders := "host;x-content-sha256;x-date"

	canonicalRequest := strings.Join([]string{
		http.MethodGet, path, canonicalQuery, canonicalHeaders, signedHeaders, hashedPayload,
	}, "\n")

	stringToSign := strings.Join([]string{
		"HMAC-SHA256", xDate, credentialScope, sha256hex([]byte(canonicalRequest)),
	}, "\n")

	secretDate := hmacSHA256([]byte(p.cfg.VolcAccessKeySecret), date)
	secretRegion := hmacSHA256(secretDate, p.region())
	secretService := hmacSHA256(secretRegion, service)
	secretSigning := hmacSHA256(secretService, "request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	auth := "HMAC-SHA256 Credential=" + p.cfg.VolcAccessKeyID + "/" + credentialScope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultVolcEndpoint+path+"?"+q, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Host", host)
	req.Header.Set("X-Date", xDate)
	req.Header.Set("X-Content-Sha256", hashedPayload)
	req.Header.Set("Authorization", auth)

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
		return nil, fmt.Errorf("volc http %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// canonicalizeQuery 对查询串按参数名排序并规范编码（火山 V4 要求）。
func canonicalizeQuery(q string) string {
	if q == "" {
		return ""
	}
	parts := strings.Split(q, "&")
	encoded := make([]string, 0, len(parts))
	for _, kv := range parts {
		i := strings.Index(kv, "=")
		if i < 0 {
			continue
		}
		k, v := kv[:i], kv[i+1:]
		encoded = append(encoded, percentEncode(k)+"="+percentEncode(v))
	}
	sortStrings(encoded)
	return strings.Join(encoded, "&")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// base64Encode 保留给需要 body 签名的服务商使用。
func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
