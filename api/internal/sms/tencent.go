package sms

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// tencentProvider 对接腾讯云短信（sms.tencentcloudapi.com，TC3-HMAC-SHA256 签名）。
type tencentProvider struct{ cfg *Config }

const defaultTencentEndpoint = "https://sms.tencentcloudapi.com"

func (p *tencentProvider) Name() string { return "tencent" }

func (p *tencentProvider) Enabled() bool {
	c := p.cfg
	return c != nil && c.TencentSecretID != "" && c.TencentSecretKey != "" &&
		c.TencentSdkAppID != "" && c.TencentSignName != "" && c.TencentTemplate != ""
}

func (p *tencentProvider) region() string {
	if strings.TrimSpace(p.cfg.TencentRegion) != "" {
		return strings.TrimSpace(p.cfg.TencentRegion)
	}
	return "ap-guangzhou"
}

func (p *tencentProvider) payload(phone, code string) ([]byte, error) {
	// 腾讯云模板参数为字符串数组，验证码作为第一个占位符。
	body := map[string]any{
		"SmsSdkAppId":      p.cfg.TencentSdkAppID,
		"SignName":         p.cfg.TencentSignName,
		"TemplateId":       p.cfg.TencentTemplate,
		"TemplateParamSet": []string{code},
		"PhoneNumberSet":   []string{"+86" + phone},
	}
	return json.Marshal(body)
}

func (p *tencentProvider) Send(ctx context.Context, phone, code string) (string, error) {
	if !p.Enabled() {
		return "", ErrIncomplete
	}
	payload, err := p.payload(phone, code)
	if err != nil {
		return "", err
	}
	respBody, err := p.do(ctx, payload)
	if err != nil {
		return "", err
	}
	var r struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			SendStatusSet []struct {
				SerialNo string `json:"SerialNo"`
				Code     string `json:"Code"`
				Message  string `json:"Message"`
			} `json:"SendStatusSet"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return "", fmt.Errorf("tencent sms parse: %w (%s)", err, string(respBody))
	}
	if r.Response.Error != nil {
		return "", fmt.Errorf("tencent sms rejected: %s %s", r.Response.Error.Code, r.Response.Error.Message)
	}
	if len(r.Response.SendStatusSet) > 0 {
		st := r.Response.SendStatusSet[0]
		if st.Code != "Ok" {
			return "", fmt.Errorf("tencent sms rejected: %s %s", st.Code, st.Message)
		}
		return st.SerialNo, nil
	}
	return "", nil
}

func (p *tencentProvider) TestConnection(ctx context.Context) error {
	if !p.Enabled() {
		return ErrIncomplete
	}
	payload, _ := p.payload("10000000000", "0000")
	body, err := p.do(ctx, payload)
	if err != nil {
		return err
	}
	var r struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Response.Error != nil {
		switch r.Response.Error.Code {
		case "AuthFailure.SignatureFailure", "AuthFailure.SecretIdNotFound", "AuthFailure.InvalidSecretId":
			return fmt.Errorf("tencent 凭据校验失败：%s %s", r.Response.Error.Code, r.Response.Error.Message)
		}
	}
	return nil
}

func (p *tencentProvider) ConfigPayload() map[string]any {
	return map[string]any{
		"provider":          "tencent",
		"enabled":           p.Enabled(),
		"tencentSecretId":   p.cfg.TencentSecretID,
		"hasTencentSecret":  p.cfg.TencentSecretKey != "",
		"tencentSdkAppId":   p.cfg.TencentSdkAppID,
		"tencentSignName":   p.cfg.TencentSignName,
		"tencentTemplateId": p.cfg.TencentTemplate,
		"tencentRegion":     p.cfg.TencentRegion,
	}
}

func (p *tencentProvider) do(ctx context.Context, payload []byte) ([]byte, error) {
	// TC3-HMAC-SHA256 签名（腾讯云 API 3.0）。
	now := time.Now().UTC()
	date := now.Format("2006-01-02")
	service := "sms"
	host := "sms.tencentcloudapi.com"
	action := "SendSms"
	version := "2021-01-11"

	hashedPayload := sha256hex(payload)
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + host + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := strings.Join([]string{
		http.MethodPost, "/", "", canonicalHeaders, signedHeaders, hashedPayload,
	}, "\n")

	credentialScope := date + "/" + service + "/tc3_request"
	hashedCanonical := sha256hex([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256", now.Format("2006-01-02T15:04:05Z"), credentialScope, hashedCanonical,
	}, "\n")

	secretDate := hmacSHA256([]byte("TC3"+p.cfg.TencentSecretKey), date)
	secretService := hmacSHA256(secretDate, service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	auth := "TC3-HMAC-SHA256 Credential=" + p.cfg.TencentSecretID + "/" + credentialScope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, defaultTencentEndpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", version)
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", now.Unix()))
	req.Header.Set("X-TC-Region", p.region())
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
		return nil, fmt.Errorf("tencent http %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
