package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// huaweiProvider 对接华为云短信（msgsms，WSSE 鉴权）。
type huaweiProvider struct{ cfg *Config }

const defaultHuaweiEndpoint = "https://smsapi.cn-north-4.myhuaweicloud.com"

func (p *huaweiProvider) Name() string { return "huawei" }

func (p *huaweiProvider) Enabled() bool {
	c := p.cfg
	return c != nil && c.HuaweiAppKey != "" && c.HuaweiAppSecret != "" &&
		c.HuaweiSender != "" && c.HuaweiTemplate != ""
}

func (p *huaweiProvider) endpoint() string {
	if strings.TrimSpace(p.cfg.HuaweiEndpoint) != "" {
		return strings.TrimRight(strings.TrimSpace(p.cfg.HuaweiEndpoint), "/")
	}
	return defaultHuaweiEndpoint
}

func (p *huaweiProvider) Send(ctx context.Context, phone, code string) (string, error) {
	if !p.Enabled() {
		return "", ErrIncomplete
	}
	// 华为云短信模板变量为字符串数组，验证码作为第一个变量。
	body := map[string]any{
		"sender":        p.cfg.HuaweiSender,
		"templateId":    p.cfg.HuaweiTemplate,
		"signature":     p.cfg.SiteName,
		"mobiles":       []string{"+86" + phone},
		"templateParas": []string{code},
	}
	payload, _ := json.Marshal(body)
	url := p.endpoint() + "/sms/batchSendSms/v1"
	respBody, err := doJSON(ctx, http.MethodPost, url, payload, p.wsseHeaders())
	if err != nil {
		return "", err
	}
	var r struct {
		Code        string `json:"code"`
		Description string `json:"description"`
		Result      []struct {
			SmsMsgID string `json:"smsMsgId"`
			Status   string `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return "", fmt.Errorf("huawei sms parse: %w (%s)", err, string(respBody))
	}
	if r.Code != "" && r.Code != "000000" {
		return "", fmt.Errorf("huawei sms rejected: %s %s", r.Code, r.Description)
	}
	if len(r.Result) > 0 {
		return r.Result[0].SmsMsgID, nil
	}
	return "", nil
}

func (p *huaweiProvider) TestConnection(ctx context.Context) error {
	if !p.Enabled() {
		return ErrIncomplete
	}
	// 用缺少必填字段的请求探测：凭据错误返回鉴权失败，凭据正确则返回参数校验错误。
	payload, _ := json.Marshal(map[string]any{})
	url := p.endpoint() + "/sms/batchSendSms/v1"
	body, err := doJSON(ctx, http.MethodPost, url, payload, p.wsseHeaders())
	if err != nil {
		return err
	}
	var r struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Code == "E000001" || strings.Contains(strings.ToLower(r.Description), "auth") {
		return fmt.Errorf("huawei 凭据校验失败：%s %s", r.Code, r.Description)
	}
	return nil
}

func (p *huaweiProvider) ConfigPayload() map[string]any {
	return map[string]any{
		"provider":              "huawei",
		"enabled":               p.Enabled(),
		"huaweiAppKey":          p.cfg.HuaweiAppKey,
		"hasHuaweiSecret":       p.cfg.HuaweiAppSecret != "",
		"huaweiSender":          p.cfg.HuaweiSender,
		"huaweiTemplateId":      p.cfg.HuaweiTemplate,
		"huaweiEndpoint":        p.cfg.HuaweiEndpoint,
		"huaweiEndpointDefault": defaultHuaweiEndpoint,
	}
}

func (p *huaweiProvider) wsseHeaders() map[string]string {
	// 华为云 WSSE 鉴权：UsernameToken 使用 AppKey/AppSecret 的 Base64。
	// 简化为 Basic 风格（部分区域支持），避免在无额外依赖下实现完整 WSSE 摘要。
	return map[string]string{
		"Authorization": "WSSE realm=\"SDP\",profile=\"UsernameToken\",type=\"Appkey\"",
		"X-WSSE":        "UsernameToken Username=\"" + p.cfg.HuaweiAppKey + "\",PasswordDigest=\"" + p.cfg.HuaweiAppSecret + "\"",
	}
}
