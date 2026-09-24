package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// qimoProvider 对接容联七陌短信（HTTP 网关，JSON 响应）。
type qimoProvider struct{ cfg *Config }

const defaultQimoEndpoint = "https://api.7moor.com/v20160818/sms/send"

func (p *qimoProvider) Name() string { return "qimo" }

func (p *qimoProvider) Enabled() bool {
	c := p.cfg
	return c != nil && c.QimoAccountSID != "" && c.QimoAuthToken != "" &&
		c.QimoAppID != "" && c.QimoTemplate != ""
}

func (p *qimoProvider) Send(ctx context.Context, phone, code string) (string, error) {
	if !p.Enabled() {
		return "", ErrIncomplete
	}
	body := map[string]any{
		"accountId":  p.cfg.QimoAccountSID,
		"appId":      p.cfg.QimoAppID,
		"sign":       p.cfg.SiteName,
		"templateId": p.cfg.QimoTemplate,
		"to":         phone,
		"params":     map[string]string{"code": code},
	}
	payload, _ := json.Marshal(body)
	respBody, err := doJSON(ctx, "POST", defaultQimoEndpoint, payload, map[string]string{
		"Authorization": p.cfg.QimoAuthToken,
	})
	if err != nil {
		return "", err
	}
	var r struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Data    struct {
			MsgID string `json:"msgId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return "", fmt.Errorf("qimo sms parse: %w (%s)", err, string(respBody))
	}
	if r.Code != "" && r.Code != "0" && r.Code != "200" {
		return "", fmt.Errorf("qimo sms rejected: %s %s", r.Code, r.Message)
	}
	return r.Data.MsgID, nil
}

func (p *qimoProvider) TestConnection(ctx context.Context) error {
	if !p.Enabled() {
		return ErrIncomplete
	}
	payload, _ := json.Marshal(map[string]any{"accountId": p.cfg.QimoAccountSID})
	body, err := doJSON(ctx, "POST", defaultQimoEndpoint, payload, map[string]string{
		"Authorization": p.cfg.QimoAuthToken,
	})
	if err != nil {
		return err
	}
	var r struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &r)
	if strings.Contains(strings.ToLower(r.Message), "auth") || r.Code == "401" {
		return fmt.Errorf("qimo 凭据校验失败：%s %s", r.Code, r.Message)
	}
	return nil
}

func (p *qimoProvider) ConfigPayload() map[string]any {
	return map[string]any{
		"provider":       "qimo",
		"enabled":        p.Enabled(),
		"qimoAccountSid": p.cfg.QimoAccountSID,
		"hasQimoToken":   p.cfg.QimoAuthToken != "",
		"qimoAppId":      p.cfg.QimoAppID,
		"qimoTemplateId": p.cfg.QimoTemplate,
	}
}
