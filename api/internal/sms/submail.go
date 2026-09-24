package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// submailProvider 对接 SUBMAIL 短信（MSSEND 接口，表单提交）。
type submailProvider struct{ cfg *Config }

const defaultSubmailEndpoint = "https://api.mysubmail.com/message/xsend"

func (p *submailProvider) Name() string { return "submail" }

func (p *submailProvider) Enabled() bool {
	c := p.cfg
	return c != nil && c.SubmailAppID != "" && c.SubmailAppKey != "" &&
		c.SubmailSign != "" && c.SubmailTemplate != ""
}

func (p *submailProvider) Send(ctx context.Context, phone, code string) (string, error) {
	if !p.Enabled() {
		return "", ErrIncomplete
	}
	form := url.Values{}
	form.Set("appid", p.cfg.SubmailAppID)
	form.Set("signature", p.cfg.SubmailAppKey)
	form.Set("to", phone)
	form.Set("project", p.cfg.SubmailTemplate)
	form.Set("sign", p.cfg.SubmailSign)
	// SUBMAIL 的 vars 为 JSON 字符串。
	form.Set("vars", fmt.Sprintf(`{"code":"%s"}`, code))

	respBody, err := doForm(ctx, "POST", defaultSubmailEndpoint, form, map[string]string{"Accept": "application/json"})
	if err != nil {
		return "", err
	}
	var r struct {
		Status string          `json:"status"`
		Msg    string          `json:"msg"`
		SendID json.RawMessage `json:"send_id"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return "", fmt.Errorf("submail sms parse: %w (%s)", err, string(respBody))
	}
	if r.Status != "success" {
		return "", fmt.Errorf("submail sms rejected: %s %s", r.Status, r.Msg)
	}
	return strings.Trim(string(r.SendID), `"`), nil
}

func (p *submailProvider) TestConnection(ctx context.Context) error {
	if !p.Enabled() {
		return ErrIncomplete
	}
	form := url.Values{}
	form.Set("appid", p.cfg.SubmailAppID)
	form.Set("signature", p.cfg.SubmailAppKey)
	body, err := doForm(ctx, "POST", defaultSubmailEndpoint, form, map[string]string{"Accept": "application/json"})
	if err != nil {
		return err
	}
	var r struct {
		Status string `json:"status"`
		Code   any    `json:"code"`
		Msg    string `json:"msg"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Status != "" && r.Status != "success" {
		low := strings.ToLower(r.Msg)
		if strings.Contains(low, "auth") || strings.Contains(low, "appid") || strings.Contains(low, "signature") {
			return fmt.Errorf("submail 凭据校验失败：%s %s", r.Status, r.Msg)
		}
	}
	return nil
}

func (p *submailProvider) ConfigPayload() map[string]any {
	return map[string]any{
		"provider":          "submail",
		"enabled":           p.Enabled(),
		"submailAppId":      p.cfg.SubmailAppID,
		"hasSubmailKey":     p.cfg.SubmailAppKey != "",
		"submailSign":       p.cfg.SubmailSign,
		"submailTemplateId": p.cfg.SubmailTemplate,
	}
}
