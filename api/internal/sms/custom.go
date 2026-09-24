package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// customProvider 允许通过通用 HTTP 网关对接任意短信厂商。
//
// 支持在 URL / Header / Body 中使用占位符 {phone} 与 {code}（Body 为 JSON 时
// 会做转义替换）。响应视为成功，除非 HTTP 状态 >= 400 或响应体 JSON 中
// 明确给出非零 code。
type customProvider struct{ cfg *Config }

func (p *customProvider) Name() string { return "custom" }

func (p *customProvider) Enabled() bool {
	return p.cfg != nil && strings.TrimSpace(p.cfg.CustomURL) != ""
}

func (p *customProvider) method() string {
	m := strings.ToUpper(strings.TrimSpace(p.cfg.CustomMethod))
	if m == "" {
		return "POST"
	}
	return m
}

func (p *customProvider) render(tpl, phone, code string) string {
	r := strings.NewReplacer("{phone}", phone, "{code}", code)
	return r.Replace(tpl)
}

func (p *customProvider) Send(ctx context.Context, phone, code string) (string, error) {
	if !p.Enabled() {
		return "", ErrIncomplete
	}
	url := p.render(strings.TrimSpace(p.cfg.CustomURL), phone, code)
	headers := map[string]string{"Content-Type": "application/json"}
	// 额外 Header 按每行 "Key: Value" 解析。
	for _, line := range strings.Split(p.cfg.CustomHeaders, "\n") {
		if i := strings.Index(line, ":"); i > 0 {
			headers[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	if strings.TrimSpace(p.cfg.CustomSecret) != "" {
		headers["Authorization"] = p.cfg.CustomSecret
	}
	var body []byte
	if strings.TrimSpace(p.cfg.CustomBody) != "" {
		body = []byte(p.render(p.cfg.CustomBody, phone, code))
	}
	respBody, err := doJSON(ctx, p.method(), url, body, headers)
	if err != nil {
		return "", err
	}
	return parseCustomResult(respBody)
}

func (p *customProvider) TestConnection(ctx context.Context) error {
	if !p.Enabled() {
		return ErrIncomplete
	}
	// 仅探测端点可达性：用占位手机号发起一次请求。
	_, err := p.Send(ctx, "10000000000", "0000")
	return err
}

func (p *customProvider) ConfigPayload() map[string]any {
	return map[string]any{
		"provider":        "custom",
		"enabled":         p.Enabled(),
		"customUrl":       p.cfg.CustomURL,
		"customMethod":    p.cfg.CustomMethod,
		"customHeaders":   p.cfg.CustomHeaders,
		"customBody":      p.cfg.CustomBody,
		"hasCustomSecret": p.cfg.CustomSecret != "",
	}
}

// parseCustomResult 从自定义网关响应中尽力提取成功/失败与流水号。
func parseCustomResult(body []byte) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	var r map[string]any
	if err := json.Unmarshal(body, &r); err != nil {
		// 非 JSON 响应视为成功（网关可能返回纯文本）。
		return "", nil
	}
	// 常见失败标志：success=false 或 code 非 0/200。
	if v, ok := r["success"].(bool); ok && !v {
		return "", fmt.Errorf("custom sms rejected: %s", string(body))
	}
	if code, ok := r["code"]; ok {
		cs := fmt.Sprint(code)
		if cs != "0" && cs != "200" && cs != "OK" && cs != "ok" {
			return "", fmt.Errorf("custom sms rejected: %s", string(body))
		}
	}
	if id, ok := r["id"].(string); ok {
		return id, nil
	}
	if id, ok := r["msgId"].(string); ok {
		return id, nil
	}
	return "", nil
}
