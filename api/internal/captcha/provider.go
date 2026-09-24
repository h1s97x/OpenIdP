package captcha

import (
	"context"
	"errors"
	"strings"
)

// Flow 标识需要人机验证的业务流程。
type Flow string

const (
	FlowLogin         Flow = "login"
	FlowSignup        Flow = "signup"
	FlowPasswordReset Flow = "passwordReset"
)

// ErrNotProof 表示客户端没有提交人机验证证明（与"校验被拒绝"区分）。
var ErrNotProof = errors.New("captcha required")

// Proof 是客户端提交的统一人机验证负载：
// Turnstile 场景携带 token，极验场景携带 v4 证明。
type Proof struct {
	Captcha   *Captcha `json:"captcha,omitempty"`
	Turnstile string   `json:"turnstile,omitempty"`
}

// Provider 是统一的人机验证抽象（极验 / Cloudflare Turnstile 各一份实现）。
// 收敛"是否要求验证""校验""下发配置"三件事，新增提供商只需实现本接口。
type Provider interface {
	// Name 返回提供商标识（turnstile / geetest / none）。
	Name() string
	// Enabled 报告该提供商是否已配置可用。
	Enabled() bool
	// Required 报告给定流程是否要求人机验证。
	Required(flow Flow) bool
	// Verify 校验客户端证明；未配置时返回 ErrNotConfigured。
	Verify(ctx context.Context, p *Proof, remoteIP string) (bool, error)
	// ConfigPayload 下发给前端的渲染配置。
	ConfigPayload() map[string]any
}

// geetestProvider 把 *Config 适配成 Provider。
type geetestProvider struct{ cfg *Config }

func (g geetestProvider) Name() string { return "geetest" }

func (g geetestProvider) Enabled() bool { return g.cfg != nil && g.cfg.Enabled }

func (g geetestProvider) Required(flow Flow) bool {
	if g.cfg == nil {
		return false
	}
	switch flow {
	case FlowLogin:
		return g.cfg.RequiredForLogin
	case FlowSignup:
		return g.cfg.RequiredForSignup
	case FlowPasswordReset:
		return g.cfg.RequiredForPasswordReset
	}
	return false
}

func (g geetestProvider) Verify(ctx context.Context, p *Proof, _ string) (bool, error) {
	if g.cfg == nil {
		return false, ErrNotConfigured
	}
	if p == nil || p.Captcha == nil || !p.Captcha.Valid() {
		return false, ErrNotProof
	}
	return g.cfg.Verify(ctx, p.Captcha)
}

func (g geetestProvider) ConfigPayload() map[string]any { return g.cfg.CaptchaConfigPayload() }

// turnstileProvider 把 *TurnstileConfig 适配成 Provider。
type turnstileProvider struct{ cfg *TurnstileConfig }

func (t turnstileProvider) Name() string { return "turnstile" }

func (t turnstileProvider) Enabled() bool { return t.cfg != nil && t.cfg.Enabled }

func (t turnstileProvider) Required(flow Flow) bool {
	if t.cfg == nil {
		return false
	}
	switch flow {
	case FlowLogin:
		return t.cfg.RequiredForLogin
	case FlowSignup:
		return t.cfg.RequiredForSignup
	case FlowPasswordReset:
		return t.cfg.RequiredForPasswordReset
	}
	return false
}

func (t turnstileProvider) Verify(ctx context.Context, p *Proof, remoteIP string) (bool, error) {
	if t.cfg == nil {
		return false, ErrNotConfigured
	}
	if p == nil || strings.TrimSpace(p.Turnstile) == "" {
		return false, ErrNotProof
	}
	return t.cfg.Verify(ctx, p.Turnstile, remoteIP)
}

func (t turnstileProvider) ConfigPayload() map[string]any { return t.cfg.CaptchaConfigPayload() }

// noopProvider 是未配置人机验证时的空实现。
type noopProvider struct{}

func (noopProvider) Name() string                                         { return "none" }
func (noopProvider) Enabled() bool                                        { return false }
func (noopProvider) Required(Flow) bool                                   { return false }
func (noopProvider) Verify(context.Context, *Proof, string) (bool, error) { return true, nil }
func (noopProvider) ConfigPayload() map[string]any {
	return map[string]any{"enabled": false, "provider": "none"}
}

// NewProvider 按已配置的凭据挑选提供商：Turnstile 优先，其次极验，都没有则为空实现。
func NewProvider(geetest *Config, turnstile *TurnstileConfig) Provider {
	if turnstile != nil && turnstile.Enabled {
		return turnstileProvider{cfg: turnstile}
	}
	if geetest != nil && geetest.Enabled {
		return geetestProvider{cfg: geetest}
	}
	return noopProvider{}
}

// IsNotProof 报告错误是否表示"尚未提交人机验证证明"。
func IsNotProof(err error) bool { return errors.Is(err, ErrNotProof) }
