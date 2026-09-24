// Package sms 提供一个可扩展的短信验证码服务抽象层。
//
// 设计对齐 internal/captcha：把「配置、发送、测试连接、下发字段」收敛到统一的
// Provider 接口，新增服务商只需实现接口并在注册表登记，避免把各厂商的签名/
// 请求格式散落到业务代码里。
//
// 短信验证码只用于「手机号归属验证」（不发手机号登录）：OpenIdP 生成验证码 → 调用
// 服务商下发 → 用户回填 → OpenIdP 校验。服务商只负责送达，校验在本地完成。
package sms

import (
	"context"
	"errors"
	"strings"
)

// Provider 是统一的短信服务商抽象。
type Provider interface {
	// Name 返回提供商标识（aliyun / tencent / ... / custom）。
	Name() string
	// Enabled 报告该服务商是否已配置可用。
	Enabled() bool
	// Send 发送一条短信验证码到 phone。返回服务商流水号（可空）。
	Send(ctx context.Context, phone, code string) (string, error)
	// TestConnection 用当前配置探测服务商连通性与凭据有效性。
	TestConnection(ctx context.Context) error
	// ConfigPayload 下发给管理后台的字段定义（用于动态渲染表单）。
	ConfigPayload() map[string]any
}

// Config 是短信服务的运行时配置（由管理后台持久化后注入）。
type Config struct {
	// Enabled 总开关：关闭时任何发送请求都会被拒绝。
	Enabled bool
	// Provider 当前启用的服务商标识。
	Provider string
	// SiteName 短信签名/应用名。
	SiteName string
	// CodeTTL 验证码有效期（分钟）。
	CodeTTL int
	// Cooldown 发送冷却（秒）。
	Cooldown int

	// 阿里云号码认证服务。
	AliyunAccessKeyID     string
	AliyunAccessKeySecret string
	AliyunSignName        string
	AliyunTemplateCode    string
	AliyunEndpoint        string

	// 腾讯云短信。
	TencentSecretID  string
	TencentSecretKey string
	TencentSdkAppID  string
	TencentSignName  string
	TencentTemplate  string
	TencentRegion    string

	// 火山引擎短信。
	VolcAccessKeyID     string
	VolcAccessKeySecret string
	VolcSmsAccount      string
	VolcSign            string
	VolcTemplateID      string
	VolcRegion          string

	// 华为云短信。
	HuaweiAppKey    string
	HuaweiAppSecret string
	HuaweiSender    string
	HuaweiTemplate  string
	HuaweiEndpoint  string

	// 容联七陌。
	QimoAccountSID string
	QimoAuthToken  string
	QimoAppID      string
	QimoTemplate   string

	// SUBMAIL。
	SubmailAppID    string
	SubmailAppKey   string
	SubmailSign     string
	SubmailTemplate string

	// 自定义 HTTP 网关。
	CustomURL     string
	CustomMethod  string
	CustomHeaders string
	CustomBody    string
	CustomSecret  string
}

// Errors
var (
	// ErrNotConfigured 表示短信服务未配置或未启用。
	ErrNotConfigured = errors.New("sms not configured")
	// ErrIncomplete 表示当前服务商的必填配置不完整。
	ErrIncomplete = errors.New("sms provider config incomplete")
	// ErrInvalidPhone 表示手机号格式不合法。
	ErrInvalidPhone = errors.New("invalid phone number")
)

// NormalizePhone 归一化手机号：去掉空格、连字符与 + 号前缀，保留纯数字。
//
// 当前仅支持中国大陆 11 位手机号（1 开头）；国际号码需服务商支持且配置模板
// 适配，故此处显式拒绝，避免把明显非法的号码交给服务商计费。
func NormalizePhone(phone string) (string, bool) {
	p := strings.TrimSpace(phone)
	p = strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(p)
	p = strings.TrimPrefix(p, "+86")
	p = strings.TrimPrefix(p, "86")
	for _, r := range p {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	if len(p) != 11 || p[0] != '1' {
		return "", false
	}
	return p, true
}

// NewProvider 按配置挑选服务商。未启用或未指定服务商时返回 noopProvider。
func NewProvider(c *Config) Provider {
	if c == nil || !c.Enabled {
		return noopProvider{}
	}
	switch strings.TrimSpace(c.Provider) {
	case "aliyun":
		return &aliyunProvider{cfg: c}
	case "tencent":
		return &tencentProvider{cfg: c}
	case "volcengine":
		return &volcProvider{cfg: c}
	case "huawei":
		return &huaweiProvider{cfg: c}
	case "qimo":
		return &qimoProvider{cfg: c}
	case "submail":
		return &submailProvider{cfg: c}
	case "custom":
		return &customProvider{cfg: c}
	default:
		return noopProvider{}
	}
}

// noopProvider 是未配置短信服务时的空实现。
type noopProvider struct{}

func (noopProvider) Name() string  { return "none" }
func (noopProvider) Enabled() bool { return false }
func (noopProvider) Send(context.Context, string, string) (string, error) {
	return "", ErrNotConfigured
}
func (noopProvider) TestConnection(context.Context) error { return ErrNotConfigured }
func (noopProvider) ConfigPayload() map[string]any {
	return map[string]any{"enabled": false, "provider": "none"}
}

// Providers 返回内置服务商的元信息（标识 + 名称），供管理后台渲染下拉窗口。
func Providers() []map[string]string {
	return []map[string]string{
		{"provider": "none", "name": "sms.provider.none"},
		{"provider": "aliyun", "name": "Aliyun PNVS"},
		{"provider": "tencent", "name": "Tencent Cloud SMS"},
		{"provider": "volcengine", "name": "Volcengine SMS"},
		{"provider": "huawei", "name": "Huawei Cloud SMS"},
		{"provider": "qimo", "name": "Qimo SMS"},
		{"provider": "submail", "name": "SUBMAIL"},
		{"provider": "custom", "name": "Custom HTTP"},
	}
}
