package handler

import (
	"errors"
	"net/url"
	"strings"

	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oauth2"
)

// 登录提供商的端点配置校验。
//
// 背景：端点在初始化时按内置注册表写入数据库，管理员可在后台查看并修改
// （如自建的反代地址、企业内网的 OAuth2 网关，或平台改了域名）。
// 这些地址有两个使用方：
//  1. 授权地址被拼进浏览器跳转（302）；
//  2. 令牌 / 用户信息 / openid 地址由服务端发起出站请求。
//
// 因此不能只做 TrimSpace：javascript: / data: 之类的取值会被交给浏览器执行，
// file:// 会让服务端去读本机文件。统一按「http/https 绝对地址」校验。

// providerEndpointMaxLen 限制单个端点地址长度，避免超长取值落库后
// 在出站请求、日志与后台界面上造成无谓开销。
const providerEndpointMaxLen = 500

// sanitizeProviderEndpoint 归一化提供商端点地址。
// 空串是合法取值（表示「未覆盖」，调用方按内置默认值回落）；
// 返回的 bool 为 false 表示填写了非法值，调用方应拒绝保存。
func sanitizeProviderEndpoint(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", true
	}
	if len(v) > providerEndpointMaxLen {
		return "", false
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if u.Host == "" {
		return "", false
	}
	// 端点里不允许出现控制字符（换行会导致出站请求头注入）。
	if strings.ContainsAny(v, "\r\n\t") {
		return "", false
	}
	return v, true
}

// providerScopesMaxCount 限制单个提供商的权限项数量。
const providerScopesMaxCount = 64

// sanitizeProviderScopes 归一化权限范围（Scope）列表：去空白、去重、拒绝空项。
// Scope 会拼进授权 URL 的 scope 参数（空格分隔），故不允许包含空白或控制字符。
func sanitizeProviderScopes(in []string) ([]string, bool) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(s) > 128 || strings.ContainsAny(s, " \t\r\n") {
			return nil, false
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) > providerScopesMaxCount {
		return nil, false
	}
	return out, true
}

// effectiveProviderEndpoints 返回「保存后真正生效」的端点：
// 数据库取值优先，为空时回落到内置默认值（与 resolveProvider 口径一致）。
func effectiveProviderEndpoints(p *models.OAuthProvider) (authorize, token, userInfo string) {
	authorize, token, userInfo = strings.TrimSpace(p.AuthorizeURL), strings.TrimSpace(p.TokenURL), strings.TrimSpace(p.UserInfoURL)
	if def, ok := oauth2.Get(p.ProviderType); ok {
		if authorize == "" {
			authorize = def.AuthorizeURL
		}
		if token == "" {
			token = def.TokenURL
		}
		if userInfo == "" {
			userInfo = def.UserInfoURL
		}
	}
	return authorize, token, userInfo
}

// validateProviderEndpoints 校验保存后仍可完成一次第三方登录。
//
// 三个核心端点（授权 / 令牌 / 用户信息）缺一即无法登录：授权地址缺失时用户点进去
// 就是空白页，令牌地址缺失时授权码永远换不到令牌。与其存下一个必然失败的配置，
// 不如在保存时就明确拒绝。
func validateProviderEndpoints(p *models.OAuthProvider) error {
	authorize, token, userInfo := effectiveProviderEndpoints(p)
	if authorize == "" || token == "" || userInfo == "" {
		return errors.New("授权、令牌与用户信息地址均不能为空")
	}
	return nil
}
