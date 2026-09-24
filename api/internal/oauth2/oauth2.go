// Package oauth2 implements the built-in third-party login providers
// (GitHub / Google / Microsoft / QQ / Gitee / LinuxDo) plus generic custom
// OAuth2 providers constructed from database configuration.
//
// Each provider exposes the standard Authorization Code flow. The authorize
// and token endpoints, plus the profile/userinfo parsing, are declared in the
// registry so new providers can be added with a single struct.
package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
)

// Provider is a built-in third-party OAuth provider definition.
type Provider struct {
	Type         string // github / google / microsoft / qq / gitee / linuxdo / custom
	Name         string // display name
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	// OpenIDURL 是仅某些提供商（如 QQ）用于换取唯一 openid 的额外接口。
	// 其 token 响应并不返回 openid，需单独调用 /oauth2.0/me 获取。
	OpenIDURL string
	// DocsURL is a link to the official documentation / app-registration console,
	// shown in the admin provider config panel so admins know where to apply.
	DocsURL string
	// Custom marks a user-defined OAuth2 provider (endpoints configured by admin).
	Custom bool
	// HTTPClient 为该提供商出站请求使用的 HTTP 客户端（可携带代理）。
	// 为 nil 时使用默认直连客户端。由 Handler 按「提供商是否开启使用代理」注入。
	HTTPClient *http.Client
	// ParseUserInfo converts the provider profile response to a normalized Profile.
	ParseUserInfo func(data []byte) (*Profile, error)
}

// client 返回本次出站请求使用的 HTTP 客户端。
func (p *Provider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Profile is the normalized third-party user profile.
type Profile struct {
	Provider      string `json:"provider"`
	ProviderUID   string `json:"providerUid"`
	DisplayName   string `json:"displayName"`
	AvatarURL     string `json:"avatarUrl"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
}

// Credentials is a configured provider instance with client ID/appcrypto.
type Credentials struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// Registry contains all built-in providers.
var Registry = map[string]*Provider{}

func register(p *Provider) { Registry[p.Type] = p }

func init() {
	register(&Provider{
		Type: "github", Name: "Github",
		AuthorizeURL: "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		Scopes:       []string{"read:user", "user:email"},
		DocsURL:      "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
		ParseUserInfo: func(data []byte) (*Profile, error) {
			var d struct {
				ID        int64  `json:"id"`
				Login     string `json:"login"`
				Name      string `json:"name"`
				AvatarURL string `json:"avatar_url"`
				Email     string `json:"email"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, err
			}
			if d.ID == 0 {
				return nil, errors.New("github: empty profile")
			}
			return &Profile{
				Provider: "github", ProviderUID: fmt.Sprintf("%d", d.ID),
				DisplayName: auth.FirstNonEmpty(d.Name, d.Login), AvatarURL: d.AvatarURL, Email: d.Email,
				// GitHub /user 接口返回的是公开邮箱，不保证已通过平台验证，
				// 不标记 EmailVerified，避免伪造未认证邮箱自动关联到他人账号。
			}, nil
		},
	})
	register(&Provider{
		Type: "google", Name: "Google",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
		DocsURL:      "https://console.cloud.google.com/apis/credentials",
		ParseUserInfo: func(data []byte) (*Profile, error) {
			var d struct {
				Sub           string `json:"sub"`
				Name          string `json:"name"`
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
				Picture       string `json:"picture"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, err
			}
			if d.Sub == "" {
				return nil, errors.New("google: empty profile")
			}
			return &Profile{
				Provider: "google", ProviderUID: d.Sub, DisplayName: d.Name,
				AvatarURL: d.Picture, Email: d.Email, EmailVerified: d.EmailVerified,
			}, nil
		},
	})
	register(&Provider{
		Type: "microsoft", Name: "Microsoft",
		AuthorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/oidc/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
		DocsURL:      "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow",
		ParseUserInfo: func(data []byte) (*Profile, error) {
			var d struct {
				Sub           string `json:"sub"`
				Name          string `json:"name"`
				Email         string `json:"email"`
				PreferredName string `json:"preferred_username"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, err
			}
			if d.Sub == "" {
				return nil, errors.New("microsoft: empty profile")
			}
			return &Profile{
				Provider: "microsoft", ProviderUID: d.Sub,
				DisplayName: auth.FirstNonEmpty(d.Name, d.PreferredName), Email: auth.FirstNonEmpty(d.Email, d.PreferredName),
				EmailVerified: true,
			}, nil
		},
	})
	register(&Provider{
		Type: "qq", Name: "QQ",
		AuthorizeURL: "https://graph.qq.com/oauth2.0/authorize",
		TokenURL:     "https://graph.qq.com/oauth2.0/token",
		UserInfoURL:  "https://graph.qq.com/user/get_user_info",
		// QQ 的 token 响应不含 openid，需额外调用 /oauth2.0/me 换取。
		OpenIDURL: "https://graph.qq.com/oauth2.0/me",
		Scopes:    []string{"get_user_info"},
		DocsURL:   "https://connect.qq.com/",
		ParseUserInfo: func(data []byte) (*Profile, error) {
			var d struct {
				Ret      int    `json:"ret"`
				Nickname string `json:"nickname"`
				Avatar   string `json:"figureurl_qq_2"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, err
			}
			if d.Ret != 0 {
				return nil, errors.New("qq: profile error")
			}
			return &Profile{Provider: "qq", DisplayName: d.Nickname, AvatarURL: d.Avatar}, nil
		},
	})
	register(&Provider{
		Type: "gitee", Name: "Gitee",
		AuthorizeURL: "https://gitee.com/oauth/authorize",
		TokenURL:     "https://gitee.com/oauth/token",
		UserInfoURL:  "https://gitee.com/api/v5/user",
		Scopes:       []string{"user_info"},
		DocsURL:      "https://gitee.com/oauth/applications",
		ParseUserInfo: func(data []byte) (*Profile, error) {
			var d struct {
				ID        int64  `json:"id"`
				Name      string `json:"name"`
				Login     string `json:"login"`
				AvatarURL string `json:"avatar_url"`
				Email     string `json:"email"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, err
			}
			if d.ID == 0 {
				return nil, errors.New("gitee: empty profile")
			}
			return &Profile{
				Provider: "gitee", ProviderUID: fmt.Sprintf("%d", d.ID),
				DisplayName: auth.FirstNonEmpty(d.Name, d.Login), AvatarURL: d.AvatarURL, Email: d.Email,
				// Gitee /user 邮箱不保证已通过平台验证，不标记 EmailVerified。
			}, nil
		},
	})
	register(&Provider{
		Type: "linuxdo", Name: "LinuxDo",
		AuthorizeURL: "https://connect.linux.do/oauth2/authorize",
		TokenURL:     "https://connect.linux.do/oauth2/token",
		UserInfoURL:  "https://connect.linux.do/api/user",
		Scopes:       []string{"read"},
		DocsURL:      "https://connect.linux.do/",
		ParseUserInfo: func(data []byte) (*Profile, error) {
			var d struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Avatar   string `json:"avatar_template"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, err
			}
			if d.ID == 0 {
				return nil, errors.New("linuxdo: empty profile")
			}
			return &Profile{
				Provider: "linuxdo", ProviderUID: fmt.Sprintf("%d", d.ID),
				DisplayName: auth.FirstNonEmpty(d.Name, d.Username), AvatarURL: d.Avatar,
			}, nil
		},
	})
}

// Get returns a registered provider by type.
func Get(providerType string) (*Provider, bool) {
	p, ok := Registry[providerType]
	return p, ok
}

// NewCustomProvider builds a user-defined OAuth2 provider from admin-configured
// endpoints. It uses a generic userinfo parser that reads common fields
// (sub/id, name, email, email_verified, picture/avatar_url) so any standard
// OAuth2 provider can be integrated without code changes.
func NewCustomProvider(providerType, name, authorizeURL, tokenURL, userInfoURL string, scopes []string) *Provider {
	return &Provider{
		Type:         providerType,
		Name:         name,
		AuthorizeURL: authorizeURL,
		TokenURL:     tokenURL,
		UserInfoURL:  userInfoURL,
		Scopes:       scopes,
		Custom:       true,
		ParseUserInfo: func(data []byte) (*Profile, error) {
			var d struct {
				Sub           string `json:"sub"`
				ID            any    `json:"id"`
				Name          string `json:"name"`
				Login         string `json:"login"`
				Email         string `json:"email"`
				EmailVerified any    `json:"email_verified"`
				Picture       string `json:"picture"`
				AvatarURL     string `json:"avatar_url"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, err
			}
			uid := d.Sub
			if uid == "" {
				switch v := d.ID.(type) {
				case string:
					uid = v
				case float64:
					uid = fmt.Sprintf("%.0f", v)
				}
			}
			if uid == "" {
				return nil, errors.New("custom oauth: missing sub/id in userinfo")
			}
			verified := false
			switch v := d.EmailVerified.(type) {
			case bool:
				verified = v
			case string:
				verified = v == "true" || v == "1"
			}
			return &Profile{
				Provider:      providerType,
				ProviderUID:   uid,
				DisplayName:   auth.FirstNonEmpty(d.Name, d.Login, uid),
				AvatarURL:     auth.FirstNonEmpty(d.Picture, d.AvatarURL),
				Email:         d.Email,
				EmailVerified: verified,
			}, nil
		},
	}
}

// BuildAuthorizeURL builds the provider's authorize URL.
func (p *Provider) BuildAuthorizeURL(cred *Credentials, state, codeChallenge, returnURL string) string {
	q := url.Values{}
	q.Set("client_id", cred.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", cred.RedirectURL)
	q.Set("state", state)
	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, " "))
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	if returnURL != "" {
		q.Set("return_url", returnURL)
	}
	sep := "?"
	if strings.Contains(p.AuthorizeURL, "?") {
		sep = "&"
	}
	return p.AuthorizeURL + sep + q.Encode()
}

// ExchangeCode exchanges an authorization code for an access token.
//
// 返回 (access_token, extra, err)。其中 extra 携带 QQ/微信在 token 响应中返回的
// openid/unionid（用于唯一标识用户），其它提供商为空。
func (p *Provider) ExchangeCode(ctx context.Context, cred *Credentials, code string) (string, url.Values, error) {
	form := url.Values{}
	form.Set("client_id", cred.ClientID)
	form.Set("client_secret", cred.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", cred.RedirectURL)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := p.client()
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	extra := url.Values{}
	// 保留 client_id 供后续 userinfo（QQ 需要 oauth_consumer_key）与 openid 换取使用。
	extra.Set("client_id", cred.ClientID)
	// Some providers (GitHub, QQ) return form-encoded tokens.
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(body))
		if err == nil {
			if tok := vals.Get("access_token"); tok != "" {
				// QQ/微信 的 openid/unionid 会随 token 一起返回，需保留用于唯一标识用户。
				extra.Set("openid", vals.Get("openid"))
				extra.Set("unionid", vals.Get("unionid"))
				return tok, extra, nil
			}
			return "", nil, errors.New(vals.Get("error_description") + " " + vals.Get("error"))
		}
	}
	var d struct {
		AccessToken string `json:"access_token"`
		OpenID      string `json:"openid"`
		UnionID     string `json:"unionid"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return "", nil, err
	}
	if d.AccessToken == "" {
		return "", nil, errors.New(auth.FirstNonEmpty(d.Description, d.Error, "exchange failed"))
	}
	extra.Set("openid", d.OpenID)
	extra.Set("unionid", d.UnionID)
	return d.AccessToken, extra, nil
}

// FetchProfile fetches and parses the provider profile with the access token.
func (p *Provider) FetchProfile(ctx context.Context, accessToken string, extra url.Values) (*Profile, error) {
	// QQ/微信：先确保拿到唯一 openid。QQ 的 token 响应不含 openid，需额外调用
	// /oauth2.0/me 获取（其返回 JSONP：callback({...})），否则不同用户会串号。
	if p.Type == "qq" && extra.Get("openid") == "" && p.OpenIDURL != "" {
		if openid, err := p.fetchQQOpenID(ctx, accessToken); err != nil {
			return nil, err
		} else {
			extra.Set("openid", openid)
		}
	}

	u := p.UserInfoURL
	if p.Type == "qq" {
		// QQ 需要 openid/access_token 参数
		q := extra
		if q == nil {
			q = url.Values{}
		}
		q.Set("access_token", accessToken)
		// QQ userinfo 还要求 oauth_consumer_key（即 appid/client_id）。
		q.Set("oauth_consumer_key", extra.Get("client_id"))
		q.Set("openid", extra.Get("openid"))
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u = u + sep + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if p.Type == "github" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("User-Agent", "openidp")
		req.Header.Set("Accept", "application/vnd.github+json")
	} else if p.Type != "qq" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	client := p.client()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d: %s", p.Type, resp.StatusCode, string(body))
	}
	profile, err := p.ParseUserInfo(body)
	if err != nil {
		return nil, err
	}
	// QQ：ProviderUID 依赖 openid/unionid（ExchangeCode 或 fetchQQOpenID 已把其放入
	// extra），在此回填，确保不同用户使用各自唯一标识，而不是空串导致串号。
	if p.Type == "qq" {
		if profile.ProviderUID == "" {
			profile.ProviderUID = auth.FirstNonEmpty(extra.Get("unionid"), extra.Get("openid"))
		}
		if profile.ProviderUID == "" {
			return nil, errors.New(p.Type + ": missing openid in token response")
		}
	}
	return profile, nil
}

// fetchQQOpenID 调用 QQ 的 /oauth2.0/me 接口换取唯一 openid。
// QQ 的 token 响应并不包含 openid，必须用 access_token 单独换取；其返回体是
// JSONP 形式 `callback( {"client_id":"...","openid":"..."} );`，需要剥掉包裹。
func (p *Provider) fetchQQOpenID(ctx context.Context, accessToken string) (string, error) {
	u := p.OpenIDURL + "?access_token=" + url.QueryEscape(accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	client := p.client()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("qq: fetch openid: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("qq: openid HTTP %d: %s", resp.StatusCode, string(body))
	}
	// 剥掉 JSONP 包裹：callback({...});
	s := string(body)
	if i := strings.IndexByte(s, '{'); i >= 0 {
		s = s[i:]
	}
	if i := strings.LastIndexByte(s, '}'); i >= 0 {
		s = s[:i+1]
	}
	var d struct {
		OpenID string `json:"openid"`
		Error  int    `json:"error"`
	}
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return "", fmt.Errorf("qq: parse openid: %w", err)
	}
	if d.OpenID == "" {
		return "", errors.New("qq: empty openid from /oauth2.0/me")
	}
	return d.OpenID, nil
}
