package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/oauth2"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- Admin OAuth clients ----

// GET /api/v1/admin/oauth-clients
func (h *Handler) handleAdminOAuthClients(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var clients []models.OAuthClient
	if err := h.db.NewSelect().Model(&clients).Order("created_at DESC").Scan(r.Context(), &clients); err != nil {
		internal(w, r, err)
		return
	}
	// Logo 会被渲染进后台列表的 <img src>：出库前再过滤一次，
	// 与公开端（登录页 / 授权页）同一处置，防历史数据或直接改库留下危险协议。
	for i := range clients {
		logo, _ := sanitizeAssetURL(clients[i].LogoURL)
		clients[i].LogoURL = logo
	}
	if clients == nil {
		clients = []models.OAuthClient{}
	}
	ok(w, r, clients)
}

// POST /api/v1/admin/oauth-clients
func (h *Handler) handleAdminCreateOAuthClient(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		LogoURL      string   `json:"logoUrl"`
		HomepageURL  string   `json:"homepageUrl"`
		RedirectURIs []string `json:"redirectUris"`
		Scopes       []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		fail(w, r, http.StatusBadRequest, "admin.client_name_required", "请填写应用名称")
		return
	}
	// Logo 与应用主页会被前端渲染进 <img src> / <a href>，只做 TrimSpace 时
	// 管理员（或直接改库者）填入 javascript: 取值即构成存储型 XSS。
	logo, logoOK := sanitizeAssetURL(req.LogoURL)
	homepage, homepageOK := sanitizeExternalURL(req.HomepageURL)
	if !logoOK || !homepageOK {
		fail(w, r, http.StatusBadRequest, "admin.invalid_url", "应用主页地址只支持 http/https 链接，应用 Logo 还支持站内路径")
		return
	}
	secret := auth.RandomToken(24)
	hash, _ := auth.HashPassword(secret)
	// 后台创建的应用一律是机密客户端（confidential）：令牌端点会强制校验
	// client_secret，不再出现"无密钥也能通过客户端认证"的情况。
	cli := &models.OAuthClient{
		ID:           auth.NewID(),
		SecretHash:   hash,
		ClientType:   "confidential",
		Name:         req.Name,
		Description:  req.Description,
		LogoURL:      logo,
		HomepageURL:  homepage,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		CreatedAt:    db.Now(),
	}
	if _, err := h.db.NewInsert().Model(cli).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, 0, &models.Event{
		Type:     "admin.oauth_client_created",
		Summary:  "管理员创建 OAuth 应用",
		Metadata: map[string]string{"clientId": cli.ID, "name": cli.Name},
	})
	// include the plaintext secret once for the admin to copy
	ok(w, r, map[string]any{"client": cli, "clientSecret": secret})
}

// PATCH /api/v1/admin/oauth-clients/{id}
// 局部更新应用名称 / Logo / 回调地址 / 权限范围。
// Client ID 与 Client Secret 不受影响，已接入的应用无需改动配置。
func (h *Handler) handleAdminUpdateOAuthClient(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	var cli models.OAuthClient
	if err := h.db.NewSelect().Model(&cli).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.client_not_found", "应用不存在")
		return
	}
	var req struct {
		Name         *string  `json:"name"`
		Description  *string  `json:"description"`
		LogoURL      *string  `json:"logoUrl"`
		HomepageURL  *string  `json:"homepageUrl"`
		RedirectURIs []string `json:"redirectUris"`
		Scopes       []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			fail(w, r, http.StatusBadRequest, "admin.client_name_required", "请填写应用名称")
			return
		}
		cli.Name = name
	}
	if req.Description != nil {
		cli.Description = strings.TrimSpace(*req.Description)
	}
	if req.LogoURL != nil {
		// 必须与创建接口用同一套校验（sanitizeAssetURL）：
		// 创建允许站内路径（如 /images/logo.svg），编辑却只认 http/https，
		// 结果是「带着原样回填的 Logo 保存一次就被判非法」——站内路径的应用
		// 一旦编辑就再也存不回去。
		v, ok := sanitizeAssetURL(*req.LogoURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "admin.invalid_url", "应用 Logo 只支持站内路径或 http/https 链接")
			return
		}
		cli.LogoURL = v
	}
	if req.HomepageURL != nil {
		v, ok := sanitizeExternalURL(*req.HomepageURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "admin.invalid_url", "应用主页地址只支持 http/https 链接")
			return
		}
		cli.HomepageURL = v
	}
	if req.RedirectURIs != nil {
		cli.RedirectURIs = req.RedirectURIs
	}
	if req.Scopes != nil {
		cli.Scopes = req.Scopes
	}
	if _, err := h.db.NewUpdate().Model(&cli).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, 0, &models.Event{
		Type:     "admin.oauth_client_updated",
		Summary:  "管理员更新 OAuth 应用",
		Metadata: map[string]string{"clientId": cli.ID, "name": cli.Name},
	})
	ok(w, r, cli)
}

// POST /api/v1/admin/oauth-clients/{id}/secret
// 轮换 Client Secret：生成新密钥并立即覆盖旧密钥，明文仅在本次响应中返回一次。
func (h *Handler) handleAdminRotateOAuthClientSecret(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	var cli models.OAuthClient
	if err := h.db.NewSelect().Model(&cli).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.client_not_found", "应用不存在")
		return
	}
	plain := auth.RandomToken(24)
	hash, err := auth.HashPassword(plain)
	if err != nil {
		internal(w, r, err)
		return
	}
	cli.SecretHash = hash
	// 轮换后应用必定持有密钥，统一标记为机密客户端，避免被当作 public client 放行。
	cli.ClientType = "confidential"
	// 旧密钥在写入后立即失效：令牌端点的客户端认证会比对新哈希。
	// 此前已签发的 access/refresh token 仍可用到自然过期。
	if _, err := h.db.NewUpdate().Model(&cli).
		Set("secret_hash = ?", cli.SecretHash).
		Set("client_type = ?", cli.ClientType).
		WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, 0, &models.Event{
		Type:     "admin.oauth_client_secret_rotated",
		Summary:  "管理员刷新 OAuth 应用密钥",
		Metadata: map[string]string{"clientId": cli.ID, "name": cli.Name},
	})
	ok(w, r, map[string]any{"client": cli, "clientSecret": plain})
}

// DELETE /api/v1/admin/oauth-clients/{id}
func (h *Handler) handleAdminDeleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	_, _ = h.db.NewDelete().Model((*models.OAuthClient)(nil)).Where("id = ?", id).Exec(r.Context())
	h.logEvent(r, 0, &models.Event{
		Type:     "admin.oauth_client_deleted",
		Summary:  "管理员删除 OAuth 应用",
		Metadata: map[string]string{"clientId": id},
	})
	ok(w, r, map[string]any{"success": true})
}

// ---- Admin OAuth providers ----

// GET /api/v1/admin/oauth-providers
func (h *Handler) handleAdminOAuthProviders(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var providers []models.OAuthProvider
	if err := h.db.NewSelect().Model(&providers).Order("created_at DESC").Scan(r.Context(), &providers); err != nil {
		internal(w, r, err)
		return
	}
	if providers == nil {
		providers = []models.OAuthProvider{}
	}
	// 补充展示用的回调 URL（不持久化）：基于当前访问域名动态拼接短路径 /callback/{type}；
	// 同时附加内置提供商清单中的端点地址（授权/令牌/用户信息/Scope/文档），便于管理员核对。
	base := h.requestBaseURL(r)
	out := make([]map[string]any, 0, len(providers))
	for i := range providers {
		p := providers[i]
		// secretSet 用于后台提示：ClientSecret 是否已配置（明文存储）。
		// 若通过环境变量 GITEE_CLIENT_SECRET 等配置明文，则视为已就绪。
		csec := p.ClientSecret
		if envSec := h.cfg.ProviderClientSecrets[p.ProviderType]; envSec != "" {
			csec = envSec
		}
		// 与公开端（登录页）同一处置：Logo 会渲染进后台列表的 <img src>，
		// 出库前过滤危险协议。
		logo, _ := sanitizeAssetURL(p.LogoURL)
		item := map[string]any{
			"id":           p.ID,
			"name":         p.Name,
			"displayName":  p.DisplayName,
			"providerType": p.ProviderType,
			"logoUrl":      logo,
			"clientId":     p.ClientID,
			"enabled":      p.Enabled,
			"custom":       p.Custom,
			"authorizeUrl": p.AuthorizeURL,
			"tokenUrl":     p.TokenURL,
			"userInfoUrl":  p.UserInfoURL,
			"openIdUrl":    p.OpenIDURL,
			"scopes":       p.Scopes,
			"docsUrl":      p.DocsURL,
			"createdAt":    p.CreatedAt,
			"secretSet":    csec != "",
			"ready":        p.Enabled && p.ClientID != "" && csec != "",
			"useProxy":     p.UseProxy,
			"proxyReady":   h.providerProxyReady(),
			"callbackUrl":  base + "/api/oauth/callback/" + p.ProviderType,
		}
		// 内置提供商附带「内置默认端点」：后台据此展示默认值，并据此判断某个字段
		// 是否被改过、以及提供「恢复默认」。端点本身直接返回数据库取值——
		// 内置端点会在初始化时落库，管理员改动后以库为准。
		if def, ok := oauth2.Get(p.ProviderType); ok {
			item["builtin"] = true
			item["defaultEndpoints"] = map[string]any{
				"authorizeUrl": def.AuthorizeURL,
				"tokenUrl":     def.TokenURL,
				"userInfoUrl":  def.UserInfoURL,
				"openIdUrl":    def.OpenIDURL,
				"scopes":       def.Scopes,
				"docsUrl":      def.DocsURL,
			}
		}
		out = append(out, item)
	}
	ok(w, r, out)
}

// providerCredentialsMissing 判断提供商是否缺少可用凭据。
//
// 启用（enabled）的前提是 ClientID 与 ClientSecret 齐备：二者缺一都无法完成授权码
// 交换，允许开启只会造出「列表里有、点进去必失败」的入口，而失败原因（凭据缺失）
// 对普通用户完全不可见。因此这条规则在创建与更新两处都强制执行。
func providerCredentialsMissing(p *models.OAuthProvider) bool {
	return p.ClientID == "" || p.ClientSecret == ""
}

// PATCH /api/v1/admin/oauth-providers/{id}  {enabled, clientId, clientSecret, displayName, logoUrl}
func (h *Handler) handleAdminUpdateOAuthProvider(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	var p models.OAuthProvider
	if err := h.db.NewSelect().Model(&p).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.provider_not_found", "提供商不存在")
		return
	}
	var req struct {
		Enabled      *bool    `json:"enabled"`
		ClientID     *string  `json:"clientId"`
		ClientSecret *string  `json:"clientSecret"`
		DisplayName  *string  `json:"displayName"`
		LogoURL      *string  `json:"logoUrl"`
		AuthorizeURL *string  `json:"authorizeUrl"`
		TokenURL     *string  `json:"tokenUrl"`
		UserInfoURL  *string  `json:"userInfoUrl"`
		OpenIDURL    *string  `json:"openIdUrl"`
		Scopes       []string `json:"scopes"`
		DocsURL      *string  `json:"docsUrl"`
		UseProxy     *bool    `json:"useProxy"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	// 开启「使用代理」时检查系统代理是否已配置：未配置时直接拒绝保存，
	// 让前端右下角弹窗提示补全代理配置，而不是静默保存一个无效开关。
	if req.UseProxy != nil && *req.UseProxy && !h.providerProxyReady() {
		fail(w, r, http.StatusBadRequest, "proxy.not_configured", "尚未配置系统代理，请先在系统设置的代理设置中完成配置")
		return
	}
	if req.UseProxy != nil {
		p.UseProxy = *req.UseProxy
	}
	if req.ClientID != nil {
		p.ClientID = *req.ClientID
	}
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		// 密文落库（同 MailSetting.Password），读取时解密用于换取 access_token
		p.ClientSecret = secretpkg.Encrypt(*req.ClientSecret)
	}
	if req.DisplayName != nil {
		p.DisplayName = *req.DisplayName
	}
	if req.LogoURL != nil {
		// 登录提供商 Logo 会下发到未登录的登录页，必须与 OAuth 客户端 Logo 用
		// 同一套校验：否则可被填成第三方地址，被用作追踪像素或内网探测。
		v, ok := sanitizeAssetURL(*req.LogoURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "provider.logo_invalid", "Logo 地址无效，仅支持站内路径或 http/https 绝对地址")
			return
		}
		p.LogoURL = v
	}
	// 端点配置（内置与自定义提供商都可修改）。
	//
	// 端点由前端表单在**初始化时填入**（内置默认值随初始化落库），因此这里不再
	// 区分 Custom：填错端点会直接导致登录失败，属于管理员可控的运维配置。
	// 每个字段都做归一化与校验，拒绝 javascript: / data: 之类的取值——
	// 这些地址会被拼进浏览器跳转（授权地址）或服务端出站请求（令牌 / 用户信息）。
	if req.AuthorizeURL != nil {
		v, ok := sanitizeProviderEndpoint(*req.AuthorizeURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "provider.endpoint_invalid", "授权地址无效，仅支持 http/https 绝对地址")
			return
		}
		p.AuthorizeURL = v
	}
	if req.TokenURL != nil {
		v, ok := sanitizeProviderEndpoint(*req.TokenURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "provider.endpoint_invalid", "令牌地址无效，仅支持 http/https 绝对地址")
			return
		}
		p.TokenURL = v
	}
	if req.UserInfoURL != nil {
		v, ok := sanitizeProviderEndpoint(*req.UserInfoURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "provider.endpoint_invalid", "用户信息地址无效，仅支持 http/https 绝对地址")
			return
		}
		p.UserInfoURL = v
	}
	if req.OpenIDURL != nil {
		v, ok := sanitizeProviderEndpoint(*req.OpenIDURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "provider.endpoint_invalid", "openid 地址无效，仅支持 http/https 绝对地址")
			return
		}
		p.OpenIDURL = v
	}
	if req.Scopes != nil {
		scopes, ok := sanitizeProviderScopes(req.Scopes)
		if !ok {
			fail(w, r, http.StatusBadRequest, "provider.scopes_invalid", "权限范围含非法字符或条目过多")
			return
		}
		p.Scopes = scopes
	}
	if req.DocsURL != nil {
		v, ok := sanitizeProviderEndpoint(*req.DocsURL)
		if !ok {
			fail(w, r, http.StatusBadRequest, "provider.endpoint_invalid", "文档地址无效，仅支持 http/https 绝对地址")
			return
		}
		p.DocsURL = v
	}
	// 保存后必须仍然可用：三个核心端点（授权 / 令牌 / 用户信息）缺一即无法完成登录。
	// 内置提供商清空某字段会回落到内置默认值，故按「生效值」判断。
	if err := validateProviderEndpoints(&p); err != nil {
		fail(w, r, http.StatusBadRequest, "provider.endpoints_incomplete", err.Error())
		return
	}
	// 启用前必须有凭据：ClientID / ClientSecret 缺任何一项都换不来 access_token，
	// 放行只会得到一个「开着但用不了」的提供商 —— 登录页与安全中心会出现点了必然
	// 报错的入口（授权端点会以 providerReadyErr 拒绝）。
	if p.Enabled && providerCredentialsMissing(&p) {
		fail(w, r, http.StatusBadRequest, "provider.not_configured", "启用前需先填写 Client ID 与 Client Secret")
		return
	}
	// 注意：bun 的 UpdateQuery 一旦调用 .Set()，就只会更新被显式列出的列，
	// 其余字段（client_id / client_secret / display_name / enabled 等）会被静默丢弃，
	// 表现为管理后台对登录提供商的修改“响应成功但不落库”。
	// p 是先从库中读出的完整记录、再按请求逐字段覆盖，故直接 WherePK().Exec()
	// 即可把全部字段写回（不加 .Set()，也不加 .Column("*")——后者在 bun v1.2.18 会报错）。
	if _, err := h.db.NewUpdate().Model(&p).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, 0, &models.Event{
		Type:     "admin.oauth_provider_updated",
		Summary:  "管理员更新登录提供商配置",
		Metadata: map[string]string{"providerType": p.ProviderType},
	})
	ok(w, r, p)
}

// providerProbeTimeout 是「测试连通性」的整体上限：三个端点并行探测，
// 最坏情况也只是等这一个超时，不会让管理员对着转圈等几十秒。
const providerProbeTimeout = 10 * time.Second

// POST /api/v1/admin/oauth-providers/{id}/test — 测试该提供商的出站链路是否可达。
//
// 用该提供商**真实的出站客户端**探测授权 / 令牌 / 用户信息三个端点，因此
// 「使用代理」开启时走的正是代理——这正是排查「授权码交换失败」时最需要区分的：
// 是网络层不通（dial / TLS / reset / timeout），还是上游返回了错误。
//
// 判定口径：拿到任何 HTTP 响应都算链路可达，4xx/5xx 只说明该端点不接受裸 GET。
// 若把 4xx 判成失败，正常站点（令牌端点必然拒绝无凭据的 GET）会被误报为不通。
// 探测请求不携带 client_secret，也不解析响应体，只取状态码。
func (h *Handler) handleAdminTestOAuthProvider(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var prov models.OAuthProvider
	if err := h.db.NewSelect().Model(&prov).Where("id = ?", chi.URLParam(r, "id")).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.provider_not_found", "提供商不存在")
		return
	}
	// 端点与出站客户端都从 resolveProvider 取：内置提供商来自注册表，
	// 自定义提供商来自库里的端点，两条路径都会按「使用代理」注入代理客户端。
	pv, resolved := h.resolveProvider(prov.ProviderType)
	if !resolved {
		fail(w, r, http.StatusBadRequest, "admin.provider_unresolved", "无法解析该提供商的端点配置，请检查端点地址是否填写完整")
		return
	}
	client := pv.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: providerProbeTimeout}
	}
	// 回显代理地址：排查时第一件要确认的就是「到底走没走代理」，
	// 让这一条直接出现在结果里，省掉来回确认。
	proxyAddr := ""
	if prov.UseProxy {
		if ps := h.loadProxySetting(); ps.Enabled && ps.Host != "" && ps.Port != 0 {
			proxyAddr = fmt.Sprintf("%s:%d", ps.Host, ps.Port)
		}
	}

	type endpoint struct{ key, url string }
	endpoints := []endpoint{
		{"authorize", pv.AuthorizeURL},
		{"token", pv.TokenURL},
		{"userinfo", pv.UserInfoURL},
		// openid 端点只有部分平台需要（如 QQ），地址为空时下面的循环直接跳过。
		{"openid", pv.OpenIDURL},
	}
	type probeResult struct {
		Key        string `json:"key"`
		URL        string `json:"url"`
		Reachable  bool   `json:"reachable"`
		StatusCode int    `json:"statusCode"`
		ElapsedMs  int64  `json:"elapsedMs"`
		Error      string `json:"error,omitempty"`
	}
	results := make([]probeResult, len(endpoints))
	ctx, cancel := context.WithTimeout(r.Context(), providerProbeTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for i, ep := range endpoints {
		if strings.TrimSpace(ep.url) == "" {
			continue
		}
		wg.Add(1)
		go func(i int, ep endpoint) {
			defer wg.Done()
			res := probeResult{Key: ep.key, URL: ep.url}
			start := time.Now()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, nil)
			if err != nil {
				res.Error = err.Error()
				results[i] = res
				return
			}
			req.Header.Set("User-Agent", "openidp-provider-check")
			resp, err := client.Do(req)
			res.ElapsedMs = time.Since(start).Milliseconds()
			if err != nil {
				// 网络层失败：dial / TLS / 连接被重置 / 超时。原文保留给管理员看。
				res.Error = err.Error()
				results[i] = res
				return
			}
			// 不解析响应体，但要把连接交回连接池（限读 4KB，避免大页面拖慢测试）。
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			res.Reachable = true
			res.StatusCode = resp.StatusCode
			results[i] = res
		}(i, ep)
	}
	wg.Wait()

	out := make([]probeResult, 0, len(results))
	for _, res := range results {
		if res.URL != "" {
			out = append(out, res)
		}
	}
	ok(w, r, map[string]any{
		"providerType": prov.ProviderType,
		"useProxy":     prov.UseProxy,
		"proxyAddr":    proxyAddr,
		"results":      out,
	})
}

// POST /api/v1/admin/oauth-providers — create a custom OAuth2 provider.
func (h *Handler) handleAdminCreateOAuthProvider(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		ProviderType string   `json:"providerType"`
		DisplayName  string   `json:"displayName"`
		LogoURL      string   `json:"logoUrl"`
		ClientID     string   `json:"clientId"`
		ClientSecret string   `json:"clientSecret"`
		AuthorizeURL string   `json:"authorizeUrl"`
		TokenURL     string   `json:"tokenUrl"`
		UserInfoURL  string   `json:"userInfoUrl"`
		OpenIDURL    string   `json:"openIdUrl"`
		Scopes       []string `json:"scopes"`
		DocsURL      string   `json:"docsUrl"`
		Enabled      bool     `json:"enabled"`
		UseProxy     bool     `json:"useProxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	providerType := strings.TrimSpace(req.ProviderType)
	if providerType == "" {
		fail(w, r, http.StatusBadRequest, "admin.provider_type_required", "请填写提供商类型标识")
		return
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		fail(w, r, http.StatusBadRequest, "admin.provider_name_required", "请填写提供商显示名称")
		return
	}
	authorizeURL, okA := sanitizeProviderEndpoint(req.AuthorizeURL)
	tokenURL, okT := sanitizeProviderEndpoint(req.TokenURL)
	userInfoURL, okU := sanitizeProviderEndpoint(req.UserInfoURL)
	openIDURL, okO := sanitizeProviderEndpoint(req.OpenIDURL)
	docsURL, okD := sanitizeProviderEndpoint(req.DocsURL)
	scopes, okS := sanitizeProviderScopes(req.Scopes)
	if !okA || !okT || !okU || !okO || !okD || !okS {
		fail(w, r, http.StatusBadRequest, "provider.endpoint_invalid", "端点地址或权限范围格式不正确")
		return
	}
	if authorizeURL == "" || tokenURL == "" || userInfoURL == "" {
		fail(w, r, http.StatusBadRequest, "admin.provider_endpoints_required", "请填写授权、令牌与用户信息端点地址")
		return
	}
	// 创建时开启「使用代理」同样要求系统代理已配置。
	if req.UseProxy && !h.providerProxyReady() {
		fail(w, r, http.StatusBadRequest, "proxy.not_configured", "尚未配置系统代理，请先在系统设置的代理设置中完成配置")
		return
	}
	// 校验类型标识唯一（避免与内置或其他自定义提供商冲突）
	n, _ := h.db.NewSelect().Model((*models.OAuthProvider)(nil)).Where("provider_type = ?", providerType).Count(r.Context())
	if n > 0 {
		fail(w, r, http.StatusConflict, "admin.provider_type_exists", "该提供商类型标识已存在")
		return
	}
	logoURL, okLogo := sanitizeAssetURL(req.LogoURL)
	if !okLogo {
		fail(w, r, http.StatusBadRequest, "provider.logo_invalid", "Logo 地址无效，仅支持站内路径或 http/https 绝对地址")
		return
	}
	// 与更新同样的规则：没有凭据就不能以「已启用」状态创建。
	if req.Enabled && (req.ClientID == "" || req.ClientSecret == "") {
		fail(w, r, http.StatusBadRequest, "provider.not_configured", "启用前需先填写 Client ID 与 Client Secret")
		return
	}
	p := &models.OAuthProvider{
		ID:           auth.NewID(),
		Name:         "Oauth-" + providerType,
		DisplayName:  req.DisplayName,
		ProviderType: providerType,
		LogoURL:      logoURL,
		ClientID:     req.ClientID,
		ClientSecret: secretpkg.Encrypt(req.ClientSecret),
		Enabled:      req.Enabled,
		Custom:       true,
		UseProxy:     req.UseProxy,
		AuthorizeURL: authorizeURL,
		TokenURL:     tokenURL,
		UserInfoURL:  userInfoURL,
		OpenIDURL:    openIDURL,
		Scopes:       scopes,
		DocsURL:      docsURL,
		CreatedAt:    db.Now(),
	}
	if _, err := h.db.NewInsert().Model(p).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, p)
}

// DELETE /api/v1/admin/oauth-providers/{id} — delete a custom OAuth2 provider.
func (h *Handler) handleAdminDeleteOAuthProvider(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	var p models.OAuthProvider
	if err := h.db.NewSelect().Model(&p).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.provider_not_found", "提供商不存在")
		return
	}
	// 仅允许删除自定义提供商（内置提供商不可删除，只能停用）。
	if !p.Custom {
		fail(w, r, http.StatusBadRequest, "admin.provider_builtin", "内置提供商不可删除，只能停用")
		return
	}
	if _, err := h.db.NewDelete().Model((*models.OAuthProvider)(nil)).Where("id = ?", id).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, 0, &models.Event{
		Type:     "admin.oauth_provider_deleted",
		Summary:  "管理员删除登录提供商",
		Metadata: map[string]string{"providerType": p.ProviderType},
	})
	ok(w, r, map[string]any{"success": true})
}

// ---- Admin grants ----

// DELETE /api/v1/admin/oauth-grants/{id} — 管理员撤销任意用户的授权。
// 撤销任意用户的授权，不受 user_id 过滤限制。
func (h *Handler) handleAdminRevokeGrant(w http.ResponseWriter, r *http.Request) {
	admin, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		fail(w, r, http.StatusBadRequest, "request.invalid_path", "无效的授权 ID")
		return
	}
	var g models.Grant
	if err := h.db.NewSelect().Model(&g).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.grant_not_found", "授权记录不存在")
		return
	}
	if _, err := h.db.NewDelete().Model((*models.Grant)(nil)).Where("id = ?", id).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	// 授权撤销后立即使该用户在此客户端下的令牌失效，避免已签发 token 继续访问。
	_, _ = h.db.NewUpdate().Model((*models.Token)(nil)).
		Set("revoked = ?", true).
		Where("user_id = ? AND client_id = ?", g.UserID, g.ClientID).Exec(r.Context())
	h.logEvent(r, admin.ID, &models.Event{
		Type:    "admin.grant_revoked",
		Summary: "管理员撤销用户授权",
		Metadata: map[string]string{
			"grantId":  id,
			"clientId": g.ClientID,
			"userId":   strconv.FormatInt(g.UserID, 10),
		},
	})
	ok(w, r, map[string]any{"success": true})
}

// GET /api/v1/admin/oauth-grants
//
// 补充展示所需的应用名 / Logo 与授权用户名，避免管理端只拿到 client_id 这类
// 无意义的机器标识。客户端可能已被删除，故用 LEFT JOIN 并在缺失时回落为 ID。
func (h *Handler) handleAdminOAuthGrants(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	type grantRow struct {
		ID          string    `bun:"id"`
		UserID      int64     `bun:"user_id"`
		ClientID    string    `bun:"client_id"`
		CreatedAt   time.Time `bun:"created_at"`
		ClientName  string    `bun:"client_name"`
		ClientLogo  string    `bun:"client_logo"`
		Username    string    `bun:"username"`
		DisplayName string    `bun:"display_name"`
		Email       string    `bun:"email"`
	}
	var rows []grantRow
	// 每列都用「别名 AS 字段名」显式命名：JOIN 后同名列（如 created_at 在
	// grants / oauth_clients / users 三张表里都有）会让 bun 的字段回填错位，
	// 表现为授权时间为零值。
	err := h.db.NewSelect().
		Model((*models.Grant)(nil)).
		ColumnExpr("g.id AS id, g.user_id AS user_id, g.client_id AS client_id, g.created_at AS created_at").
		ColumnExpr("COALESCE(oc.name, '') AS client_name, COALESCE(oc.logo_url, '') AS client_logo").
		ColumnExpr("COALESCE(u.username, '') AS username, COALESCE(u.display_name, '') AS display_name, COALESCE(u.email, '') AS email").
		Join("LEFT JOIN oauth_clients AS oc ON oc.id = g.client_id").
		Join("LEFT JOIN users AS u ON u.id = g.user_id").
		Order("g.created_at DESC").
		Limit(200).
		Scan(r.Context(), &rows)
	if err != nil {
		internal(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, g := range rows {
		// 同上：管理端授权列表也会把 Logo 渲染进 <img src>。
		logo, _ := sanitizeAssetURL(g.ClientLogo)
		items = append(items, map[string]any{
			"id":          g.ID,
			"userId":      g.UserID,
			"clientId":    g.ClientID,
			"createdAt":   g.CreatedAt,
			"clientName":  g.ClientName,
			"clientLogo":  logo,
			"username":    g.Username,
			"displayName": g.DisplayName,
			"email":       g.Email,
		})
	}
	ok(w, r, items)
}

// escapeLike 转义 LIKE 模式中的通配符（% 与 _），让搜索按字面量匹配。
// 参数化查询已由 bun 保证（不是注入问题），这里修正的是搜索结果失真；
// 转义符使用 '!' 而非反斜杠，避免各数据库对反斜杠字符串字面量的差异处理。
func escapeLike(s string) string {
	const esc = "!"
	return strings.NewReplacer(esc, esc+esc, "%", esc+"%", "_", esc+"_").Replace(s)
}
