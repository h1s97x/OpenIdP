package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/netutil"
)

// ---- 系统设置 → 代理设置 ----
//
// 代理配置仅作为「可用配置项」保存：不全局生效，
// 只对在登录提供商中开启「使用代理」的提供商出站请求生效。

// loadProxySetting 读取单行代理配置；首次访问时落一条默认行（关闭状态）。
func (h *Handler) loadProxySetting() *models.ProxySetting {
	var ps models.ProxySetting
	err := h.db.NewSelect().Model(&ps).Where("id = 1").Scan(context.Background())
	if err != nil {
		ps = models.ProxySetting{ID: 1, Protocol: "http", Enabled: false, UpdatedAt: db.Now()}
		_, _ = h.db.NewInsert().Model(&ps).Exec(context.Background())
		return &ps
	}
	return &ps
}

// GET /api/v1/admin/proxy
func (h *Handler) handleAdminGetProxy(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ps := h.loadProxySetting()
	ok(w, r, map[string]any{
		"protocol":    ps.Protocol,
		"host":        ps.Host,
		"port":        ps.Port,
		"username":    ps.Username,
		"enabled":     ps.Enabled,
		"hasPassword": ps.Password != "",
	})
}

// PATCH /api/v1/admin/proxy
func (h *Handler) handleAdminUpdateProxy(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ps := h.loadProxySetting()
	var req struct {
		Protocol         *string `json:"protocol"`
		Host             *string `json:"host"`
		Port             *int    `json:"port"`
		Username         *string `json:"username"`
		Password         *string `json:"password"`
		HasClearPassword *bool   `json:"clearPassword"`
		Enabled          *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if req.Protocol != nil {
		p := strings.ToLower(strings.TrimSpace(*req.Protocol))
		switch p {
		case "http", "https", "socks5":
			ps.Protocol = p
		case "":
			ps.Protocol = "http"
		default:
			fail(w, r, http.StatusBadRequest, "proxy.protocol_invalid", "代理协议仅支持 http / https / socks5")
			return
		}
	}
	if req.Host != nil {
		ps.Host = strings.TrimSpace(*req.Host)
	}
	if req.Port != nil {
		if *req.Port < 0 || *req.Port > 65535 {
			fail(w, r, http.StatusBadRequest, "proxy.port_invalid", "代理端口需在 0-65535 之间")
			return
		}
		ps.Port = *req.Port
	}
	if req.Username != nil {
		ps.Username = strings.TrimSpace(*req.Username)
	}
	if req.HasClearPassword != nil && *req.HasClearPassword {
		ps.Password = ""
	} else if req.Password != nil && *req.Password != "" {
		ps.Password = secretpkg.Encrypt(*req.Password)
	}
	if req.Enabled != nil {
		ps.Enabled = *req.Enabled
	}
	// 开启总开关时做基本完整性校验，避免保存一份无法使用的配置。
	if ps.Enabled {
		if ps.Host == "" || ps.Port == 0 {
			fail(w, r, http.StatusBadRequest, "proxy.incomplete", "启用代理前请先填写代理地址与端口")
			return
		}
	}
	ps.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(ps).WherePK().
		Set("protocol = ?", ps.Protocol).
		Set("host = ?", ps.Host).
		Set("port = ?", ps.Port).
		Set("username = ?", ps.Username).
		Set("password = ?", ps.Password).
		Set("enabled = ?", ps.Enabled).
		Set("updated_at = ?", ps.UpdatedAt).
		Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	h.auditConfigChange(r, "proxy", "update", 0, []string{
		"protocol", "host", "port", "username", "password", "enabled",
	})
	h.logEvent(r, 0, &models.Event{Type: "admin.proxy_updated", Summary: "管理员更新代理设置"})
	ok(w, r, map[string]any{
		"protocol":    ps.Protocol,
		"host":        ps.Host,
		"port":        ps.Port,
		"username":    ps.Username,
		"enabled":     ps.Enabled,
		"hasPassword": ps.Password != "",
	})
}

// POST /api/v1/admin/proxy/test — 经代理请求外部地址，验证连通性。
// body: { target?: string }
func (h *Handler) handleAdminTestProxy(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// 空请求体也允许：直接用默认测试地址
		req = struct {
			Target string `json:"target"`
		}{}
	}
	ps := h.loadProxySetting()
	if ps.Host == "" || ps.Port == 0 {
		fail(w, r, http.StatusBadRequest, "proxy.incomplete", "请先保存代理地址与端口")
		return
	}
	pw := secretpkg.Decrypt(ps.Password)
	proxyURL := ps.ProxyURL(pw)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	status, elapsed, err := netutil.TestConnectivity(ctx, proxyURL, req.Target)
	if err != nil {
		ok(w, r, map[string]any{"success": false, "error": "代理连接失败，请检查地址、端口与认证信息"})
		return
	}
	ok(w, r, map[string]any{
		"success":      status >= 200 && status < 400,
		"statusCode":   status,
		"elapsedMilli": elapsed.Milliseconds(),
	})
}

// proxyClientForProvider 为指定提供商返回出站 HTTP 客户端：
// 该提供商开启「使用代理」且系统代理已配置时走代理，否则直连。
func (h *Handler) proxyClientForProvider(prov *models.OAuthProvider) *http.Client {
	if prov == nil || !prov.UseProxy {
		return nil // nil = 调用方使用默认直连客户端
	}
	ps := h.loadProxySetting()
	if !ps.Enabled || ps.Host == "" || ps.Port == 0 {
		return nil
	}
	pw := secretpkg.Decrypt(ps.Password)
	client, err := netutil.HTTPClient(ps.ProxyURL(pw))
	if err != nil {
		return nil
	}
	return client
}

// providerProxyReady 判断系统代理配置是否已就绪（已启用且地址端口齐备）。
// 供提供商保存时的「使用代理」检查与前端提示使用。
func (h *Handler) providerProxyReady() bool {
	ps := h.loadProxySetting()
	return ps.Enabled && ps.Host != "" && ps.Port != 0
}
