package handler

import (
	"context"

	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// grantCoversScope 报告该用户对该客户端已有的授权是否覆盖本次请求的全部 scope。
//
// 只有「覆盖」时才允许跳过同意页直接签发授权码；否则（首次授权，或应用把权限
// 范围扩大了）必须重新走同意流程。仅判断 grant 是否存在是不够的——那样应用
// 只要拿到过一次授权，之后就能任意追加权限而不再打扰用户。
func (h *Handler) grantCoversScope(userID int64, clientID, scope string) bool {
	var g models.Grant
	err := h.db.NewSelect().Model(&g).
		Where("user_id = ? AND client_id = ?", userID, clientID).
		Limit(1).Scan(context.Background())
	if err != nil {
		return false
	}
	granted := make(map[string]bool, len(g.Scopes))
	for _, s := range g.Scopes {
		granted[s] = true
	}
	for _, s := range strings.Fields(scope) {
		if !granted[s] {
			return false
		}
	}
	return true
}

// consumeConsent 取出并校验 consent ticket，返回绑定的授权请求参数。
// 校验通过后一次性消费（删除 ticket 与 tokenstore 缓存）。
func (h *Handler) consumeConsent(r *http.Request, ticket string) (*consentReq, bool) {
	sess := h.sessionID(r)
	// 校验 ticket 存在、未过期，且绑定到当前会话（防止跨会话滥用/重放）。
	if !h.tokens.Check("consent:"+ticket, sess) {
		return nil, false
	}
	req, found := h.takeConsent(ticket)
	if !found {
		return nil, false
	}
	// 消费后移除 tokenstore 中的 ticket，避免重放。
	h.tokens.Delete("consent:" + ticket)
	if time.Since(req.CreatedAt) > authorizationCodeTTL {
		return nil, false
	}
	return &req, true
}

// HandleConsentInfo: GET /api/v1/oauth/consent?request=<ticket>
// 返回授权确认页所需的 client、scopes、当前账户信息。需要登录且携带匹配会话。
func (h *Handler) HandleConsentInfo(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("request")
	if ticket == "" {
		fail(w, r, http.StatusBadRequest, "consent.invalid", "缺少授权请求标识")
		return
	}
	if !h.tokens.Has("consent:" + ticket) {
		fail(w, r, http.StatusBadRequest, "consent.expired", "授权请求已失效，请重新发起登录")
		return
	}
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	req, found := h.peekConsent(ticket)
	if !found || req.UserID != u.ID {
		fail(w, r, http.StatusBadRequest, "consent.invalid", "授权请求不存在")
		return
	}
	var client models.OAuthClient
	if err := h.db.NewSelect().Model(&client).Where("id = ?", req.ClientID).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusBadRequest, "consent.invalid", "无效的客户端")
		return
	}

	// 解析请求的 scopes，附带展示所需的标签（Standard / 高风险）与描述。
	scopes := parseScopes(req.Scope)
	// Logo 会被渲染进授权确认页的 <img src>，与登录页提供商 Logo 同一处置：
	// 出库前再过滤一次，防历史数据或直接改库留下 javascript: 之类的取值。
	logo, _ := sanitizeAssetURL(client.LogoURL)

	ok(w, r, map[string]any{
		"requestId": ticket,
		"client": map[string]any{
			"id":          client.ID,
			"name":        client.Name,
			"logoUrl":     logo,
			"description": client.Description,
			"redirectUri": req.RedirectURI,
			"scopes":      scopes,
		},
		"account": map[string]any{
			"displayName": u.DisplayName,
			"username":    u.Username,
			"email":       u.Email,
			"avatarUrl":   u.AvatarURL,
		},
	})
}

// HandleConsentAction: POST /api/v1/oauth/consent  { request, action: "allow"|"deny" }
// 用户点击同意/拒绝后回调。同意则记录 grant、签发授权码并返回重定向地址；拒绝则带 error 返回。
func (h *Handler) HandleConsentAction(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		Request string `json:"request"`
		Action  string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil || reqBody.Request == "" {
		fail(w, r, http.StatusBadRequest, "consent.invalid", "请求体不合法")
		return
	}
	req, consumed := h.consumeConsent(r, reqBody.Request)
	if !consumed {
		fail(w, r, http.StatusBadRequest, "consent.expired", "授权请求已失效，请重新发起登录")
		return
	}
	// 再次确认用户仍登录且 ticket 属于该用户
	u, _, err := h.currentUser(r)
	if err != nil || req.UserID != u.ID {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if reqBody.Action == "deny" {
		// 拒绝：带 access_denied 错误重定向回 redirect_uri。
		loc := req.RedirectURI
		sep := "?"
		if strings.Contains(loc, "?") {
			sep = "&"
		}
		loc += sep + "error=access_denied&error_description=" + escape("用户拒绝了授权")
		if req.State != "" {
			loc += "&state=" + req.State
		}
		h.logEvent(r, u.ID, &models.Event{
			Type:    "oauth.denied",
			Summary: "拒绝第三方应用授权",
			Metadata: map[string]string{
				"clientId":   req.ClientID,
				"clientName": h.clientName(req.ClientID),
			},
		})
		ok(w, r, map[string]any{"redirect": loc})
		return
	}
	// 同意：记录 grant（幂等）后签发授权码，返回重定向地址由前端跳转。
	if reqBody.Action == "allow" {
		_ = h.recordGrant(r.Context(), u.ID, req.ClientID, strings.Fields(req.Scope))
		loc := h.issueAuthorizationCode(w, r, req.ClientID, req.RedirectURI, req.Scope, req.Nonce, req.CodeChallenge, req.State, u.ID)
		// 授权是账号安全事件，必须落审计与「最近活动」；此前 consent 流程完全没有
		// 写事件，导致用户授权第三方应用后在个人总览里看不到任何记录。
		h.logEvent(r, u.ID, &models.Event{
			Type:    "oauth.authorized",
			Summary: "授权第三方应用",
			Metadata: map[string]string{
				"clientId":   req.ClientID,
				"clientName": h.clientName(req.ClientID),
				"scope":      req.Scope,
			},
		})
		ok(w, r, map[string]any{"redirect": loc})
		return
	}
	fail(w, r, http.StatusBadRequest, "consent.invalid", "未知的操作")
}

// clientName 返回 OAuth 应用的展示名，查不到时回落为 client_id。
func (h *Handler) clientName(clientID string) string {
	if clientID == "" {
		return ""
	}
	c := &models.OAuthClient{}
	if err := h.db.NewSelect().Model(c).Where("id = ?", clientID).Scan(context.Background()); err != nil {
		return clientID
	}
	if c.Name == "" {
		return clientID
	}
	return c.Name
}

// recordGrant 幂等地为用户 + 客户端记录一条授权（已存在则更新 scopes）。
func (h *Handler) recordGrant(ctx context.Context, userID int64, clientID string, scopes []string) error {
	var g models.Grant
	err := h.db.NewSelect().Model(&g).Where("user_id = ? AND client_id = ?", userID, clientID).Scan(ctx)
	if err != nil {
		_, err = h.db.NewInsert().Model(&models.Grant{
			ID:       auth.RandomToken(24),
			UserID:   userID,
			ClientID: clientID,
			Scopes:   scopes,
			// 必须显式赋值：created_at 列没有数据库默认值，漏掉会让授权时间
			// 一律落为零值（0001-01-01），授权记录里就永远看不到真实时间。
			CreatedAt: db.Now(),
		}).Exec(ctx)
		return err
	}
	// 更新 scopes（合并去重）
	merged := append([]string{}, g.Scopes...)
	for _, s := range scopes {
		if !contains(merged, s) {
			merged = append(merged, s)
		}
	}
	_, err = h.db.NewUpdate().Model((*models.Grant)(nil)).Set("scopes = ?", merged).Where("id = ?", g.ID).Exec(ctx)
	return err
}

// scopeInfo 描述单个 OAuth scope 的展示信息（名称、说明、风险等级）。
// Key 是原始权限标识（如 openid）：前端据此查语言包做本地化，查不到时
// 才回落到后端的 Name / Description，避免权限项在界面上直接暴露英文标识符。
type scopeInfo struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Level       string `json:"level"` // standard | high
}

// scopeOrder 决定权限在界面上的展示顺序；未收录的自定义权限排在最后。
var scopeOrder = []string{"openid", "profile", "email", "phone", "offline_access"}

// scopeDefs 是内置权限的展示定义（名称 / 说明 / 风险等级），唯一事实来源：
// 授权同意页（parseScopes）与「我的授权」权限明细（scopeInfosFor）共用，
// 避免同一权限在两个页面上出现不同文案或不同风险标注。
var scopeDefs = map[string]scopeInfo{
	"openid":         {Key: "openid", Name: "身份标识", Description: "获取您的唯一身份标识，用于确认登录者身份", Level: "standard"},
	"profile":        {Key: "profile", Name: "基本资料", Description: "读取您的用户名、昵称与头像", Level: "standard"},
	"email":          {Key: "email", Name: "电子邮箱", Description: "获取您的电子邮箱以便于直接帮助您自动化注册用户", Level: "high"},
	"phone":          {Key: "phone", Name: "手机号码", Description: "读取您的手机号码，用于安全校验与通知", Level: "high"},
	"offline_access": {Key: "offline_access", Name: "离线访问", Description: "允许应用在您离线时刷新令牌", Level: "standard"},
}

// scopeInfosFor 把权限标识列表转换为展示信息列表：内置权限按 scopeOrder 保序，
// 自定义权限按原始顺序追加（否则用户看不到应用实际申请了什么）。
func scopeInfosFor(list []string) []scopeInfo {
	requested := make(map[string]bool, len(list))
	for _, s := range list {
		requested[s] = true
	}
	out := make([]scopeInfo, 0, len(list))
	for _, key := range scopeOrder {
		if requested[key] {
			out = append(out, scopeDefs[key])
		}
	}
	// 已输出的自定义权限去重：list 可能来自 JSON 数组，允许重复项，
	// 但界面明细与计数不应因此重复。
	seen := make(map[string]bool, len(list))
	for _, s := range list {
		// address 并非本服务实际提供的能力（历史上被错误登记，权限项已禁用），
		// 展示层不再把它当作权限项列出，避免卡片上出现不存在的权限。
		if s == "address" || contains(scopeOrder, s) || seen[s] {
			continue
		}
		seen[s] = true
		if d, ok := scopeDefs[s]; ok {
			out = append(out, d)
		} else {
			out = append(out, scopeInfo{Key: s, Name: s, Description: "", Level: "standard"})
		}
	}
	return out
}

// parseScopes 把 OIDC scope 字符串（空格分隔）转换为授权页展示所需的权限列表。
func parseScopes(scope string) []scopeInfo {
	return scopeInfosFor(strings.Fields(scope))
}
