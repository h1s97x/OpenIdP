package handler

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- 设备授权流（RFC 8628 Device Authorization Grant）----
//
// discovery 中已对外声明支持 device_code，此前实现缺失会造成「契约与实现不符」。
// 这里补上完整流程：
//  1. 客户端 POST /api/login/oauth/device_authorization 取回 device_code + user_code；
//  2. 用户在门户输入 user_code 完成确认（本文件的端点）；
//  3. 客户端按 interval 轮询令牌端点，直到拿到令牌或授权被拒/过期。

// device code 生命周期参数。
const (
	deviceCodeTTLSeconds      = 600 // user_code 有效期 10 分钟
	deviceCodeIntervalSeconds = 5   // 建议轮询间隔
	// deviceUserCodeLen 是 user_code 的长度。排除易混淆字符（0/O/1/I/L），
	// 8 位足够抵抗在线猜测：配合过期时间与错误次数限制，穷举不可行。
	deviceUserCodeLen = 8
)

// deviceUserCodeAlphabet 是 user_code 的字符集（排除易混淆字符）。
const deviceUserCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// cryptRandInt 返回 [0, max) 范围内的密码学安全随机整数。
// 使用 crypto/rand.Int 而非 math/rand，避免 user_code 可被预测。
func cryptRandInt(max int64) (int64, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return v.Int64(), nil
}

// deviceCodeErrors 定义 RFC 8628 规范的错误码，轮询时按状态返回。
var deviceCodeErrors = map[string]struct {
	Err  string
	Desc string
}{
	models.DeviceAuthPending:  {"authorization_pending", "用户尚未完成授权"},
	models.DeviceAuthDenied:   {"access_denied", "用户已拒绝授权"},
	models.DeviceAuthExpired:  {"expired_token", "授权已过期，请重新发起"},
	models.DeviceAuthApproved: {"", ""},
}

// randomUserCode 生成展示给用户的短码（大写，排除易混淆字符）。
func randomUserCode() string {
	const n = len(deviceUserCodeAlphabet)
	b := make([]byte, deviceUserCodeLen)
	for i := range b {
		v, err := cryptRandInt(int64(n))
		if err != nil {
			// crypto/rand 失败属于不可恢复错误，退化为时间戳派生也不安全，
			// 这里返回空串由调用方报错。
			return ""
		}
		b[i] = deviceUserCodeAlphabet[v]
	}
	return string(b)
}

// POST /api/login/oauth/device_authorization — 设备端申请授权（免会话）
//
// 该端点由设备（CLI / TV / IoT）调用，不携带用户会话，因此放在 CSRF 组之外，
// 仅校验 client_id 是否有效。
func (h *Handler) HandleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": "无法解析请求体"})
		return
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	if clientID == "" {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "缺少 client_id"})
		return
	}
	var client models.OAuthClient
	if err := h.db.NewSelect().Model(&client).Where("id = ?", clientID).Scan(r.Context()); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "无效的客户端"})
		return
	}
	// 机密客户端必须出示密钥（RFC 8628 §3.1）。此前只校验 client_id 是否存在，
	// 等于任何知道 client_id 的人都能无限发起设备授权，刷出大量待确认记录。
	if clientConfidential(&client) && !auth.CheckPassword(client.SecretHash, r.Form.Get("client_secret")) {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "客户端密钥错误"})
		return
	}
	// scope 收敛到客户端已登记的范围内，避免设备端请求越权权限。
	scope := strings.TrimSpace(r.Form.Get("scope"))
	if scope == "" {
		scope = "openid"
	}
	scope = h.intersectScopes(r.Context(), scope, client.Scopes)

	userCode := ""
	for i := 0; i < 5; i++ {
		userCode = randomUserCode()
		if userCode == "" {
			writeJSON(w, 500, map[string]any{"error": "internal_error", "error_description": "生成授权码失败"})
			return
		}
		// user_code 唯一：并发下极小概率碰撞，重试几次即可。
		n, _ := h.db.NewSelect().Model((*models.DeviceAuthorization)(nil)).
			Where("user_code = ?", userCode).Count(r.Context())
		if n == 0 {
			break
		}
		userCode = ""
	}
	if userCode == "" {
		writeJSON(w, 500, map[string]any{"error": "internal_error", "error_description": "生成授权码失败"})
		return
	}

	da := &models.DeviceAuthorization{
		DeviceCode: auth.RandomToken(32),
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		Status:     models.DeviceAuthPending,
		Interval:   deviceCodeIntervalSeconds,
		ExpiresAt:  db.Now().Add(deviceCodeTTLSeconds * time.Second),
		CreatedAt:  db.Now(),
	}
	if _, err := h.db.NewInsert().Model(da).Exec(r.Context()); err != nil {
		writeJSON(w, 500, map[string]any{"error": "internal_error", "error_description": "创建设备授权失败"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"device_code":      da.DeviceCode,
		"user_code":        da.UserCode,
		"verification_uri": h.issuer(r) + "/device",
		// verification_uri_complete 带上 user_code，便于设备以二维码形式展示。
		"verification_uri_complete": h.issuer(r) + "/device?code=" + da.UserCode,
		"expires_in":                deviceCodeTTLSeconds,
		"interval":                  da.Interval,
	})
}

// deviceGrant 处理 grant_type=urn:ietf:params:oauth:grant-type:device_code 的令牌请求。
func (h *Handler) tokenByDeviceCode(w http.ResponseWriter, r *http.Request) {
	deviceCode := strings.TrimSpace(r.Form.Get("device_code"))
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	clientSecret := r.Form.Get("client_secret")
	if deviceCode == "" || clientID == "" {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": "缺少 device_code 或 client_id"})
		return
	}
	var da models.DeviceAuthorization
	if err := h.db.NewSelect().Model(&da).Where("device_code = ?", deviceCode).Scan(r.Context()); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "无效的设备码"})
		return
	}
	if da.ClientID != clientID {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "设备码不属于该客户端"})
		return
	}
	var client models.OAuthClient
	if err := h.db.NewSelect().Model(&client).Where("id = ?", clientID).Scan(r.Context()); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "无效的客户端"})
		return
	}
	// 机密客户端必须出示密钥，与授权码流保持一致。
	if clientConfidential(&client) && !auth.CheckPassword(client.SecretHash, clientSecret) {
		writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "客户端密钥错误"})
		return
	}
	// 过期：标记失效后返回 expired_token，并清理记录避免堆积。
	if db.Now().After(da.ExpiresAt) {
		_, _ = h.db.NewUpdate().Model((*models.DeviceAuthorization)(nil)).
			Set("status = ?", models.DeviceAuthExpired).
			Where("device_code = ?", deviceCode).Exec(r.Context())
		writeJSON(w, 400, map[string]any{
			"error":             deviceCodeErrors[models.DeviceAuthExpired].Err,
			"error_description": deviceCodeErrors[models.DeviceAuthExpired].Desc,
		})
		return
	}
	switch da.Status {
	case models.DeviceAuthApproved:
		// 已授权：签发令牌并删除记录（一次性兑换，防重放）。
		if da.UserID == 0 {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "授权状态异常"})
			return
		}
		access, refresh, idToken, tokOK := h.issueTokens(w, r, &client, da.UserID, da.Scope, "")
		if !tokOK {
			return
		}
		_, _ = h.db.NewDelete().Model((*models.DeviceAuthorization)(nil)).
			Where("device_code = ?", deviceCode).Exec(r.Context())
		payload := map[string]any{
			"access_token": access,
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if refresh != "" {
			payload["refresh_token"] = refresh
		}
		if idToken != "" {
			payload["id_token"] = idToken
		}
		writeJSON(w, 200, payload)
		return
	case models.DeviceAuthDenied:
		// 已拒绝：同样删除记录，防止客户端无限重试。
		_, _ = h.db.NewDelete().Model((*models.DeviceAuthorization)(nil)).
			Where("device_code = ?", deviceCode).Exec(r.Context())
		writeJSON(w, 400, map[string]any{
			"error":             deviceCodeErrors[models.DeviceAuthDenied].Err,
			"error_description": deviceCodeErrors[models.DeviceAuthDenied].Desc,
		})
		return
	default:
		writeJSON(w, 400, map[string]any{
			"error":             deviceCodeErrors[models.DeviceAuthPending].Err,
			"error_description": deviceCodeErrors[models.DeviceAuthPending].Desc,
		})
		return
	}
}

// ---- 门户侧：用户确认设备授权 ----

// POST /api/v1/oauth/device-authorizations — 用 user_code 查找待确认的授权
//
// 走 CSRF 组内，需登录态。返回待确认授权的基本信息（客户端名称/请求权限）。
func (h *Handler) handleDeviceAuthVerify(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		UserCode string `json:"userCode"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	code := strings.ToUpper(strings.TrimSpace(req.UserCode))
	if code == "" {
		fail(w, r, http.StatusBadRequest, "device.code_required", "请输入设备显示的授权码")
		return
	}
	// 按用户维度限流：防止用固定会话反复猜测 user_code。
	if !h.accountLimiter.AllowKey("devauth:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "尝试次数过多，请稍后再试")
		return
	}
	da := &models.DeviceAuthorization{}
	if err := h.db.NewSelect().Model(da).
		Where("user_code = ? AND status = ?", code, models.DeviceAuthPending).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "device.not_found", "授权码无效或已过期")
		return
	}
	if db.Now().After(da.ExpiresAt) {
		fail(w, r, http.StatusNotFound, "device.not_found", "授权码无效或已过期")
		return
	}
	// 认领语义：该授权码可能已被其他用户认领，此时对当前用户一律视为不存在。
	// 输入正确的 user_code 即完成认领——后续的批准/拒绝都必须是同一个用户，
	// 否则任何登录用户只要拿到（或猜中）码就能把别人的设备会话绑到自己账号上。
	if da.UserID != 0 && da.UserID != u.ID {
		fail(w, r, http.StatusNotFound, "device.not_found", "授权码无效或已过期")
		return
	}
	if da.UserID == 0 {
		// 条件更新（user_id = 0）保证并发下只有一个用户认领成功。
		res, err := h.db.NewUpdate().Model((*models.DeviceAuthorization)(nil)).
			Set("user_id = ?", u.ID).
			Where("device_code = ? AND user_id = 0", da.DeviceCode).Exec(r.Context())
		if err != nil {
			internal(w, r, err)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			fail(w, r, http.StatusNotFound, "device.not_found", "授权码无效或已过期")
			return
		}
		da.UserID = u.ID
	}
	ok(w, r, h.deviceAuthPayload(da))
}

// GET /api/v1/oauth/device-authorizations — 当前用户待确认的设备授权列表
func (h *Handler) handleDeviceAuthList(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 只返回「本用户已认领、仍待确认」的记录。
	// 未认领（user_id = 0）的记录不属于任何人，绝不能出现在列表里：否则任意登录
	// 用户都能直接读到他人设备上显示的 user_code，进而抢先批准该设备授权，
	// 把受害者的设备会话绑到攻击者账号上（会话混淆）。
	var items []models.DeviceAuthorization
	if err := h.db.NewSelect().Model(&items).
		Where("user_id = ? AND status = ?", u.ID, models.DeviceAuthPending).
		Order("created_at DESC").Limit(20).Scan(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for i := range items {
		out = append(out, h.deviceAuthPayload(&items[i]))
	}
	ok(w, r, out)
}

// GET /api/v1/oauth/device-authorizations/{id} — 单个待确认授权详情
func (h *Handler) handleDeviceAuthGet(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 只允许查看本人已认领的授权：未认领记录不属于任何人，不应对外暴露。
	da := &models.DeviceAuthorization{}
	if err := h.db.NewSelect().Model(da).
		Where("user_code = ? AND user_id = ?", chi.URLParam(r, "id"), u.ID).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "device.not_found", "授权码无效或已过期")
		return
	}
	ok(w, r, h.deviceAuthPayload(da))
}

// POST /api/v1/oauth/device-authorizations/{id} — 批准或拒绝
// body: { decision: "approve" | "deny" }
func (h *Handler) handleDeviceAuthDecide(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Decision string `json:"decision"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	code := strings.ToUpper(strings.TrimSpace(chi.URLParam(r, "id")))
	// 必须由「已认领该授权码的本人」批准/拒绝。未认领（user_id = 0）的记录一律
	// 拒绝：用户必须先在前端输入设备上显示的 user_code（走 Verify 认领），
	// 否则任何登录用户都能凭猜测/枚举直接批准他人的设备授权。
	da := &models.DeviceAuthorization{}
	if err := h.db.NewSelect().Model(da).
		Where("user_code = ? AND status = ? AND user_id = ?", code, models.DeviceAuthPending, u.ID).
		Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "device.not_found", "授权码无效或已过期")
		return
	}
	if db.Now().After(da.ExpiresAt) {
		fail(w, r, http.StatusNotFound, "device.not_found", "授权码无效或已过期")
		return
	}
	if req.Decision == "approve" {
		da.Status = models.DeviceAuthApproved
		now := db.Now()
		da.ApprovedAt = &now
	} else {
		da.Status = models.DeviceAuthDenied
	}
	if _, err := h.db.NewUpdate().Model(da).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	summary := "批准设备授权"
	if da.Status == models.DeviceAuthDenied {
		summary = "拒绝设备授权"
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:    "device_auth.decided",
		Summary: summary,
		Metadata: map[string]string{
			"clientId": da.ClientID,
			"userCode": da.UserCode,
		},
	})
	ok(w, r, h.deviceAuthPayload(da))
}

// deviceAuthPayload 构造设备授权的展示负载（含客户端名称与请求的权限）。
func (h *Handler) deviceAuthPayload(da *models.DeviceAuthorization) map[string]any {
	name := da.ClientID
	var c models.OAuthClient
	if err := h.db.NewSelect().Model(&c).Where("id = ?", da.ClientID).Scan(context.Background()); err == nil {
		name = auth.FirstNonEmpty(c.Name, c.ID)
	}
	remaining := int(time.Until(da.ExpiresAt).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return map[string]any{
		"userCode":   da.UserCode,
		"clientId":   da.ClientID,
		"clientName": name,
		"scope":      da.Scope,
		"status":     da.Status,
		"expiresAt":  da.ExpiresAt,
		"expiresIn":  remaining,
	}
}

// intersectScopes 把请求的 scope 收敛到客户端已登记的范围内。
// openid 始终保留（OIDC 的基础权限）。
//
// 客户端未登记任何 scope 时，只保留 openid：此前会原样返回请求的全部 scope，
// 等于「没登记权限 = 什么权限都能要」，与本函数「收敛」的语义相反。
//
// 同时剔除管理员在「OAuth 权限项」里已停用的权限：该开关此前只改库、
// 不参与任何判定，后台点「停用」不会有任何效果，反而给出虚假的安全感。
func (h *Handler) intersectScopes(ctx context.Context, requested string, allowed []string) string {
	set := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		set[s] = true
	}
	disabled := h.disabledOAuthScopes(ctx)
	kept := []string{"openid"}
	for _, s := range strings.Fields(requested) {
		if s == "openid" {
			continue
		}
		if !set[s] || disabled[s] {
			continue
		}
		kept = append(kept, s)
	}
	return strings.Join(kept, " ")
}

// disabledOAuthScopes 返回被管理员停用、不得再下发的权限集。
// openid 是必选基础权限（Required=true，不可关闭），无论如何都保留。
func (h *Handler) disabledOAuthScopes(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	var scopes []models.OAuthScope
	if err := h.db.NewSelect().Model(&scopes).Where("enabled = ?", false).Scan(ctx); err != nil {
		// 查库失败时按「无停用项」处理：宁可保守地继续按客户端登记范围授权，
		// 也不要因一次读失败把所有权限静默剔除导致功能整体不可用。
		return out
	}
	for i := range scopes {
		if scopes[i].Required {
			continue
		}
		out[scopes[i].Name] = true
	}
	return out
}
