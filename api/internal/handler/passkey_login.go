package handler

import (
	"database/sql"

	"encoding/json"
	"errors"

	"net/http"

	"strings"

	"github.com/h1s97x/openidp/api/internal/logging"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- 通行密钥（登录） ----

// POST /api/v1/session/passkey/begin
func (h *Handler) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	// 通行密钥需在系统设置中显式开启，且能确定依赖方 URL 才可用。
	cfg := h.ResolvePasskeyConfig(h.requestBaseURL(r))
	if h.passkeys == nil || !cfg.Enabled {
		fail(w, r, http.StatusServiceUnavailable, "passkey.unavailable", "通行密钥服务未启用")
		return
	}
	originHint := h.requestBaseURL(r)
	// 无密码登录：可选传 login 定位用户；不传时走 usernameless（可发现凭据）登录。
	var req struct {
		Login     string `json:"login"`
		ReturnURL string `json:"returnUrl"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	login := strings.TrimSpace(req.Login)

	// 未输入账号 → 可发现登录（浏览器端选择通行密钥）
	if login == "" {
		ceremonyID, optionsJSON, err := h.passkeys.BeginDiscoverableLogin(originHint)
		if err != nil {
			fail(w, r, http.StatusBadRequest, "passkey.begin_failed", "通行密钥初始化失败")
			return
		}
		ok(w, r, map[string]any{
			"ceremonyId": ceremonyID,
			"options":    json.RawMessage(optionsJSON),
		})
		return
	}

	u, err := findUserByAccount(r.Context(), h.db, login)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "user.not_found", "请先输入已注册的账号")
		return
	}
	if err != nil {
		fail(w, r, http.StatusBadRequest, "user.ambiguous", err.Error())
		return
	}
	ceremonyID, optionsJSON, err := h.passkeys.BeginLogin(u.ID, originHint)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "passkey.begin_failed", "通行密钥初始化失败")
		return
	}
	ok(w, r, map[string]any{
		"ceremonyId": ceremonyID,
		"options":    json.RawMessage(optionsJSON),
	})
}

// POST /api/v1/session/passkey/finish
func (h *Handler) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	cfg := h.ResolvePasskeyConfig(h.requestBaseURL(r))
	if h.passkeys == nil || !cfg.Enabled {
		fail(w, r, http.StatusServiceUnavailable, "passkey.unavailable", "通行密钥服务未启用")
		return
	}
	var req struct {
		CeremonyID string          `json:"ceremonyId"`
		Credential json.RawMessage `json:"credential"`
		ReturnURL  string          `json:"returnUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	var userID int64
	var err error
	switch h.passkeys.PeekKind(req.CeremonyID) {
	case "loginDiscoverable":
		userID, err = h.passkeys.FinishDiscoverableLogin(req.CeremonyID, req.Credential)
	default:
		userID, err = h.passkeys.FinishLogin(req.CeremonyID, req.Credential)
	}
	if err != nil {
		// 底层原因必须落日志：响应体只回一个笼统的「验证失败」，否则
		// 依赖方配置、标志位、签名、仪式过期等截然不同的故障在现场全部
		// 表现成同一个 400，无法区分。
		logging.Warn("🔐 [Passkey] 通行密钥登录验证失败: %v", err)
		fail(w, r, http.StatusBadRequest, "passkey.verification_failed", "通行密钥验证失败")
		return
	}
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", userID).Scan(r.Context()); err != nil {
		internal(w, r, err)
		return
	}

	// 双因素认证：通行密钥本身即强认证，不再要求二次验证
	h.completeLogin(w, r, &u, "passkey", "通行密钥登录成功")
}

// ---- 通行密钥管理（已登录） ----

// POST /api/v1/me/passkeys/begin
func (h *Handler) handleMePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	cfg := h.ResolvePasskeyConfig(h.requestBaseURL(r))
	if err != nil || h.passkeys == nil || !cfg.Enabled {
		fail(w, r, http.StatusServiceUnavailable, "passkey.unavailable", "通行密钥服务未启用")
		return
	}
	ceremonyID, optionsJSON, err := h.passkeys.BeginRegistration(u.ID, h.requestBaseURL(r))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "passkey.begin_failed", "通行密钥注册初始化失败")
		return
	}
	ok(w, r, map[string]any{
		"ceremonyId": ceremonyID,
		"options":    json.RawMessage(optionsJSON),
	})
}

// POST /api/v1/me/passkeys/finish
func (h *Handler) handleMePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	cfg := h.ResolvePasskeyConfig(h.requestBaseURL(r))
	if err != nil || h.passkeys == nil || !cfg.Enabled {
		fail(w, r, http.StatusServiceUnavailable, "passkey.unavailable", "通行密钥服务未启用")
		return
	}
	var req struct {
		CeremonyID string          `json:"ceremonyId"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if _, err := h.passkeys.FinishRegistration(req.CeremonyID, req.Name, req.Credential); err != nil {
		logging.Warn("🔐 [Passkey] 通行密钥注册失败: %v", err)
		fail(w, r, http.StatusBadRequest, "passkey.registration_failed", "通行密钥注册失败")
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "passkey.registered", Summary: "添加通行密钥"})
	ok(w, r, map[string]any{"success": true})
}

// DELETE /api/v1/me/passkeys/{id}
func (h *Handler) handleMePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	cfg := h.ResolvePasskeyConfig(h.requestBaseURL(r))
	if err != nil || h.passkeys == nil || !cfg.Enabled {
		fail(w, r, http.StatusServiceUnavailable, "passkey.unavailable", "通行密钥服务未启用")
		return
	}
	// 删除通行密钥属敏感操作：删除后该设备就再无法用通行密钥登录，等于把强认证
	// 降级。会话被盗时攻击者正需要这一步。必须先完成身份重验证（reauth），
	// 令牌用后即焚。此前该端点只校验普通会话，前端虽已携带 X-OpenIdP-Reauth 却无人校验。
	if !h.requireReauth(w, r, u, curSessionID(cur)) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/me/passkeys/")
	if err := h.passkeys.Delete(u.ID, id); err != nil {
		fail(w, r, http.StatusBadRequest, "passkey.delete_failed", "删除失败")
		return
	}
	ok(w, r, map[string]any{"success": true})
}

// GET /api/v1/me/passkeys
//
// 通行密钥未启用时不再返回 503：安全中心需要据此隐藏「添加通行密钥」入口、
// 展示未启用状态，而不是让前端拿到一个错误后既不提示也无法降级。
// 返回体统一为 {enabled, passkeys}，写操作（注册/删除）仍保持 503。
func (h *Handler) handleMePasskeysList(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	cfg := h.ResolvePasskeyConfig(h.requestBaseURL(r))
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if h.passkeys == nil || !cfg.Enabled {
		ok(w, r, map[string]any{"enabled": false, "passkeys": []any{}})
		return
	}
	items, err := h.passkeys.List(u.ID)
	if err != nil {
		internal(w, r, err)
		return
	}
	if items == nil {
		items = []map[string]any{}
	}
	ok(w, r, map[string]any{"enabled": true, "passkeys": items})
}
