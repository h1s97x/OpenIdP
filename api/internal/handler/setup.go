package handler

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// isInitialized reports whether the system has been set up yet, i.e. whether
// at least one user exists. 项目不再自动内置账号：只有当不存在任何用户时，才允许
// 进入首次部署初始化（setup）流程。
func (h *Handler) isInitialized(ctx context.Context) bool {
	n, err := h.db.NewSelect().Model((*models.User)(nil)).Count(ctx)
	if err != nil {
		return false
	}
	return n > 0
}

// dbInfo describes which database the running instance uses (for the setup page).
// 绝不回显完整 DSN（可能含密码），仅返回 provider 与脱敏后的主机信息。
func (h *Handler) dbInfo() map[string]any {
	if h.cfg.DatabaseURL == "" {
		// 只回显文件名，不回显完整路径。该端点在初始化前必须免登录可访问，
		// 返回服务器绝对路径会白送攻击者部署目录结构、系统用户名等信息。
		return map[string]any{
			"provider": "sqlite",
			"path":     filepath.Base(filepath.Join(h.cfg.DataDir, "openidp.db")),
		}
	}
	return map[string]any{
		// 与启动日志共用 db.Kind 这一个判定。
		"provider": db.Kind(h.cfg.DatabaseURL),
		"host":     maskDSN(h.cfg.DatabaseURL),
	}
}

// maskDSN returns a sanitized host[:port] from a DSN, hiding credentials.
func maskDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return db.Kind(dsn)
	}
	host := u.Host
	if host == "" {
		// MySQL DSN uses a different scheme; parse the authority manually.
		if at := strings.LastIndex(dsn, "@"); at >= 0 {
			rest := dsn[at+1:]
			if slash := strings.Index(rest, "/"); slash >= 0 {
				rest = rest[:slash]
			}
			return strings.TrimPrefix(rest, "tcp(")
		}
		return db.Kind(dsn)
	}
	return host
}

// GET /api/v1/setup/status — 初始化状态（公开，免 CSRF）。
func (h *Handler) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	ok(w, r, map[string]any{
		"initialized": h.isInitialized(r.Context()),
		"database":    h.dbInfo(),
	})
}

// setupIPAllowed reports whether the request's client IP may perform the
// first-run initialization. 默认允许从任意 IP 执行，便于远程/云环境部署时初始化。
func (h *Handler) setupIPAllowed(r *http.Request) bool {
	if h.cfg.SetupAllowRemote {
		return true
	}
	ip := net.ParseIP(clientIP(r))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// POST /api/v1/setup — 首次部署初始化：创建初始管理员账号（公开，免 CSRF）。
// 仅当系统尚未初始化（不存在任何用户）时可用；邮箱后续再绑定。
// 出于安全考虑，可通过 SETUP_ALLOW_REMOTE=false 限制仅本机/内网 IP 访问，防止公网被抢先初始化。
func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !h.setupIPAllowed(r) {
		fail(w, r, http.StatusForbidden, "setup.forbidden", "当前环境不允许从本机之外执行首次初始化，请通过 SSH/内网访问或设置 SETUP_ALLOW_REMOTE=true")
		return
	}
	// 串行化首次初始化：防止多个并发 setup 请求同时通过 isInitialized() 检查
	// 而重复创建管理员账号。
	h.setupOnce.Lock()
	defer h.setupOnce.Unlock()
	if h.isInitialized(r.Context()) {
		fail(w, r, http.StatusConflict, "setup.already_initialized", "系统已完成初始化，无需重复设置")
		return
	}
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	username := strings.TrimSpace(req.Username)
	if msg := validateUsername(username); msg != "" {
		fail(w, r, http.StatusBadRequest, "username.invalid", msg)
		return
	}
	// 初始化密码策略：仅要求长度 >= 8，不要求大小写 / 数字 / 特殊字符等额外条件。
	// 使用独立的宽松策略,避免受数据库中已有安全策略（如 RequireUppercase）影响。
	if msg := validatePassword(&models.SecurityPolicy{
		MinPasswordLength: 8,
		RequireUppercase:  false,
		RequireLowercase:  false,
		RequireNumber:     false,
		RequireSymbol:     false,
	}, req.Password); msg != "" {
		fail(w, r, http.StatusBadRequest, "setup.password_weak", msg)
		return
	}
	// 用户名按精确值判重（区分大小写）。
	n, _ := h.db.NewSelect().Model((*models.User)(nil)).
		Where("username = ?", username).Count(r.Context())
	if n > 0 {
		fail(w, r, http.StatusConflict, "user.exists", "用户名已被占用")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		internal(w, r, err)
		return
	}
	u := &models.User{
		Username:     username,
		DisplayName:  auth.FirstNonEmpty(req.DisplayName, username),
		AvatarURL:    defaultAvatarURL,
		PasswordHash: hash,
		PasswordSet:  true,
		IsAdmin:      true, // 首个账号为管理员
	}
	if err := h.createUser(r.Context(), u); err != nil {
		internal(w, r, err)
		return
	}
	// 初始化即签发会话，直接进入管理后台
	csrf := auth.RandomToken(32)
	sessID, err := h.issueSession(w, r, u, "password")
	if err != nil {
		internal(w, r, err)
		return
	}
	h.tokens.Set(csrf, u.ID, sessID)
	h.logEvent(r, u.ID, &models.Event{Type: "setup.success", Summary: "首次部署初始化，创建管理员账号"})
	ok(w, r, h.sessionPayload(u, csrf))
}
