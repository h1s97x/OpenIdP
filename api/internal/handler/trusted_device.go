package handler

import (
	"context"

	"net/http"

	"strings"

	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- 可信设备（跳过二次验证）----

// deviceIDFromRequest 返回当前浏览器携带的设备 Cookie 值（无则空串）。
// 设备 Cookie 由 issueSession 在每次登录时下发，可信设备即绑定在该值上。
func (h *Handler) deviceIDFromRequest(r *http.Request) string {
	if c, err := r.Cookie(h.cfg.DeviceCookieName); err == nil {
		return strings.TrimSpace(c.Value)
	}
	return ""
}

// trustedDeviceTTLDays 返回可信设备的有效天数：
// 后台安全策略（SecurityPolicy.TrustedDeviceTTLDays）优先，未配置时回退环境变量
// DEVICE_TTL_DAYS，避免配置项写了却不生效。
func (h *Handler) trustedDeviceTTLDays() int {
	sp := h.loadSecurityPolicy()
	if sp != nil && sp.TrustedDeviceTTLDays > 0 {
		return sp.TrustedDeviceTTLDays
	}
	if h.cfg.DeviceTTLDays > 0 {
		return h.cfg.DeviceTTLDays
	}
	return 365
}

// isTrustedDevice reports whether the device cookie of the current request is a
// trusted device of the user. 命中条件：device_id 匹配、归属该用户且未过期。
//
// 可信设备用于在密码 / 邮箱验证码登录时跳过二次验证（通行密钥本身即强认证，
// 无需再走这条路径）。设备 Cookie 缺失或设备未标记为可信时一律返回 false，
// 即"默认要求二次验证"。
func (h *Handler) isTrustedDevice(r *http.Request, userID int64) bool {
	devID := h.deviceIDFromRequest(r)
	if devID == "" {
		return false
	}
	n, err := h.db.NewSelect().Model((*models.TrustedDevice)(nil)).
		Where("user_id = ?", userID).
		Where("device_id = ?", devID).
		Where("expires_at > ?", db.Now()).
		Limit(1).Count(r.Context())
	if err != nil {
		return false
	}
	return n > 0
}

// touchTrustedDevice 在可信设备登录后刷新其最后活跃时间，
// 便于用户从「设备会话」页确认该设备仍在使用。
func (h *Handler) touchTrustedDevice(ctx context.Context, userID int64, devID string) {
	if devID == "" {
		return
	}
	_, _ = h.db.NewUpdate().Model((*models.TrustedDevice)(nil)).
		Set("last_seen_at = ?", db.Now()).
		Where("user_id = ?", userID).
		Where("device_id = ?", devID).
		Exec(ctx)
}
