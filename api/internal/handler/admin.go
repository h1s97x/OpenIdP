package handler

import (
	"net/http"

	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/metrics"

	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// requireAdmin resolves the current user and returns 403 unless they are admin.
func (h *Handler) requireAdmin(r *http.Request) (*models.User, bool) {
	u, _, err := h.currentUser(r)
	if err != nil {
		return nil, false
	}
	return u, u.IsAdmin
}

func adminForbidden(w http.ResponseWriter, r *http.Request) {
	fail(w, r, http.StatusForbidden, "admin.forbidden", "需要管理员权限")
}

// ---- 管理员能力位（随用户返回）----

// adminCapabilities returns admin feature flags based on the user.
func (h *Handler) adminCapabilities(u *models.User) map[string]bool {
	flags := map[string]bool{
		"dashboard": false, "auditEvents": false, "notifications": false, "users": false,
		"oauthClients": false, "oauthGrants": false, "oauthProviders": false,
		"mail": false, "location": false, "site": false, "storage": false,
		"securityPolicy": false, "oauthScopes": false,
		"dataCleanup": false, "systemStatus": false,
	}
	if u == nil || !u.IsAdmin {
		return flags
	}
	for k := range flags {
		flags[k] = true
	}
	return flags
}

// ---- Admin dashboard ----

// GET /api/v1/admin/dashboard
func (h *Handler) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	_, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	// 统计日界按系统时区切分（默认 UTC+8），保证「今日」与本地自然日一致。
	now := db.Now()
	dayStart := timezone.StartOfDay(now)

	totalUsers, _ := h.db.NewSelect().Model((*models.User)(nil)).Count(r.Context())
	todayUsers, _ := h.db.NewSelect().Model((*models.User)(nil)).Where("created_at >= ?", dayStart).Count(r.Context())
	totalSessions, _ := h.db.NewSelect().Model((*models.Session)(nil)).Where("expires_at > ?", now).Count(r.Context())
	totalEvents, _ := h.db.NewSelect().Model((*models.Event)(nil)).Count(r.Context())
	todayLogins, _ := h.db.NewSelect().Model((*models.Event)(nil)).
		Where("type = 'login.success' AND created_at >= ?", dayStart).Count(r.Context())
	activeApps, _ := h.db.NewSelect().Model((*models.OAuthClient)(nil)).Count(r.Context())

	type trendPoint struct {
		At    string `json:"at"`
		Count int64  `json:"count"`
	}
	trend := make([]trendPoint, 0, 7)
	for i := 6; i >= 0; i-- {
		start := timezone.StartOfDay(now).AddDate(0, 0, -i)
		end := start.AddDate(0, 0, 1)
		c, _ := h.db.NewSelect().Model((*models.Event)(nil)).
			Where("type = 'login.success' AND created_at >= ? AND created_at < ?", start, end).
			Count(r.Context())
		trend = append(trend, trendPoint{At: start.Format("2006-01-02"), Count: int64(c)})
	}

	// 「需要关注的事件」：概览只取失败/异常事件作为风险提示（口径与审计日志的
	// outcome=failure 一致，即事件类型后缀 .failed）。全部最近事件在审计日志页，
	// 概览再列一份只是重复同一份数据，反而稀释了「概览该看什么」。
	var recent []models.Event
	_ = h.db.NewSelect().Model(&recent).
		Where("type LIKE ?", "%.failed%").
		Order("created_at DESC").Limit(8).Scan(r.Context())

	ok(w, r, map[string]any{
		"generatedAt": now,
		"stats": map[string]any{
			"totalUsers":     totalUsers,
			"todayNewUsers":  todayUsers,
			"activeSessions": totalSessions,
			"totalEvents":    totalEvents,
			"todayLogins":    todayLogins,
			"activeApps":     activeApps,
		},
		"loginTrend":   trend,
		"recentEvents": recent,
	})
}

// GET /api/v1/admin/stats — 更丰富的用户行为统计（事件分类、登录方式、用户增长）。
func (h *Handler) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	_, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	snap, err := metrics.Compute(r.Context(), h.db)
	if err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, snap)
}
