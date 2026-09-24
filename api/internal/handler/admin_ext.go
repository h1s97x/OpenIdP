package handler

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/schema"

	"github.com/h1s97x/openidp/api/internal/db"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/cache"
	"github.com/h1s97x/openidp/api/internal/geolocation"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/system"
	"github.com/h1s97x/openidp/api/internal/timezone"
	"github.com/h1s97x/openidp/api/internal/version"
)

// ---- IP 归属地配置 ----

// loadLocationSetting 返回持久化的 IP 归属地配置。
func (h *Handler) loadLocationSetting() *models.LocationSetting {
	return cached(h.conf, peekLocation, storeLocation, h.fetchLocationSetting)
}

// fetchLocationSetting 读取配置；缺失时写入一行空配置。
// 初始化不填入任何内容：真实 IP 头 / 可信代理 / 数据库路径全部留空，
// 由管理员在「系统设置 → 归属地」中自行填写。
func (h *Handler) fetchLocationSetting() *models.LocationSetting {
	ls := &models.LocationSetting{}
	err := h.db.NewSelect().Model(ls).Where("id = 1").Scan(context.Background())
	if err != nil {
		ls = &models.LocationSetting{
			ID:             1,
			Enabled:        true,
			RealIPHeader:   "",
			TrustedProxies: "",
			UpdatedAt:      db.Now(),
		}
		_, _ = h.db.NewInsert().Model(ls).Exec(context.Background())
	}
	return ls
}

// GET /api/v1/admin/location
func (h *Handler) handleAdminGetLocation(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ok(w, r, h.loadLocationSetting())
}

// PUT /api/v1/admin/location
func (h *Handler) handleAdminUpdateLocation(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ls := h.loadLocationSetting()
	var req struct {
		Enabled        *bool  `json:"enabled"`
		DBPath         string `json:"dbPath"`
		V6DBPath       string `json:"v6DbPath"`
		RealIPHeader   string `json:"realIpHeader"`
		TrustedProxies string `json:"trustedProxies"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled != nil {
		ls.Enabled = *req.Enabled
	}
	ls.DBPath = strings.TrimSpace(req.DBPath)
	ls.V6DBPath = strings.TrimSpace(req.V6DBPath)
	ls.RealIPHeader = strings.TrimSpace(req.RealIPHeader)
	ls.TrustedProxies = strings.TrimSpace(req.TrustedProxies)
	ls.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(ls).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	ok(w, r, ls)
}

// POST /api/v1/admin/location/test — 用样例 IP 验证归属地解析是否可用
func (h *Handler) handleAdminTestLocation(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		SampleIP string `json:"sampleIp"`
	}
	_ = decodeJSONBody(r, &req)
	sample := strings.TrimSpace(req.SampleIP)
	if sample == "" {
		sample = "1.2.4.8"
	}
	region := ""
	if h.loadLocationSetting().Enabled {
		region = geolocation.Resolve(sample)
	}
	ok(w, r, map[string]any{
		"sampleIp":     sample,
		"sampleRegion": region,
		"resolved":     region != "",
	})
}

// ---- 审计日志（分页增强）与保留策略 ----

// GET /api/v1/admin/audit-events — 审计日志（唯一入口）
//
// 支持 q / type / endpoint / outcome / userId 五个过滤维度，
// 并按 user_id 预取用户名，前端无需再为每个事件单独查用户。
// 旧 /admin/audit 端点已移除：两套实现形状不一致且过滤维度更少。
func (h *Handler) handleAdminAuditEvents(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	page, pageSize := parsePage(r)
	q := h.db.NewSelect().Model((*models.Event)(nil))
	if t := strings.TrimSpace(r.URL.Query().Get("type")); t != "" {
		q = q.Where("type = ?", t)
	}
	if t := strings.TrimSpace(r.URL.Query().Get("endpoint")); t != "" {
		q = q.Where("type LIKE ?", "%"+escapeLike(t)+"%")
	}
	if o := strings.TrimSpace(r.URL.Query().Get("outcome")); o != "" {
		// outcome 语义：success / failure 按事件类型的后缀判定。
		if o == "failure" {
			q = q.Where("type LIKE ?", "%.failed%")
		} else if o == "success" {
			q = q.Where("type NOT LIKE ?", "%.failed%")
		}
	}
	// userId 支持精确数字 ID（非数字直接忽略，避免 PG 上类型转换报错 500）；
	// user 为按用户名/邮箱/昵称的模糊搜索（前端筛选框用）。
	if uid := strings.TrimSpace(r.URL.Query().Get("userId")); uid != "" {
		if n, err := strconv.ParseInt(uid, 10, 64); err == nil {
			q = q.Where("user_id = ?", n)
		}
	}
	if uname := strings.TrimSpace(r.URL.Query().Get("user")); uname != "" {
		like := "%" + escapeLike(uname) + "%"
		q = q.Where(
			`user_id IN (SELECT id FROM users WHERE username LIKE ? ESCAPE '!' OR email LIKE ? ESCAPE '!' OR display_name LIKE ? ESCAPE '!')`,
			like, like, like)
	}
	if s := strings.TrimSpace(r.URL.Query().Get("q")); s != "" {
		like := "%" + escapeLike(s) + "%"
		q = q.Where(
			`summary LIKE ? ESCAPE '!' OR ip_address LIKE ? ESCAPE '!' OR user_agent LIKE ? ESCAPE '!'`,
			like, like, like)
	}
	total, err := q.Clone().Count(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	var events []models.Event
	if err := q.Order("created_at DESC").Limit(pageSize).Offset((page-1)*pageSize).Scan(r.Context(), &events); err != nil {
		internal(w, r, err)
		return
	}
	if events == nil {
		events = []models.Event{}
	}
	// 预取用户名：避免前端逐条查询。
	usernames := map[int64]string{}
	if len(events) > 0 {
		seen := map[int64]bool{}
		ids := make([]int64, 0, len(events))
		for _, e := range events {
			if e.UserID > 0 && !seen[e.UserID] {
				seen[e.UserID] = true
				ids = append(ids, e.UserID)
			}
		}
		if len(ids) > 0 {
			var users []models.User
			if err := h.db.NewSelect().Model(&users).Where("id IN (?)", bunIn(ids)).Scan(r.Context()); err == nil {
				for _, u := range users {
					usernames[u.ID] = auth.FirstNonEmpty(u.DisplayName, u.Username)
				}
			}
		}
	}
	items := make([]map[string]any, 0, len(events))
	for i := range events {
		e := &events[i]
		item := map[string]any{
			"id":        e.ID,
			"userId":    e.UserID,
			"username":  usernames[e.UserID],
			"type":      e.Type,
			"summary":   e.Summary,
			"ipAddress": e.IPAddress,
			"ipRegion":  e.IPRegion,
			"userAgent": e.UserAgent,
			"metadata":  e.Metadata,
			"createdAt": e.CreatedAt,
		}
		// 兼容旧 /admin/audit 的下发结构：前端按 user.displayName 展示，
		// 这里补上嵌套的 user 对象，避免两个端点形状不一致。
		if e.UserID > 0 {
			if name, ok := usernames[e.UserID]; ok {
				item["user"] = map[string]any{"id": e.UserID, "displayName": name}
			}
		}
		items = append(items, item)
	}
	ok(w, r, map[string]any{"items": items, "page": page, "pageSize": pageSize, "total": total})
}

// GET /api/v1/admin/audit-stats?days=7 — 审计日志统计摘要。
//
// 为审计页顶部的统计卡提供数据：总量 / 成功 / 失败，以及最近 N 天的按天序列
// （迷你趋势线用）。失败判定与列表筛选口径一致：事件类型含 .failed。
func (h *Handler) handleAdminAuditStats(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	days := 7
	if v := strings.TrimSpace(r.URL.Query().Get("days")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 30 {
			days = n
		}
	}
	now := db.Now()

	total, err := h.db.NewSelect().Model((*models.Event)(nil)).Count(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	failed, err := h.db.NewSelect().Model((*models.Event)(nil)).
		Where("type LIKE ?", "%.failed%").Count(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}

	type dayPoint struct {
		At      string `json:"at"`
		Total   int64  `json:"total"`
		Success int64  `json:"success"`
		Failed  int64  `json:"failed"`
	}
	trend := make([]dayPoint, 0, days)
	for i := days - 1; i >= 0; i-- {
		start := timezone.StartOfDay(now).AddDate(0, 0, -i)
		end := start.AddDate(0, 0, 1)
		dayTotal, _ := h.db.NewSelect().Model((*models.Event)(nil)).
			Where("created_at >= ? AND created_at < ?", start, end).Count(r.Context())
		dayFailed, _ := h.db.NewSelect().Model((*models.Event)(nil)).
			Where("type LIKE ? AND created_at >= ? AND created_at < ?", "%.failed%", start, end).Count(r.Context())
		trend = append(trend, dayPoint{
			At:      start.Format("2006-01-02"),
			Total:   int64(dayTotal),
			Success: int64(dayTotal - dayFailed),
			Failed:  int64(dayFailed),
		})
	}
	ok(w, r, map[string]any{
		"windowDays": days,
		"total":      total,
		"success":    total - failed,
		"failed":     failed,
		"trend":      trend,
	})
}

// loadAuditSetting 返回审计保留策略。
func (h *Handler) loadAuditSetting() *models.AuditSetting {
	return cached(h.conf, peekAudit, storeAudit, h.fetchAuditSetting)
}

func (h *Handler) fetchAuditSetting() *models.AuditSetting {
	a := &models.AuditSetting{}
	err := h.db.NewSelect().Model(a).Where("id = 1").Scan(context.Background())
	if err != nil {
		a = &models.AuditSetting{
			ID: 1, RetentionDays: 90, ArchiveEnabled: true, LoginEventsOnly: false,
			UpdatedAt: db.Now(),
		}
		_, _ = h.db.NewInsert().Model(a).Exec(context.Background())
	}
	return a
}

// GET /api/v1/admin/audit-settings
func (h *Handler) handleAdminGetAuditSettings(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ok(w, r, h.loadAuditSetting())
}

// PUT /api/v1/admin/audit-settings
func (h *Handler) handleAdminUpdateAuditSettings(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	a := h.loadAuditSetting()
	var req struct {
		RetentionDays   *int  `json:"retentionDays"`
		ArchiveEnabled  *bool `json:"archiveEnabled"`
		LoginEventsOnly *bool `json:"loginEventsOnly"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RetentionDays != nil {
		if *req.RetentionDays < 0 {
			fail(w, r, http.StatusBadRequest, "audit.invalid_retention", "保留天数不能为负数")
			return
		}
		a.RetentionDays = *req.RetentionDays
	}
	if req.ArchiveEnabled != nil {
		a.ArchiveEnabled = *req.ArchiveEnabled
	}
	if req.LoginEventsOnly != nil {
		a.LoginEventsOnly = *req.LoginEventsOnly
	}
	a.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(a).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	ok(w, r, a)
}

// EventRetentionDays 返回审计事件的有效保留天数（<=0 表示永久保留）。
// 供清理任务使用：保留期全部来自「审计保留策略」，不再硬编码常量。
func (h *Handler) EventRetentionDays() int {
	a := h.loadAuditSetting()
	if a == nil {
		return db.DefaultEventRetentionDays
	}
	return a.RetentionDays
}

// AuditArchivePolicy 返回归档任务需要的策略快照（归档开关 + 保留天数）。
func (h *Handler) AuditArchivePolicy() (out struct {
	ArchiveEnabled bool
	RetentionDays  int
}) {
	a := h.loadAuditSetting()
	if a == nil {
		out.RetentionDays = db.DefaultEventRetentionDays
		return out
	}
	out.ArchiveEnabled = a.ArchiveEnabled
	out.RetentionDays = a.RetentionDays
	return out
}

// ---- 分类数据清理策略 ----

// loadDataCleanupSetting 返回数据清理策略。
func (h *Handler) loadDataCleanupSetting() *models.DataCleanupSetting {
	return cached(h.conf, peekCleanup, storeCleanup, h.fetchDataCleanupSetting)
}

func (h *Handler) fetchDataCleanupSetting() *models.DataCleanupSetting {
	d := &models.DataCleanupSetting{}
	err := h.db.NewSelect().Model(d).Where("id = 1").Scan(context.Background())
	if err != nil {
		d = &models.DataCleanupSetting{
			ID: 1, SessionRetentionDays: 30, TokenRetentionDays: 30,
			NotificationRetentionDays: 90, DeletionRequestRetentionDays: 180,
			UpdatedAt: db.Now(),
		}
		_, _ = h.db.NewInsert().Model(d).Exec(context.Background())
	}
	return d
}

// GET /api/v1/admin/data-cleanup
func (h *Handler) handleAdminGetDataCleanup(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ok(w, r, h.loadDataCleanupSetting())
}

// PUT /api/v1/admin/data-cleanup
func (h *Handler) handleAdminUpdateDataCleanup(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	d := h.loadDataCleanupSetting()
	var req struct {
		SessionRetentionDays         *int `json:"sessionRetentionDays"`
		TokenRetentionDays           *int `json:"tokenRetentionDays"`
		NotificationRetentionDays    *int `json:"notificationRetentionDays"`
		DeletionRequestRetentionDays *int `json:"deletionRequestRetentionDays"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	applyDays := func(v *int, field *int, name string) bool {
		if v == nil {
			return true
		}
		if *v < 0 {
			fail(w, r, http.StatusBadRequest, "cleanup.invalid_days", name+"不能为负数")
			return false
		}
		*field = *v
		return true
	}
	if !applyDays(req.SessionRetentionDays, &d.SessionRetentionDays, "会话保留天数") ||
		!applyDays(req.TokenRetentionDays, &d.TokenRetentionDays, "令牌保留天数") ||
		!applyDays(req.NotificationRetentionDays, &d.NotificationRetentionDays, "通知保留天数") ||
		!applyDays(req.DeletionRequestRetentionDays, &d.DeletionRequestRetentionDays, "注销申请保留天数") {
		return
	}
	d.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(d).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.conf.invalidate()
	ok(w, r, d)
}

// POST /api/v1/admin/data-cleanup/run — 按当前策略立即清理一轮
// 返回各分类删除的行数，便于管理员确认清理效果。
func (h *Handler) handleAdminRunDataCleanup(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	d := h.loadDataCleanupSetting()
	now := db.Now()
	deleted := map[string]int{}
	if d.SessionRetentionDays > 0 {
		cutoff := now.AddDate(0, 0, -d.SessionRetentionDays)
		res, _ := h.db.NewDelete().Model((*models.Session)(nil)).
			Where("expires_at < ?", cutoff).Exec(r.Context())
		deleted["sessions"] = affected(res)
	}
	if d.TokenRetentionDays > 0 {
		cutoff := now.AddDate(0, 0, -d.TokenRetentionDays)
		res, _ := h.db.NewDelete().Model((*models.Token)(nil)).
			Where("expires_at < ?", cutoff).Exec(r.Context())
		deleted["tokens"] = affected(res)
	}
	if d.NotificationRetentionDays > 0 {
		cutoff := now.AddDate(0, 0, -d.NotificationRetentionDays)
		res, _ := h.db.NewDelete().Model((*models.Notification)(nil)).
			Where("read = true AND created_at < ?", cutoff).Exec(r.Context())
		deleted["notifications"] = affected(res)
	}
	if d.DeletionRequestRetentionDays > 0 {
		cutoff := now.AddDate(0, 0, -d.DeletionRequestRetentionDays)
		res, _ := h.db.NewDelete().Model((*models.AccountDeletionRequest)(nil)).
			Where("status IN (?) AND created_at < ?",
				bunIn([]string{models.DeletionStatusCompleted, models.DeletionStatusRejected, models.DeletionStatusCancelled}),
				cutoff).Exec(r.Context())
		deleted["accountDeletionRequests"] = affected(res)
	}
	ok(w, r, map[string]any{"deleted": deleted})
}

// GET /api/v1/admin/data-cleanup/usage — 清理前的占用概览。
//
// 回答运维在点「立即清理」之前真正关心的两个问题：现在有多大、这一轮能清掉多少。
// 「待清理」的判定条件与 handleAdminRunDataCleanup 完全一致（读同一份保留策略），
// 因此这里的数字与点下按钮后实际删除的行数对得上（同一天内）。
// 缓存与存储的字节数取自各自后端的真实统计，不做估算。
func (h *Handler) handleAdminGetDataCleanupUsage(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	d := h.loadDataCleanupSetting()
	now := db.Now()
	ctx := r.Context()

	// 保留天数为 0 表示该类别不参与清理，待清理数保持 0（与 run 的跳过条件一致）。
	type recordUsage struct {
		Total int `json:"total"`
		Stale int `json:"stale"`
	}
	countRecords := func(days int, model any, where string, args ...any) recordUsage {
		u := recordUsage{}
		u.Total, _ = h.db.NewSelect().Model(model).Count(ctx)
		if days > 0 {
			u.Stale, _ = h.db.NewSelect().Model(model).Where(where, args...).Count(ctx)
		}
		return u
	}

	records := map[string]recordUsage{
		"sessions": countRecords(d.SessionRetentionDays, (*models.Session)(nil),
			"expires_at < ?", now.AddDate(0, 0, -d.SessionRetentionDays)),
		"tokens": countRecords(d.TokenRetentionDays, (*models.Token)(nil),
			"expires_at < ?", now.AddDate(0, 0, -d.TokenRetentionDays)),
		"notifications": countRecords(d.NotificationRetentionDays, (*models.Notification)(nil),
			"read = true AND created_at < ?", now.AddDate(0, 0, -d.NotificationRetentionDays)),
		"accountDeletionRequests": countRecords(d.DeletionRequestRetentionDays, (*models.AccountDeletionRequest)(nil),
			"status IN (?) AND created_at < ?",
			bunIn([]string{models.DeletionStatusCompleted, models.DeletionStatusRejected, models.DeletionStatusCancelled}),
			now.AddDate(0, 0, -d.DeletionRequestRetentionDays)),
	}

	// 缓存：只有实现了 StatsReporter 的后端才报规模，否则只给类型。
	cacheInfo := map[string]any{"kind": h.cache.Kind()}
	if sr, ok := h.cache.(cache.StatsReporter); ok {
		st := sr.Stats()
		cacheInfo["entries"] = st.Entries
		cacheInfo["bytes"] = st.Bytes
	}

	storage, err := h.storageUsage(ctx)
	if err != nil {
		internal(w, r, err)
		return
	}

	ok(w, r, map[string]any{
		"generatedAt": now,
		"retention": map[string]int{
			"sessionRetentionDays":         d.SessionRetentionDays,
			"tokenRetentionDays":           d.TokenRetentionDays,
			"notificationRetentionDays":    d.NotificationRetentionDays,
			"deletionRequestRetentionDays": d.DeletionRequestRetentionDays,
		},
		"cache":   cacheInfo,
		"storage": storage,
		"records": records,
	})
}

// ---- 系统状态 ----

// GET /api/v1/admin/system-status — 运行状态面板（CPU / 内存 / 存储 / 版本 / 启动时间）
//
// 只保留运维真正关心的指标：不再下发 Go 版本、构建提交与构建时间。
func (h *Handler) handleAdminSystemStatus(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	dbOK := true
	if err := h.db.PingContext(r.Context()); err != nil {
		dbOK = false
	}
	host := system.Collect(h.cfg.DataDir)
	v := version.Get()
	ok(w, r, map[string]any{
		"status": "ok",
		"signal": "running",
		"database": map[string]any{
			"ok":   dbOK,
			"kind": dbKind(h.cfg.DatabaseURL),
		},
		"cache": map[string]any{
			"kind": h.cache.Kind(),
		},
		// cpu / memory / disk：used、total 为字节（CPU 为时间片），percent 为占用率。
		"cpu":    host.CPU,
		"memory": host.Memory,
		"disk":   host.Disk,
		"version": map[string]any{
			"version": v.Version,
		},
		"uptime":    uptimeSeconds(),
		"startedAt": startTime,
	})
}

// ---- OAuth 权限项 ----

// GET /api/v1/admin/oauth-scopes — 权限项清单（缺失时按内置清单初始化）
func (h *Handler) handleAdminOAuthScopes(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var scopes []models.OAuthScope
	_ = h.db.NewSelect().Model(&scopes).Order("name ASC").Scan(r.Context())
	if len(scopes) == 0 {
		scopes = defaultOAuthScopes()
		for i := range scopes {
			_, _ = h.db.NewInsert().Model(&scopes[i]).Ignore().Exec(r.Context())
		}
	}
	ok(w, r, map[string]any{"items": scopes})
}

// defaultOAuthScopes 是内置的 OAuth 权限项清单。
// 顺序即界面展示顺序：id → 资料 → 邮箱 → 手机号 → 地址 → 离线访问。
func defaultOAuthScopes() []models.OAuthScope {
	now := db.Now()
	return []models.OAuthScope{
		{Name: "openid", DisplayName: "身份标识", Description: "获取用户的唯一标识（必选）", Enabled: true, Required: true, UpdatedAt: now},
		{Name: "profile", DisplayName: "基本资料", Description: "获取用户名、昵称与头像", Enabled: true, Required: false, UpdatedAt: now},
		{Name: "email", DisplayName: "邮箱地址", Description: "获取用户的邮箱地址与验证状态", Enabled: true, Required: false, UpdatedAt: now},
		{Name: "phone", DisplayName: "手机号码", Description: "获取用户绑定的手机号", Enabled: false, Required: false, UpdatedAt: now},
		{Name: "address", DisplayName: "联系地址", Description: "获取用户填写的联系地址", Enabled: true, Required: false, UpdatedAt: now},
		{Name: "offline_access", DisplayName: "离线访问", Description: "允许应用在用户离线时刷新令牌", Enabled: true, Required: false, UpdatedAt: now},
	}
}

// PUT /api/v1/admin/oauth-scopes — 更新权限项说明与开关
func (h *Handler) handleAdminUpdateOAuthScope(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		fail(w, r, http.StatusBadRequest, "scope.name_required", "缺少权限项名称")
		return
	}
	s := &models.OAuthScope{}
	if err := h.db.NewSelect().Model(s).Where("name = ?", name).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "scope.not_found", "权限项不存在")
		return
	}
	s.DisplayName = strings.TrimSpace(req.DisplayName)
	s.Description = strings.TrimSpace(req.Description)
	s.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(s).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, s)
}

// setOAuthScopeEnabled 启停单个权限项；基础权限（openid）不允许关闭。
func (h *Handler) setOAuthScopeEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	name := chi.URLParam(r, "id")
	s := &models.OAuthScope{}
	if err := h.db.NewSelect().Model(s).Where("name = ?", name).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "scope.not_found", "权限项不存在")
		return
	}
	if !enabled && s.Required {
		fail(w, r, http.StatusBadRequest, "scope.required", "该权限项为基础权限，不可关闭")
		return
	}
	s.Enabled = enabled
	s.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(s).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, s)
}

// POST /api/v1/admin/oauth-scopes/{id}/enable
func (h *Handler) handleAdminEnableOAuthScope(w http.ResponseWriter, r *http.Request) {
	h.setOAuthScopeEnabled(w, r, true)
}

// POST /api/v1/admin/oauth-scopes/{id}/disable
func (h *Handler) handleAdminDisableOAuthScope(w http.ResponseWriter, r *http.Request) {
	h.setOAuthScopeEnabled(w, r, false)
}

// ---- 定点通知（广播）----

// GET /api/v1/admin/notifications — 最近发出的广播通知
func (h *Handler) handleAdminListNotifications(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	page, pageSize := parsePage(r)
	var items []models.Notification
	q := h.db.NewSelect().Model(&items).Where("type = ?", "admin")
	total, _ := q.Clone().Count(r.Context())
	if err := q.Order("created_at DESC").Limit(pageSize).Offset((page-1)*pageSize).Scan(r.Context(), &items); err != nil {
		internal(w, r, err)
		return
	}
	if items == nil {
		items = []models.Notification{}
	}
	ok(w, r, map[string]any{"items": items, "page": page, "pageSize": pageSize, "total": total})
}

// POST /api/v1/admin/notifications — 向全体用户或指定用户发送通知
// broadcastPresets 是定点通知的目标预设清单。
//
// preset 与 userIds 二者取一：preset 由服务端解析成用户集合，
// userIds 为管理员手工勾选的目标。allUsers 表示全量广播。
var broadcastPresets = map[string]string{
	"all":              "全部用户",
	"admin":            "管理员",
	"email_unverified": "邮箱未验证",
	"no_passkey":       "未启用通行密钥",
	"never_login":      "从未登录",
}

// resolveBroadcastPreset 把预设名解析为目标用户 ID 列表。
func (h *Handler) resolveBroadcastPreset(ctx context.Context, preset string) ([]int64, bool) {
	var ids []int64
	switch preset {
	case "all":
		if err := h.db.NewSelect().Model((*models.User)(nil)).Column("id").Scan(ctx, &ids); err != nil {
			return nil, false
		}
	case "admin":
		if err := h.db.NewSelect().Model((*models.User)(nil)).Column("id").
			Where("is_admin = ?", true).Scan(ctx, &ids); err != nil {
			return nil, false
		}
	case "email_unverified":
		if err := h.db.NewSelect().Model((*models.User)(nil)).Column("id").
			Where("email_verified = ?", false).Scan(ctx, &ids); err != nil {
			return nil, false
		}
	case "no_passkey":
		// 排除已注册通行密钥的用户。
		if err := h.db.NewSelect().Model((*models.User)(nil)).Column("u.id").
			Where("u.id NOT IN (SELECT DISTINCT user_id FROM passkeys)").Scan(ctx, &ids); err != nil {
			return nil, false
		}
	case "never_login":
		if err := h.db.NewSelect().Model((*models.User)(nil)).Column("u.id").
			Where("u.id NOT IN (SELECT DISTINCT user_id FROM sessions)").Scan(ctx, &ids); err != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	return ids, true
}

// GET /api/v1/admin/notification-presets — 定点通知的目标预设与命中人数
func (h *Handler) handleAdminNotificationPresets(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	items := make([]map[string]any, 0, len(broadcastPresets))
	for _, key := range []string{"all", "admin", "email_unverified", "no_passkey", "never_login"} {
		ids, ok := h.resolveBroadcastPreset(r.Context(), key)
		count := 0
		if ok {
			count = len(ids)
		}
		items = append(items, map[string]any{
			"key": key, "label": broadcastPresets[key], "count": count,
		})
	}
	ok(w, r, map[string]any{"items": items})
}

// POST /api/v1/admin/notifications — 发送定点通知
//
// 目标三选一：allUsers=true 全量；preset 走服务端预设；userIds 为手工勾选。
// 三者都没有时直接报错，不再静默地广播给全部用户。
func (h *Handler) handleAdminBroadcastNotification(w http.ResponseWriter, r *http.Request) {
	u, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Title    string  `json:"title"`
		Summary  string  `json:"summary"`
		UserIDs  []int64 `json:"userIds"`
		Preset   string  `json:"preset"`
		AllUsers bool    `json:"allUsers"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	req.Summary = strings.TrimSpace(req.Summary)
	req.Preset = strings.TrimSpace(req.Preset)
	if req.Title == "" {
		fail(w, r, http.StatusBadRequest, "notification.title_required", "请填写通知标题")
		return
	}
	if len([]rune(req.Title)) > 100 {
		fail(w, r, http.StatusBadRequest, "notification.title_too_long", "通知标题最多 100 个字符")
		return
	}
	var targets []int64
	switch {
	case req.AllUsers:
		if err := h.db.NewSelect().Model((*models.User)(nil)).Column("id").Scan(r.Context(), &targets); err != nil {
			internal(w, r, err)
			return
		}
	case req.Preset != "":
		ids, ok := h.resolveBroadcastPreset(r.Context(), req.Preset)
		if !ok {
			fail(w, r, http.StatusBadRequest, "notification.invalid_preset", "通知目标预设无效")
			return
		}
		targets = ids
	case len(req.UserIDs) > 0:
		targets = req.UserIDs
	default:
		fail(w, r, http.StatusBadRequest, "notification.target_required", "请选择通知目标用户")
		return
	}
	// 上限保护：广播是全表写入，限制单次目标数量避免长事务。
	if len(targets) > 5000 {
		fail(w, r, http.StatusBadRequest, "notification.too_many_targets", "单次通知最多覆盖 5000 名用户")
		return
	}
	now := db.Now()
	var rows []models.Notification
	for _, id := range targets {
		rows = append(rows, models.Notification{
			UserID: id, Type: "admin", Title: req.Title, Summary: req.Summary,
			Read: false, CreatedAt: now,
			Metadata: map[string]string{"senderId": itoa64(u.ID)},
		})
	}
	if len(rows) > 0 {
		if _, err := h.db.NewInsert().Model(&rows).Exec(r.Context()); err != nil {
			internal(w, r, err)
			return
		}
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:     "admin.broadcast",
		Summary:  "发送定点通知：" + req.Title,
		Metadata: map[string]string{"targets": itoa64(int64(len(rows)))},
	})
	ok(w, r, map[string]any{"success": true, "delivered": len(rows)})
}

// affected 从删除结果中取出受影响行数（失败时视为 0）。
func affected(res sql.Result) int {
	if res == nil {
		return 0
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return int(n)
}

// itoa64 是 strconv.FormatInt 的简写（int64 → 十进制字符串）。
func itoa64(v int64) string {
	return strconv.FormatInt(v, 10)
}

// bunIn 是 IN 子句参数的包装。
// 统一走这一层，避免各处直接拼接 IN 列表。
// 底层使用 bun.List：bun.In 已被上游标记废弃（语义等价，List 直接生成逗号分隔列表）。
func bunIn[T any](values []T) schema.QueryAppender {
	return bun.List(values)
}

// dbKind 返回当前数据库类型（sqlite / postgres / mysql），供运行状态面板展示。
func dbKind(databaseURL string) string {
	return db.Kind(databaseURL)
}

// startTime 记录进程启动时刻，用于计算运行时长。
var startTime = db.Now()

// uptimeSeconds 返回进程已运行的秒数。
func uptimeSeconds() int64 {
	return int64(time.Since(startTime).Seconds())
}
