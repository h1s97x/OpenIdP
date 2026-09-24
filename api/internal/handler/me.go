package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/uptrace/bun"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/logging"
	"github.com/h1s97x/openidp/api/internal/mfa"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/storage"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// GET /api/v1/me/profile
func (h *Handler) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	ok(w, r, u)
}

// PATCH /api/v1/me/profile
func (h *Handler) handlePatchProfile(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 只接受昵称与地址：手机号与邮箱各自有专用端点
	// （/me/phone*、/me/email*），后者还需先完成二次验证。
	//
	// 改动字段一律用指针区分「没传」与「传空」：
	// 早期版本这里会无条件写回 Phone —— 请求体漏传该字段就是空串，
	// 一次「只改昵称」的保存会把已有手机号清空并重置验证状态。
	// Address 同属这类隐患：漏传即清空，故 nil 表示不改、空串才是显式清空。
	var req struct {
		DisplayName string  `json:"displayName"`
		Address     *string `json:"address"`
		// Email 仅为兼容旧客户端保留：这里不提供改邮箱能力，
		// 传了不同地址（忽略大小写）就显式拒绝，避免对方「以为改了其实没改」地静默失败。
		Email *string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if req.Email != nil && strings.TrimSpace(*req.Email) != "" && !strings.EqualFold(strings.TrimSpace(*req.Email), u.Email) {
		// 改邮箱是高危操作（攻击者可借此配合"忘记密码"接管账户）：
		// 不再接受「当前密码 + 一次性校验」，改由必须先完成二次验证
		// （POST /me/step-up）换取 step-up 令牌后再提交，避免会话被盗用时
		// 仅凭旧密码即可把账号邮箱改成攻击者地址。
		fail(w, r, http.StatusBadRequest, "email.use_change_endpoint", "请通过更换邮箱流程提交（需先完成二次验证）")
		return
	}
	if req.DisplayName != "" {
		u.DisplayName = req.DisplayName
	}
	if req.Address != nil {
		u.Address = *req.Address
	}
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, u)
}

// POST /api/v1/me/password
// 修改密码成功后强制使该用户其它会话全部失效，防止已泄露/已盗用的旧会话
// 在密码更新后仍可继续使用（会话持久风险）。
func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if !auth.CheckPassword(u.PasswordHash, req.OldPassword) {
		h.audit(r, "failure", "password", "change_password", u.ID, "原密码校验失败")
		fail(w, r, http.StatusBadRequest, "password.incorrect", "原密码错误")
		return
	}
	if msg := validatePassword(h.loadSecurityPolicy(), req.NewPassword); msg != "" {
		fail(w, r, http.StatusBadRequest, "password.too_weak", msg)
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		internal(w, r, err)
		return
	}
	u.PasswordHash = hash
	u.PasswordSet = true
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	// 已被攻陷/泄露的旧会话（无论何种设备或获得途径）从此全部失效。
	if cur != nil {
		if _, err := h.db.NewDelete().Model((*models.Session)(nil)).
			Where("user_id = ? AND id <> ?", u.ID, cur.ID).Exec(r.Context()); err != nil {
			internal(w, r, err)
			return
		}
	}
	h.logEvent(r, u.ID, &models.Event{Type: "password.changed", Summary: "修改密码，其它会话已全部下线"})
	h.audit(r, "success", "password", "change_password", u.ID, "已修改密码，其它会话全部下线")
	ok(w, r, map[string]any{"success": true})
}

// GET /api/v1/me/dashboard?window=7d|30d
func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "7d"
	}
	days := 7
	switch window {
	case "30d":
		days = 30
	case "24h":
		days = 1
	}

	since := db.Now().AddDate(0, 0, -days)

	type trendPoint struct {
		At    string `json:"at"`
		Count int64  `json:"count"`
	}

	methods := map[string]int64{"password": 0, "emailCode": 0, "passkey": 0, "thirdParty": 0, "other": 0}
	// 按 Metadata.method 分组统计各登录方式（与 login.success 事件的写入字段保持一致）
	var loginEvents []models.Event
	_ = h.db.NewSelect().Model(&loginEvents).
		Where("user_id = ? AND type = 'login.success' AND created_at >= ?", u.ID, since).
		Scan(r.Context())
	for _, e := range loginEvents {
		m := e.Metadata["method"]
		if m == "" {
			m = "other"
		}
		methods[m]++
	}

	// 「今日登录」按「过去 24 小时」口径统计，与卡片副标题一致。
	// 复用上面已查出的登录事件在内存里分桶，不额外查库。
	// 固定 24 桶：即使一小时内没有登录也要占位，否则趋势线的横轴会被压缩，
	// 空档期看起来像连续登录。
	hourly := make([]trendPoint, 24)
	loc := timezone.Location()
	now := db.Now().In(loc)
	nowHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, loc)
	start := nowHour.Add(-23 * time.Hour)
	for i := 0; i < 24; i++ {
		hourly[i] = trendPoint{At: start.Add(time.Duration(i) * time.Hour).Format("2006-01-02T15:00"), Count: 0}
	}
	hourIndex := make(map[string]int, 24)
	for i, p := range hourly {
		hourIndex[p.At] = i
	}
	for _, e := range loginEvents {
		if e.CreatedAt.Before(start) {
			continue
		}
		key := e.CreatedAt.In(loc).Format("2006-01-02T15:00")
		if idx, ok := hourIndex[key]; ok {
			hourly[idx].Count++
		}
	}
	var todayLogins int64
	for _, p := range hourly {
		todayLogins += p.Count
	}

	trend := make([]trendPoint, 0, days)
	// 会话与授权同样给出按天序列：总览统计卡的趋势线需要各自的真实数据源，
	// 复用登录趋势会让三张卡画出同一条曲线，读起来是误导。
	sessionTrend := make([]trendPoint, 0, days)
	grantTrend := make([]trendPoint, 0, days)
	for i := days - 1; i >= 0; i-- {
		start := timezone.StartOfDay(db.Now()).AddDate(0, 0, -i)
		end := start.AddDate(0, 0, 1)
		at := start.Format("2006-01-02")
		c, _ := h.db.NewSelect().Model((*models.Event)(nil)).
			Where("user_id = ? AND type = 'login.success' AND created_at >= ? AND created_at < ?", u.ID, start, end).
			Count(r.Context())
		trend = append(trend, trendPoint{At: at, Count: int64(c)})
		sc, _ := h.db.NewSelect().Model((*models.Session)(nil)).
			Where("user_id = ? AND created_at >= ? AND created_at < ?", u.ID, start, end).
			Count(r.Context())
		sessionTrend = append(sessionTrend, trendPoint{At: at, Count: int64(sc)})
		gc, _ := h.db.NewSelect().Model((*models.Grant)(nil)).
			Where("user_id = ? AND created_at >= ? AND created_at < ?", u.ID, start, end).
			Count(r.Context())
		grantTrend = append(grantTrend, trendPoint{At: at, Count: int64(gc)})
	}

	var recent []models.Event
	// 总览「最近活动」只呈现登录与第三方授权两类事件：signup.success、
	// password.changed 等安全事件已有专门的事件页，混进来会干扰阅读。
	_ = h.db.NewSelect().Model(&recent).
		Where("user_id = ? AND type IN ('login.success','oauth.authorized','oauth.denied')", u.ID).
		Order("created_at DESC").Limit(6).Scan(r.Context())
	recentLogins := make([]map[string]any, 0, len(recent))
	for _, e := range recent {
		// 登录类事件没有关联应用，展示站点名；第三方授权等事件取 metadata 里记录的
		// 应用名（授权时写入），缺失时再回落到站点名。
		app := e.Metadata["clientName"]
		if app == "" {
			app = h.cfg.SiteDisplay
		}
		summary := e.Summary
		if summary == "" {
			summary = "登录成功"
		}
		recentLogins = append(recentLogins, map[string]any{
			"application": app,
			"summary":     summary,
			"type":        e.Type,
			"at":          e.CreatedAt,
			"id":          "event-" + strconv.FormatInt(e.ID, 10),
			"ipAddress":   e.IPAddress,
			"ipRegion":    e.IPRegion,
			"method":      e.Metadata["method"],
			"status":      "success",
			"userAgent":   e.UserAgent,
		})
	}

	ok(w, r, map[string]any{
		"generatedAt":  db.Now(),
		"loginMethods": methods,
		"loginTrend":   trend,
		"todayLogins":  todayLogins,
		"todayHourly":  hourly,
		"sessionTrend": sessionTrend,
		"grantTrend":   grantTrend,
		"recentLogins": recentLogins,
	})
}

// GET /api/v1/me/events?type=login.success&category=login
//
// category 是前端「安全事件」页的四个分类（login/profile/session/grant）。
// 它必须落在服务端过滤：此前前端一次性取一整页再在本地 filter，
// 而 parsePage 对超界 pageSize 会静默降级，导致分类统计只覆盖最新的一小部分
// 事件——「应用授权」这类低频分类长期显示 0，用户会误判没有可疑活动。
func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	q := h.db.NewSelect().Model((*models.Event)(nil)).Where("user_id = ?", u.ID)
	if t := r.URL.Query().Get("type"); t != "" {
		q = q.Where("type = ?", t)
	}
	if c := r.URL.Query().Get("category"); c != "" {
		if cond, args := eventCategoryCond(c); cond != "" {
			q = q.Where(cond, args...)
		}
	}
	page, pageSize := parsePage(r)
	total, err := q.Clone().Count(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	var events []models.Event
	// 深分页时 OFFSET 扫描代价随页码线性增长，这里对页码设上限。
	if page > maxEventPages {
		fail(w, r, http.StatusBadRequest, "request.page_out_of_range", "页码超出范围")
		return
	}
	if err := q.Order("created_at DESC").Limit(pageSize).Offset((page-1)*pageSize).Scan(r.Context(), &events); err != nil {
		internal(w, r, err)
		return
	}
	if events == nil {
		events = []models.Event{}
	}
	ok(w, r, map[string]any{
		"items":    events,
		"page":     page,
		"pageSize": pageSize,
		"total":    total,
	})
}

// maxEventPages 是安全事件列表的最大页码，防止深分页拖垮数据库。
const maxEventPages = 500

// GET /api/v1/me/events/counts
//
// 返回四个分类各自的事件总数，供安全事件页的页签与摘要使用。
// 必须走服务端统计：任何「取一页再本地 filter」的做法都只能统计到那一页，
// 会让低频分类长期显示 0。
func (h *Handler) handleEventCounts(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	countBy := func(cond string, args []any) int64 {
		q := h.db.NewSelect().Model((*models.Event)(nil)).Where("user_id = ?", u.ID)
		if cond != "" {
			q = q.Where(cond, args...)
		}
		n, err := q.Count(r.Context())
		if err != nil {
			return 0
		}
		return int64(n)
	}
	ok(w, r, map[string]any{
		"all":     countBy("", nil),
		"grant":   countBy(eventCategoryCond("grant")),
		"session": countBy(eventCategoryCond("session")),
		"login":   countBy(eventCategoryCond("login")),
		"profile": countBy(eventCategoryCond("profile")),
	})
}

// eventCategoryCond 生成事件分类的 SQL 条件，规则与前端 EventsPage 的
// categoryOf 严格一致：grant > session > login > 其余归 profile。
//
// 用 lower(type) 做匹配以屏蔽三种数据库在 LIKE 大小写敏感性上的差异
// （SQLite LIKE 默认不区分大小写，PostgreSQL 区分）。
func eventCategoryCond(category string) (string, []any) {
	loginExact := []any{"mfa.verify_failed", "mfa.challenge_locked"}
	switch category {
	case "grant":
		return "lower(type) LIKE ?", []any{"%grant%"}
	case "session":
		return "lower(type) LIKE ? OR lower(type) LIKE ?", []any{"%session%", "%logout%"}
	case "login":
		return "lower(type) LIKE ? OR lower(type) LIKE ? OR lower(type) IN (?)",
			[]any{"%login%", "%signin%", bun.List(loginExact)}
	case "profile":
		// 账号变更 = 不属于上述三类的全部事件
		return "NOT (lower(type) LIKE ? OR lower(type) LIKE ? OR lower(type) LIKE ? OR lower(type) LIKE ? OR lower(type) IN (?))",
			[]any{"%grant%", "%session%", "%logout%", "%login%", bun.List(loginExact)}
	}
	return "", nil
}

// GET /api/v1/me/sessions
func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var sessions []models.Session
	if err := h.db.NewSelect().Model(&sessions).Where("user_id = ?", u.ID).Order("created_at DESC").Scan(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	if sessions == nil {
		sessions = []models.Session{}
	}
	for i := range sessions {
		// 会话标识对外只暴露摘要（SessionHash 序列化为 id），
		// 当前会话判定同样按摘要比较，避免接触原始会话 ID。
		sessions[i].Current = cur != nil && sessions[i].SessionHash == cur.SessionHash
	}
	ok(w, r, sessions)
}

// DELETE /api/v1/me/sessions/{id}
func (h *Handler) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		fail(w, r, http.StatusBadRequest, "request.invalid_path", "无效的会话 ID")
		return
	}
	// 对外标识即 session_hash；当前会话判定与删除都按摘要进行。
	if cur != nil && id == cur.SessionHash {
		fail(w, r, http.StatusBadRequest, "session.current", "不能下线当前会话")
		return
	}
	res, err := h.db.NewDelete().Model((*models.Session)(nil)).
		Where("session_hash = ? AND user_id = ?", id, u.ID).Exec(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		fail(w, r, http.StatusNotFound, "session.not_found", "会话不存在或已下线")
		return
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:    "session.revoked",
		Summary: "下线指定会话",
		// 只记录摘要，且摘要本身不可反推出可用的会话 Cookie。
		Metadata: map[string]string{"sessionId": id},
	})
	ok(w, r, map[string]any{"success": true})
}

// DELETE /api/v1/me/sessions?scope=others
func (h *Handler) handleDeleteOtherSessions(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if cur == nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	res, err := h.db.NewDelete().Model((*models.Session)(nil)).
		Where("user_id = ? AND session_hash <> ?", u.ID, cur.SessionHash).Exec(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	n, _ := res.RowsAffected()
	h.logEvent(r, u.ID, &models.Event{
		Type:     "session.revoked",
		Summary:  "下线其它会话",
		Metadata: map[string]string{"count": strconv.FormatInt(n, 10)},
	})
	ok(w, r, map[string]any{"success": true, "revoked": n})
}

// GET /api/v1/me/devices
func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var devices []models.Device
	if err := h.db.NewSelect().Model(&devices).Where("user_id = ?", u.ID).Order("last_seen_at DESC").Scan(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	if devices == nil {
		devices = []models.Device{}
	}
	// 一次性统计所有设备的会话数与活跃会话数，避免逐设备 N+1 查询。
	type devAgg struct {
		DeviceID string `bun:"device_id"`
		Total    int    `bun:"total"`
		Active   int    `bun:"active"`
	}
	var aggs []devAgg
	_ = h.db.NewSelect().
		Column("device_id").
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS active", db.Now()).
		Model((*models.Session)(nil)).
		Where("user_id = ?", u.ID).
		Group("device_id").
		Scan(r.Context(), &aggs)
	aggByDevice := make(map[string]devAgg, len(aggs))
	for _, a := range aggs {
		aggByDevice[a.DeviceID] = a
	}
	for i := range devices {
		// 会话按 device_id（设备标识）归属设备；devices.id 自本次改版起是独立主键。
		if a, ok := aggByDevice[devices[i].DeviceID]; ok {
			devices[i].SessionCount = a.Total
			devices[i].ActiveSessionCnt = a.Active
		}
		devices[i].Current = cur != nil && devices[i].DeviceID != "" && devices[i].DeviceID == cur.DeviceID
	}
	ok(w, r, devices)
}

// GET /api/v1/me/grants
func (h *Handler) handleGrants(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 补上应用名与 Logo：grants 只存 client_id，直接下发给前端会让「我的授权」
	// 显示成一串无意义的机器标识。客户端可能已被删除，故 LEFT JOIN 后回落为 ID。
	type grantRow struct {
		ID         string    `bun:"id"`
		UserID     int64     `bun:"user_id"`
		ClientID   string    `bun:"client_id"`
		Scopes     []string  `bun:"scopes,type:json"`
		CreatedAt  time.Time `bun:"created_at"`
		ClientName string    `bun:"client_name"`
		ClientLogo string    `bun:"client_logo"`
		ClientURL  string    `bun:"client_url"`
	}
	var rows []grantRow
	// 每列都用「别名 AS 字段名」显式命名：JOIN 后同名列（如 created_at 在
	// grants / oauth_clients 两张表里都有）会让 bun 的字段回填错位。
	err = h.db.NewSelect().
		Model((*models.Grant)(nil)).
		ColumnExpr("g.id AS id, g.user_id AS user_id, g.client_id AS client_id, g.scopes AS scopes, g.created_at AS created_at").
		ColumnExpr("COALESCE(oc.name, '') AS client_name, COALESCE(oc.logo_url, '') AS client_logo, COALESCE(oc.homepage_url, '') AS client_url").
		Join("LEFT JOIN oauth_clients AS oc ON oc.id = g.client_id").
		Where("g.user_id = ?", u.ID).
		Order("g.created_at DESC").
		Scan(r.Context(), &rows)
	if err != nil {
		internal(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, g := range rows {
		scopes := g.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		// 权限明细：名称 / 说明 / 风险等级与授权同意页共用同一份定义，
		// 「我的授权」据此逐项展示应用能做什么、哪些属于高风险。
		details := scopeInfosFor(scopes)
		highRisk := 0
		for _, d := range details {
			if d.Level == "high" {
				highRisk++
			}
		}
		// 最近活跃：取该客户端下最近一次令牌签发/轮换时间（grants 本身不记录使用）。
		// 客户端可能从未换取过令牌，此时留空由前端回落到授权时间。
		var lastUsedAt any
		var tok models.Token
		if err := h.db.NewSelect().Model(&tok).
			Where("user_id = ? AND client_id = ?", g.UserID, g.ClientID).
			Order("created_at DESC").Limit(1).Scan(r.Context()); err == nil {
			lastUsedAt = tok.CreatedAt
		}
		// 出库前再过滤一次：历史数据或直接改库可能留下 javascript: 取值，
		// 前端渲染进 <img src> / <a href> 会变成存储型 XSS。
		logo, _ := sanitizeAssetURL(g.ClientLogo)
		homepage, _ := sanitizeExternalURL(g.ClientURL)
		items = append(items, map[string]any{
			"id":            g.ID,
			"userId":        g.UserID,
			"clientId":      g.ClientID,
			"scopes":        scopes,
			"scopeDetails":  details,
			"highRiskCount": highRisk,
			"createdAt":     g.CreatedAt,
			"lastUsedAt":    lastUsedAt,
			"clientName":    g.ClientName,
			"clientLogo":    logo,
			"clientUrl":     homepage,
		})
	}
	ok(w, r, items)
}

// DELETE /api/v1/me/grants/{id}
func (h *Handler) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	id := chi.URLParam(r, "id")
	var g models.Grant
	if err := h.db.NewSelect().Model(&g).Where("id = ? AND user_id = ?", id, u.ID).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "grant.not_found", "授权记录不存在")
		return
	}
	if _, err := h.db.NewDelete().Model((*models.Grant)(nil)).Where("id = ? AND user_id = ?", id, u.ID).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	// 撤销授权后立即使该用户在此客户端下的令牌失效，避免已签发的 token 继续访问。
	_, _ = h.db.NewUpdate().Model((*models.Token)(nil)).
		Set("revoked = ?", true).
		Where("user_id = ? AND client_id = ?", u.ID, g.ClientID).Exec(r.Context())
	// 记录授权撤销事件，供「登录记录」页面按「应用授权」分类展示。
	h.logEvent(r, u.ID, &models.Event{
		Type:     "grant.revoked",
		Summary:  "撤销应用授权",
		Metadata: map[string]string{"clientId": g.ClientID},
	})
	ok(w, r, map[string]any{"success": true})
}

// GET /api/v1/me/trusted-devices
func (h *Handler) handleTrustedDevices(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var tds []models.TrustedDevice
	if err := h.db.NewSelect().Model(&tds).Where("user_id = ?", u.ID).Order("created_at DESC").Scan(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	if tds == nil {
		tds = []models.TrustedDevice{}
	}
	// 标记当前浏览器所属设备，便于用户区分「这一台」与历史可信设备。
	cur := h.deviceIDFromRequest(r)
	for i := range tds {
		tds[i].Current = cur != "" && tds[i].DeviceID == cur
	}
	ok(w, r, tds)
}

// POST /api/v1/me/trusted-devices  {name}
func (h *Handler) handleAddTrustedDevice(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		req.Name = "新设备"
	}
	now := db.Now()
	devID := h.deviceIDFromRequest(r)
	// 过期记录已不具备跳过二次验证的能力，顺手清理，避免列表里堆积死条目
	// 让用户误以为仍在生效。
	_, _ = h.db.NewDelete().Model((*models.TrustedDevice)(nil)).
		Where("user_id = ?", u.ID).Where("expires_at <= ?", now).Exec(r.Context())
	if devID != "" {
		// 同一设备重复标记时更新有效期与名称，而不是堆出多条记录：
		// 多条同设备记录会让「可跳过 MFA」的实际生效范围变得不可预期。
		res, err := h.db.NewUpdate().Model((*models.TrustedDevice)(nil)).
			Set("name = ?", req.Name).
			Set("user_agent = ?", r.UserAgent()).
			Set("ip_address = ?", clientIP(r)).
			Set("ip_region = ?", requestRegion(r)).
			Set("expires_at = ?", now.AddDate(0, 0, h.trustedDeviceTTLDays())).
			Set("last_seen_at = ?", now).
			Where("user_id = ?", u.ID).Where("device_id = ?", devID).
			Exec(r.Context())
		if err != nil {
			internal(w, r, err)
			return
		}
		if n, _ := res.RowsAffected(); n > 0 {
			var existing models.TrustedDevice
			if err := h.db.NewSelect().Model(&existing).
				Where("user_id = ?", u.ID).Where("device_id = ?", devID).
				Scan(r.Context()); err == nil {
				existing.Current = true
				ok(w, r, existing)
				return
			}
		}
	}
	td := models.TrustedDevice{
		ID:         auth.NewID(),
		UserID:     u.ID,
		DeviceID:   devID,
		Name:       req.Name,
		UserAgent:  r.UserAgent(),
		IPAddress:  clientIP(r),
		IPRegion:   requestRegion(r),
		ExpiresAt:  now.AddDate(0, 0, h.trustedDeviceTTLDays()),
		LastSeenAt: now,
	}
	if _, err := h.db.NewInsert().Model(&td).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	td.Current = true
	ok(w, r, td)
}

// DELETE /api/v1/me/trusted-devices/{id}
func (h *Handler) handleDeleteTrustedDevice(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	id := chi.URLParam(r, "id")
	_, _ = h.db.NewDelete().Model((*models.TrustedDevice)(nil)).Where("id = ? AND user_id = ?", id, u.ID).Exec(r.Context())
	ok(w, r, map[string]any{"success": true})
}

// GET /api/v1/me/export
func (h *Handler) handleExport(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 导出全量安全事件：不做条数截断，否则导出的「个人数据」缺少历史记录。
	var events []models.Event
	_ = h.db.NewSelect().Model(&events).Where("user_id = ?", u.ID).Order("created_at DESC").Scan(r.Context())
	var grants []models.Grant
	_ = h.db.NewSelect().Model(&grants).Where("user_id = ?", u.ID).Scan(r.Context())
	var identities []models.Identity
	_ = h.db.NewSelect().Model(&identities).Where("user_id = ?", u.ID).Scan(r.Context())
	var sessions []models.Session
	_ = h.db.NewSelect().Model(&sessions).Where("user_id = ?", u.ID).Order("created_at DESC").Scan(r.Context())
	var devices []models.Device
	_ = h.db.NewSelect().Model(&devices).Where("user_id = ?", u.ID).Order("last_seen_at DESC").Scan(r.Context())
	var tds []models.TrustedDevice
	_ = h.db.NewSelect().Model(&tds).Where("user_id = ?", u.ID).Order("created_at DESC").Scan(r.Context())
	var passkeys []models.Passkey
	_ = h.db.NewSelect().Model(&passkeys).Where("user_id = ?", u.ID).Order("created_at DESC").Scan(r.Context())
	// 导出数据属于敏感操作（含设备指纹、IP、UA、全部安全事件），记录一次审计事件。
	h.logEvent(r, u.ID, &models.Event{Type: "data.exported", Summary: "导出个人数据"})
	payload := map[string]any{
		"authorizedApplications": grants,
		"exportedAt":             db.Now(),
		"devices":                devices,
		// 导出时带上完整的通行密钥列表（不含私钥/证明等敏感字段）。
		"linkedIdentities": identities,
		"passkeys":         passkeys,
		"profile":          u,
		"securityEvents":   events,
		"sessions":         sessions,
		"trustedDevices":   tds,
	}
	// 默认以附件下载形式返回（个人数据属于隐私，浏览器不应直接渲染/缓存）；
	// 需要 JSON 内联查看时显式加 ?inline=1。
	if r.URL.Query().Get("inline") != "1" {
		filename := "openidp-export-" + db.Now().Format("20060102-150405") + ".json"
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	}
	ok(w, r, payload)
}

// -------- 账号注销（申请 + 二次验证 + 冷静期 + 管理员审核）--------
//
// 注销是不可逆操作。整体流程：
//  1. 用户提交当前密码 + 二次验证（TOTP/恢复码；未开启 MFA 时用邮箱验证码）发起申请；
//  2. 申请进入冷静期（时长由管理员配置，可为 0），期间用户可随时撤回；
//  3. 冷静期结束后由系统设置的「注销账号」审核列表中管理员通过/驳回；
//  4. 通过后在事务内级联清理该用户的全部数据。
//
// 这样即使会话被盗用或误点，仍有挽回窗口，且管理员保留最终确认权。

// deletionCooldown 返回注销账号的冷静期时长（小时为单位的策略值 → Duration）。
func (h *Handler) deletionCooldown() time.Duration {
	sp := h.loadSecurityPolicy()
	if sp == nil || sp.AccountDeletionCooldownHours <= 0 {
		return 0
	}
	return time.Duration(sp.AccountDeletionCooldownHours) * time.Hour
}

// loadDeletionRequest 返回该用户当前处于待处理（pending / approved）的注销申请。
func (h *Handler) loadDeletionRequest(userID int64) (*models.AccountDeletionRequest, error) {
	req := &models.AccountDeletionRequest{}
	err := h.db.NewSelect().Model(req).
		Where("user_id = ?", userID).
		Where("status IN (?)", bun.List([]string{models.DeletionStatusPending, models.DeletionStatusApproved})).
		Order("created_at DESC").Limit(1).Scan(context.Background())
	if err != nil {
		return nil, err
	}
	return req, nil
}

// deletionPayload 构造前端展示用的申请状态（含剩余冷静期秒数）。
func deletionPayload(req *models.AccountDeletionRequest) map[string]any {
	if req == nil {
		return map[string]any{"status": "none"}
	}
	remaining := int(time.Until(req.ScheduledAt).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return map[string]any{
		"id":                req.ID,
		"status":            req.Status,
		"reason":            req.Reason,
		"scheduledAt":       req.ScheduledAt,
		"remainingSeconds":  remaining,
		"reviewNote":        req.ReviewNote,
		"createdAt":         req.CreatedAt,
		"cooldownRemaining": remaining > 0,
	}
}

// GET /api/v1/me/account-deletion — 查询当前账号的注销申请状态
func (h *Handler) handleGetAccountDeletion(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	sp := h.loadSecurityPolicy()
	req, err := h.loadDeletionRequest(u.ID)
	if err != nil {
		ok(w, r, map[string]any{"status": "none", "enabled": sp.AccountDeletionEnabled})
		return
	}
	out := deletionPayload(req)
	out["enabled"] = sp.AccountDeletionEnabled
	ok(w, r, out)
}

// POST /api/v1/me/account-deletion — 发起注销申请
//
// 必须同时通过「当前密码」与「二次验证」（MFA 验证码/恢复码；未开启 MFA 时用邮箱验证码）；
// 任一环节缺失都无法提交，避免会话被盗用后直接删号。
func (h *Handler) handleRequestAccountDeletion(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	sp := h.loadSecurityPolicy()
	if !sp.AccountDeletionEnabled {
		fail(w, r, http.StatusForbidden, "account.deletion_disabled", "当前未开放注销账号")
		return
	}
	// 管理员账号不允许自助注销，避免误删最后一个管理员导致后台无法管理。
	if u.IsAdmin {
		n, _ := h.db.NewSelect().Model((*models.User)(nil)).Where("is_admin = true").Count(r.Context())
		if n <= 1 {
			fail(w, r, http.StatusForbidden, "account.admin_cannot_delete", "管理员账号不支持自助注销")
			return
		}
	}
	// 已有进行中的申请：不允许重复提交（可直接撤回后重提）。
	if existing, err := h.loadDeletionRequest(u.ID); err == nil && existing != nil {
		fail(w, r, http.StatusConflict, "account.deletion_pending", "已存在待处理的注销申请")
		return
	}
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		Reason   string `json:"reason"`
		Method   string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	// 按用户维度限流，防止攻击者反复提交注销申请骚扰（或爆破验证码）。
	if !h.accountLimiter.AllowKey("delreq:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "操作过于频繁，请稍后再试")
		return
	}
	// 第一重：当前密码（设置过密码的账号必须提供）
	if u.PasswordSet && !auth.CheckPassword(u.PasswordHash, strings.TrimSpace(body.Password)) {
		fail(w, r, http.StatusUnauthorized, "password.incorrect", "注销账号需验证当前密码")
		return
	}
	// 第二重：二次验证（MFA 验证码 / 恢复码，或邮箱验证码）。
	// 账号没有任何第二因素时只校验密码——与 step-up / reauthenticate 同策略，
	// 否则这类用户永远无法提交注销申请。
	factors := h.loadSecondFactorOptions(u)
	if factors.Required && !h.verifySecondFactorMethod(u, strings.TrimSpace(body.Code), strings.ToLower(strings.TrimSpace(body.Method))) {
		fail(w, r, http.StatusBadRequest, "mfa.code_invalid", "二次验证码错误或已失效，请重新获取")
		return
	}

	now := db.Now()
	req := &models.AccountDeletionRequest{
		ID:            auth.NewID(),
		UserID:        u.ID,
		Status:        models.DeletionStatusPending,
		Reason:        strings.TrimSpace(body.Reason),
		ScheduledAt:   now.Add(h.deletionCooldown()),
		RequestIP:     clientIP(r),
		RequestRegion: requestRegion(r),
		RequestUA:     r.UserAgent(),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if _, err := h.db.NewInsert().Model(req).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{
		Type:    "account.deletion_requested",
		Summary: "提交注销账号申请",
		Metadata: map[string]string{
			"scheduledAt": req.ScheduledAt.Format(time.RFC3339),
		},
	})
	ok(w, r, deletionPayload(req))
}

// DELETE /api/v1/me/account-deletion — 撤回注销申请（冷静期内可随时撤回）
func (h *Handler) handleCancelAccountDeletion(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	req, err := h.loadDeletionRequest(u.ID)
	if err != nil || req == nil {
		fail(w, r, http.StatusNotFound, "account.deletion_not_found", "没有待处理的注销申请")
		return
	}
	// 已被管理员通过（approved）说明即将执行，此时撤回需管理员介入，避免竞态。
	if req.Status == models.DeletionStatusApproved {
		fail(w, r, http.StatusConflict, "account.deletion_approved", "申请已通过审核，无法自行撤回")
		return
	}
	if _, err := h.db.NewUpdate().Model((*models.AccountDeletionRequest)(nil)).
		Set("status = ?", models.DeletionStatusCancelled).
		Set("updated_at = ?", db.Now()).
		Where("id = ? AND user_id = ?", req.ID, u.ID).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "account.deletion_cancelled", Summary: "撤回注销账号申请"})
	ok(w, r, map[string]any{"success": true, "status": models.DeletionStatusCancelled})
}

// 二次验证方式。空串表示「自动选择」（MFA 优先，未启用则回退邮箱）。
const (
	secondFactorMFA   = "mfa"
	secondFactorEmail = "email"
)

// secondFactorOptions 描述一个账号当前可用的二次验证方式。
//
// 前端据此决定弹窗里渲染哪些输入项：只有密码时不再索要验证码，
// 有 MFA 时默认走 MFA 但同时给出「改用邮箱验证码」的切换入口。
type secondFactorOptions struct {
	// MFAEnabled 表示账号已启用认证器（TOTP）。
	MFAEnabled bool
	// EmailAvailable 表示邮箱验证码当前可用：账号已绑定邮箱且系统已配置 SMTP。
	// 二者缺一都发不出邮件，此时不能把邮箱作为可选项展示给用户。
	EmailAvailable bool
	// Methods 是可用的验证方式列表，顺序即优先级。
	Methods []string
	// Required 表示本次操作是否会真正索要第二因素。
	// 账号没有任何第二因素时为 false，此时仅凭密码即可完成验证
	// （否则这类用户将永远无法通过重验证，等于被锁死在敏感操作之外）。
	Required bool
}

// loadSecondFactorOptions 计算账号的二次验证可用方式。
func (h *Handler) loadSecondFactorOptions(u *models.User) secondFactorOptions {
	var opts secondFactorOptions
	if m := h.loadMFA(u.ID); m != nil && m.Enabled && m.Secret != "" {
		opts.MFAEnabled = true
		opts.Methods = append(opts.Methods, secondFactorMFA)
	}
	// 邮箱验证码要真的能发出去才算可用：账号绑定邮箱 + 邮件服务已配置。
	if strings.TrimSpace(u.Email) != "" && h.mailer.Enabled() {
		opts.EmailAvailable = true
		opts.Methods = append(opts.Methods, secondFactorEmail)
	}
	opts.Required = len(opts.Methods) > 0
	return opts
}

// verifySecondFactorMethod 按指定方式校验二次验证码。
//
// method 为空时自动选择：已启用 MFA 走 TOTP/恢复码，否则回退邮箱验证码。
// 显式传 method 时只接受对应方式——用户主动切换到「邮箱验证码」后，
// 若仍隐式接受 MFA 码，切换就失去意义（两类码共用同一个输入框，
// 校验策略必须与界面上展示的一致）。
func (h *Handler) verifySecondFactorMethod(u *models.User, code, method string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	switch method {
	case secondFactorMFA:
		m := h.loadMFA(u.ID)
		if m == nil || !m.Enabled || m.Secret == "" {
			return false
		}
		return mfa.Verify(m.Secret, code) || h.consumeRecoveryCode(m, code, context.Background())
	case secondFactorEmail:
		if strings.TrimSpace(u.Email) == "" {
			return false
		}
		return h.checkCode(strings.ToLower(u.Email), codePurposeChangeEmail, code)
	default:
		return h.verifySecondFactor(u, code)
	}
}

// verifySecondFactor 校验用户的二次验证因子：
//   - 已启用 MFA：接受 TOTP 验证码或一次性恢复码（恢复码命中后即消耗）；
//   - 未启用 MFA：回退到邮箱验证码（purpose=change_email），要求账号已绑定邮箱。
//
// 用于注销账号、更换邮箱等高危操作的二次确认（自动选择方式）。
// 需要限定方式时用 verifySecondFactorMethod。
func (h *Handler) verifySecondFactor(u *models.User, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	if m := h.loadMFA(u.ID); m != nil && m.Enabled && m.Secret != "" {
		return mfa.Verify(m.Secret, code) || h.consumeRecoveryCode(m, code, context.Background())
	}
	// 未启用 MFA：邮箱验证码兜底（未绑定邮箱则无法通过，需先开启 MFA 或绑定邮箱）。
	if u.Email == "" {
		return false
	}
	return h.checkCode(strings.ToLower(u.Email), codePurposeChangeEmail, code)
}

// POST /api/v1/me/account-deletion/email-code — 为注销账号申请发送邮箱验证码
// （未开启 MFA 的账号用它完成二次验证）
func (h *Handler) handleSendDeletionEmailCode(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if !h.loadSecurityPolicy().AccountDeletionEnabled {
		fail(w, r, http.StatusForbidden, "account.deletion_disabled", "当前未开放注销账号")
		return
	}
	// 已启用 MFA 的账号也允许发送：重验证弹窗提供「改用邮箱验证码」的切换入口，
	// 用于认证器丢失等无法出示 MFA 码的场景（与 /me/step-up/email-code 同策略）。
	if m := h.loadMFA(u.ID); m != nil && m.Enabled {
		h.logEvent(r, u.ID, &models.Event{
			Type:    "mfa.email_fallback_sent",
			Summary: "已启用双因素的账号改用邮箱验证码完成注销二次验证",
		})
	}
	if u.Email == "" {
		fail(w, r, http.StatusBadRequest, "email.missing", "当前账号没有绑定邮箱，请先绑定邮箱或启用双因素认证")
		return
	}
	// 未配置 SMTP 时禁止发送（避免“提示发送成功但实际未发送”）。
	if !h.mailer.Enabled() {
		fail(w, r, http.StatusServiceUnavailable, "mail.not_configured", "邮件服务未配置，无法发送验证码")
		return
	}
	if !h.accountLimiter.AllowKey("delcode:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	email := strings.ToLower(u.Email)
	if h.cooldownCheck(w, r, email, codePurposeChangeEmail) {
		return
	}
	code, err := h.mailer.SendCode(email, codePurposeChangeEmail, codeTTLMinutes, h.requestBaseURL(r))
	if err != nil {
		internal(w, r, err)
		return
	}
	h.persistCode(email, codePurposeChangeEmail, codeTTLMinutes, code)
	ok(w, r, map[string]any{"retryAfterSeconds": codeCooldownSecs})
}

// purgeUser 在事务内级联删除用户的全部数据。
// 抽成独立函数供「管理员审核通过」与「立即执行」两条路径复用，避免清理逻辑分叉遗漏。
//
// 上传文件同样在清理范围内：头像（purpose=avatar）在读取端点是免鉴权直出的，
// 若只删账号不删文件，「已注销用户」的头像仍会保留可公开访问的 URL，
// 既违背注销语义也构成合规风险。文件对象在事务提交后才物理删除：
// 事务回滚时不该已经丢掉磁盘上的对象。
func (h *Handler) purgeUser(ctx context.Context, u *models.User) error {
	// 先取出待删除文件的存储键，供事务提交后清理物理对象。
	var files []models.File
	_ = h.db.NewSelect().Model(&files).Where("owner_user_id = ?", u.ID).Scan(ctx)

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	del := func(model any, where string, args ...any) error {
		_, err := tx.NewDelete().Model(model).Where(where, args...).Exec(ctx)
		return err
	}
	if err := del((*models.File)(nil), "owner_user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Session)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Device)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.TrustedDevice)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Event)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Notification)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.NotificationPreference)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Grant)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Token)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.AuthorizationCode)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Identity)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.Passkey)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.MFA)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.MFAChallenge)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.AccountDeletionRequest)(nil), "user_id = ?", u.ID); err != nil {
		return err
	}
	if err := del((*models.VerificationCode)(nil), "email = ?", u.Email); err != nil {
		return err
	}
	if err := del((*models.User)(nil), "id = ?", u.ID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// 元数据已随账号删除，这里回收存储对象。单个对象删除失败只记日志：
	// 账号注销不应因为一个孤儿对象而失败，剩余对象由孤儿回收任务兜底。
	store := h.storageProvider()
	for i := range files {
		if store == nil || files[i].Key == "" {
			continue
		}
		if err := store.Delete(ctx, files[i].Key); err != nil && !errors.Is(err, storage.ErrNotFound) {
			logging.Warn("⚠️ [Storage] 注销账号时删除文件对象失败（key=%s）: %v", files[i].Key, err)
		}
	}
	return nil
}

// -------- 二次验证（step-up）：改邮箱 / 改密等敏感操作前的重新认证 --------

// stepUpTTLSeconds 是 step-up 令牌的有效期：足够完成一次表单填写，
// 又不至于让一次验证长期有效（避免长期持续的敏感操作权限）。
const stepUpTTLSeconds = 600

// POST /api/v1/me/step-up/email-code — 向当前邮箱发送 step-up 验证码
//
// 仅当账号未启用 MFA 时使用（已启用 MFA 的账号应直接使用验证器，
// 多引入一条可绕过因子反而削弱安全性）。
func (h *Handler) handleSendStepUpEmailCode(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 已启用 MFA 的账号也允许发送：重验证弹窗提供「改用邮箱验证码」的切换入口，
	// 用于认证器丢失/换手机等无法出示 MFA 码的场景，否则账号会被彻底锁死。
	// 这是有意的安全权衡——邮箱成为兜底因子，故此处记审计事件以便追溯。
	if m := h.loadMFA(u.ID); m != nil && m.Enabled {
		h.logEvent(r, u.ID, &models.Event{
			Type:    "mfa.email_fallback_sent",
			Summary: "已启用双因素的账号改用邮箱验证码完成二次验证",
		})
	}
	if u.Email == "" {
		fail(w, r, http.StatusBadRequest, "email.missing", "当前账号没有绑定邮箱")
		return
	}
	if !h.mailer.Enabled() {
		fail(w, r, http.StatusServiceUnavailable, "mail.not_configured", "邮件服务未配置，无法发送验证码")
		return
	}
	if !h.accountLimiter.AllowKey("stepup:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
	email := strings.ToLower(u.Email)
	if h.cooldownCheck(w, r, email, codePurposeChangeEmail) {
		return
	}
	code, err := h.mailer.SendCode(email, codePurposeChangeEmail, codeTTLMinutes, h.requestBaseURL(r))
	if err != nil {
		internal(w, r, err)
		return
	}
	h.persistCode(email, codePurposeChangeEmail, codeTTLMinutes, code)
	ok(w, r, map[string]any{"retryAfterSeconds": codeCooldownSecs})
}

// POST /api/v1/me/step-up — 完成二次验证，换取短效 step-up 令牌
//
// 敏感操作（如更换登录邮箱）除密码外还要求一次二次验证，避免会话被盗用后
// 仅凭已登录状态即可把账号邮箱改成攻击者的地址（进而配合找回密码完全接管）。
func (h *Handler) handleStepUp(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		// Method 指定二次验证方式（mfa / email），为空则自动选择。
		Method string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if !h.accountLimiter.AllowKey("stepup:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "尝试次数过多，请稍后再试")
		return
	}
	if u.PasswordSet && !auth.CheckPassword(u.PasswordHash, strings.TrimSpace(req.Password)) {
		fail(w, r, http.StatusUnauthorized, "password.incorrect", "当前密码错误")
		return
	}
	// 账号不具备任何第二因素时仅凭密码放行（与 /me/reauthenticate 同策略）：
	// 否则这类用户永远无法完成 step-up，也就无法更换邮箱。
	factors := h.loadSecondFactorOptions(u)
	if factors.Required && !h.verifySecondFactorMethod(u, strings.TrimSpace(req.Code), strings.ToLower(strings.TrimSpace(req.Method))) {
		fail(w, r, http.StatusBadRequest, "mfa.code_invalid", "验证码错误或已失效")
		return
	}
	// 令牌绑定会话：换会话即失效，避免被跨会话盗用。
	// 显式指定 TTL：与响应体里的 expiresAt 保持一致（见 stepUpTTLSeconds）。
	token := auth.RandomToken(32)
	h.tokens.SetWithTTL("stepup:"+token, u.ID, curSessionID(cur), stepUpTTLSeconds*time.Second)
	h.logEvent(r, u.ID, &models.Event{Type: "step_up.verified", Summary: "完成敏感操作二次验证"})
	ok(w, r, map[string]any{
		"stepUpToken": token,
		"expiresAt":   db.Now().Add(stepUpTTLSeconds * time.Second),
	})
}

// verifyStepUpToken 校验 step-up 令牌是否属于该用户且绑定到当前会话。
func (h *Handler) verifyStepUpToken(userID int64, sessID, token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	return h.tokens.Check("stepup:"+token, sessID) && h.tokens.UserOf("stepup:"+token) == userID
}

// curSessionID 从请求中提取当前会话 ID（无会话时返回空串）。
func curSessionID(s *models.Session) string {
	if s == nil {
		return ""
	}
	return s.ID
}

// POST /api/v1/me/email — 变更登录邮箱（需先完成二次验证）
//
// 攻击者拿到会话后若可随意改邮箱，就能配合「忘记密码」完全接管账号，
// 因此这里要求：先通过 POST /me/step-up 完成二次验证（TOTP/恢复码，或邮箱验证码），
// 拿到短效 step-up 令牌后再提交新邮箱。
func (h *Handler) handleChangeEmail(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Email       string `json:"email"`
		StepUpToken string `json:"stepUpToken"`
		// EmailCode 新邮箱收到的验证码：携带且校验通过时直接标记邮箱已验证。
		EmailCode string `json:"emailCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	// step-up 令牌绑定会话与用户：换会话/换用户即失效。
	if !h.verifyStepUpToken(u.ID, curSessionID(cur), req.StepUpToken) {
		fail(w, r, http.StatusForbidden, "step_up.required", "请先完成二次验证再更换邮箱")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(email, "@") {
		fail(w, r, http.StatusBadRequest, "email.invalid", "请输入有效的邮箱地址")
		return
	}
	if msg := h.checkEmailPolicy(h.loadSecurityPolicy(), email); msg != "" {
		fail(w, r, http.StatusBadRequest, "email.policy_blocked", msg)
		return
	}
	if email == strings.ToLower(u.Email) {
		fail(w, r, http.StatusBadRequest, "email.unchanged", "新邮箱与当前邮箱相同")
		return
	}
	// 校验唯一性，防止改到他人邮箱造成登录歧义。
	n, _ := h.db.NewSelect().Model((*models.User)(nil)).
		Where("lower(email) = lower(?) AND id <> ?", email, u.ID).Count(r.Context())
	if n > 0 {
		fail(w, r, http.StatusConflict, "email.exists", "该邮箱已被其他账号使用")
		return
	}
	// 携带新邮箱验证码时当场校验：通过即证明归属，直接标记已验证；
	// 未携带（旧流程）则保持未验证状态，由用户通过验证邮件完成归属确认。
	emailVerified := false
	if strings.TrimSpace(req.EmailCode) != "" {
		if !h.checkCode(email, codePurposeChangeEmail, req.EmailCode) {
			fail(w, r, http.StatusBadRequest, "email.code_invalid", "验证码错误或已过期")
			return
		}
		emailVerified = true
	}
	old := u.Email
	u.Email = email
	// 新邮箱必须重新验证，否则无法证明归属（也无法用于找回密码）。
	u.EmailVerified = emailVerified
	u.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	// step-up 令牌一次性使用，避免同一次验证被用于多次改邮箱。
	h.consumeStepUpToken(req.StepUpToken)
	h.logEvent(r, u.ID, &models.Event{
		Type:     "email.changed",
		Summary:  "修改登录邮箱（已完成二次验证）",
		Metadata: map[string]string{"from": old, "to": email},
	})
	ok(w, r, u)
}

// consumeStepUpToken 用后即焚，保证一次二次验证只对应一次敏感操作。
func (h *Handler) consumeStepUpToken(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	h.tokens.Delete("stepup:" + token)
}
