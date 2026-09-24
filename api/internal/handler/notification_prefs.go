package handler

import (
	"context"
	"net/http"

	"github.com/h1s97x/openidp/api/internal/models"
)

// GET /api/v1/me/notification-preferences
//
// 同时下发 emailAvailable：邮件类通道依赖 SMTP，未配置时前端把对应开关标记为
// 不可用。与 /capabilities 的 personal.notificationEmail 是同一条判定，
// 这里再给一次是为了让「通知偏好」这个接口自身就能说明通道可用性。
func (h *Handler) handleGetNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	ok(w, r, h.notificationPrefsPayload(h.loadNotificationPrefs(u.ID)))
}

// notificationPrefsPayload 组装通知偏好的响应体。
//
// 邮件通道不可用时（未配置 SMTP），邮件类开关一律按「关闭」下发：
// 库里的历史取值可能仍是 true（例如默认值或管理员停用邮件服务之前的设置），
// 直接回显会让界面出现「已开启」却永远收不到邮件的假象——这正是本次要消除的。
// 判定与邮件发送链路同源（h.mailer.Enabled()），所以界面展示的就是实际行为。
func (h *Handler) notificationPrefsPayload(np *models.NotificationPreference) map[string]any {
	emailAvailable := h.mailer.Enabled()
	effective := func(v bool) bool { return v && emailAvailable }
	return map[string]any{
		"userId":               np.UserID,
		"newDeviceInApp":       np.NewDeviceInApp,
		"newDeviceEmail":       effective(np.NewDeviceEmail),
		"privacyEmailReminder": effective(np.PrivacyEmailReminder),
		"emailAvailable":       emailAvailable,
	}
}

// PATCH /api/v1/me/notification-preferences
func (h *Handler) handlePatchNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req map[string]any
	if !decodeJSON(w, r, &req) {
		return
	}
	np := h.loadNotificationPrefs(u.ID)
	// 功能校验：邮件类通道依赖 SMTP。未配置邮件服务时不允许把邮件开关置为开启——
	// 打开一个永远不会生效的开关只会让人以为能收到提醒（比没有开关更糟）。
	// 关闭方向不受限制，否则用户就无法把历史遗留的「已开启」状态改回去。
	if !h.mailer.Enabled() {
		for _, key := range []string{"newDeviceEmail", "privacyEmailReminder"} {
			if v, ok := req[key].(bool); ok && v {
				fail(w, r, http.StatusBadRequest, "notification.email_unavailable",
					"邮件服务尚未配置，暂时无法开启邮件通知")
				return
			}
		}
	}
	applyBool := func(key string, field *bool) {
		if v, ok := req[key].(bool); ok {
			*field = v
		}
	}
	applyBool("newDeviceInApp", &np.NewDeviceInApp)
	applyBool("newDeviceEmail", &np.NewDeviceEmail)
	applyBool("privacyEmailReminder", &np.PrivacyEmailReminder)
	// 这里不额外改写邮件类开关：接口按「生效值」下发（见 notificationPrefsPayload），
	// 未配置 SMTP 时用户看到的本就是关闭。用户在前端保存后，落库取值即与界面一致；
	// 邮件服务恢复后再由用户显式开启，不会出现「界面已开启、实际发不出去」的错位。
	if _, err := h.db.NewUpdate().Model(np).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, h.notificationPrefsPayload(np))
}

// loadNotificationPrefs 读取用户的通知偏好；不存在时按默认值创建一行。
func (h *Handler) loadNotificationPrefs(userID int64) *models.NotificationPreference {
	np := &models.NotificationPreference{}
	if err := h.db.NewSelect().Model(np).Where("user_id = ?", userID).Scan(context.Background()); err == nil {
		return np
	}
	// 邮件类开关的默认值取决于邮件服务是否已配置：未配置时一律为关闭，
	// 否则新用户会带着一个「已开启但收不到」的隐私邮箱提醒进入设置页。
	//
	// 先把期望值记在局部变量里：new_device_in_app / privacy_email_reminder 带
	// default:true 标签，插入时零值会被 bun 省略、由数据库默认值填回 true；
	// 而 bun 还会用 RETURNING 回填 np，于是返回的结构体也会变成 true。
	// 局部变量是「真正希望落库的值」，插入后据此回写一次即可纠正。
	inApp, emailReminder := true, h.mailer.Enabled()
	np = &models.NotificationPreference{
		UserID:               userID,
		NewDeviceInApp:       inApp,
		NewDeviceEmail:       false,
		PrivacyEmailReminder: emailReminder,
	}
	// Ignore：并发请求同时创建同一行时，后到的插入直接跳过，不报错。
	res, err := h.db.NewInsert().Model(np).Ignore().Exec(context.Background())
	if err != nil {
		return np
	}
	if n, _ := res.RowsAffected(); n > 0 {
		// 显式回写（Set 不受 default 标签的零值省略影响），保证落库取值
		// 与此处构造的一致——此后读取与下发都以库为准。
		_, _ = h.db.NewUpdate().Model((*models.NotificationPreference)(nil)).
			Set("new_device_in_app = ?", inApp).
			Set("new_device_email = ?", false).
			Set("privacy_email_reminder = ?", emailReminder).
			Where("user_id = ?", userID).Exec(context.Background())
		np.NewDeviceInApp = inApp
		np.NewDeviceEmail = false
		np.PrivacyEmailReminder = emailReminder
	}
	return np
}

// GET /api/v1/me/notifications/unread-count — 未读通知计数
//
// 独立端点：前端轮询未读数时无需拉取全量通知列表，显著减少响应体与数据库开销。
func (h *Handler) handleUnreadNotificationCount(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	unread, err := h.db.NewSelect().Model((*models.Notification)(nil)).
		Where("user_id = ? AND read = false", u.ID).Count(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, map[string]any{"unreadCount": unread})
}
