package handler

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- Notification center (个人通知中心) ----

// GET /api/v1/me/notifications?unread=true
func (h *Handler) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	q := h.db.NewSelect().Model((*models.Notification)(nil)).Where("user_id = ?", u.ID)
	if r.URL.Query().Get("unread") == "true" {
		q = q.Where("read = false")
	}
	var items []models.Notification
	if err := q.Order("created_at DESC").Limit(50).Scan(r.Context(), &items); err != nil {
		internal(w, r, err)
		return
	}
	if items == nil {
		items = []models.Notification{}
	}
	// unread count
	unread, _ := h.db.NewSelect().Model((*models.Notification)(nil)).
		Where("user_id = ? AND read = false", u.ID).Count(r.Context())
	ok(w, r, map[string]any{
		"items":       items,
		"unreadCount": unread,
	})
}

// PATCH /api/v1/me/notifications/{id}  {read: true}
func (h *Handler) handleUpdateNotification(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_path", "无效的通知 ID")
		return
	}
	var req struct {
		Read *bool `json:"read"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Read == nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "缺少 read 字段")
		return
	}
	_, err = h.db.NewUpdate().Model((*models.Notification)(nil)).
		Set("read = ?", *req.Read).
		Where("id = ? AND user_id = ?", id, u.ID).Exec(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, map[string]any{"success": true})
}

// POST /api/v1/me/notifications/read-all
func (h *Handler) handleMarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	_, _ = h.db.NewUpdate().Model((*models.Notification)(nil)).
		Set("read = true").
		Where("user_id = ?", u.ID).Exec(r.Context())
	ok(w, r, map[string]any{"success": true})
}

// DELETE /api/v1/me/notifications — 清空当前用户的全部站内通知。
//
// 只删自己的行（Where user_id），不做软删除：通知是纯展示记录，
// 保留 read=true 的墓碑反而会让「清空」之后列表仍显示旧条目。
func (h *Handler) handleClearNotifications(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	res, err := h.db.NewDelete().Model((*models.Notification)(nil)).
		Where("user_id = ?", u.ID).Exec(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	affected, _ := res.RowsAffected()
	ok(w, r, map[string]any{"success": true, "deleted": affected})
}

// notify creates an in-app notification for a user.
func (h *Handler) notify(userID int64, typ, title, summary string, metadata map[string]string) {
	n := &models.Notification{
		UserID:    userID,
		Type:      typ,
		Title:     title,
		Summary:   summary,
		Metadata:  metadata,
		Read:      false,
		CreatedAt: db.Now(),
	}
	_, _ = h.db.NewInsert().Model(n).Exec(context.Background())
}
