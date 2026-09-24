package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/uptrace/bun"
)

// -------- 注销账号申请：管理员审核 --------

// GET /api/v1/admin/account-deletion-requests — 列出待处理的注销申请
func (h *Handler) handleAdminListDeletionRequests(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var reqs []models.AccountDeletionRequest
	if err := h.db.NewSelect().Model(&reqs).
		OrderExpr("CASE WHEN status = 'pending' THEN 0 ELSE 1 END ASC").
		Order("created_at DESC").
		Limit(200).Scan(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	if reqs == nil {
		reqs = []models.AccountDeletionRequest{}
	}
	// 关联出用户名/邮箱，便于管理员确认被注销的账号。
	type item struct {
		models.AccountDeletionRequest
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	byUser := make(map[int64]*models.User, len(reqs))
	ids := make([]int64, 0, len(reqs))
	for _, q := range reqs {
		if _, ok := byUser[q.UserID]; !ok {
			byUser[q.UserID] = nil
			ids = append(ids, q.UserID)
		}
	}
	if len(ids) > 0 {
		var users []models.User
		_ = h.db.NewSelect().Model(&users).Where("id IN (?)", bun.List(ids)).Scan(r.Context(), &users)
		for i := range users {
			cp := users[i]
			byUser[cp.ID] = &cp
		}
	}
	out := make([]item, 0, len(reqs))
	for _, q := range reqs {
		it := item{AccountDeletionRequest: q}
		if u := byUser[q.UserID]; u != nil {
			it.Username = u.Username
			it.Email = u.Email
		}
		out = append(out, it)
	}
	ok(w, r, out)
}

// POST /api/v1/admin/account-deletion-requests/{id}/approve — 通过申请并删除账号
//
// 冷静期未结束时拒绝通过（用户仍应保有撤回窗口）；通过后立即在事务内级联清理数据。
func (h *Handler) handleAdminApproveDeletionRequest(w http.ResponseWriter, r *http.Request) {
	admin, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		fail(w, r, http.StatusBadRequest, "request.invalid_path", "无效的申请 ID")
		return
	}
	var req models.AccountDeletionRequest
	if err := h.db.NewSelect().Model(&req).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "account.deletion_not_found", "注销申请不存在")
		return
	}
	if req.Status != models.DeletionStatusPending {
		fail(w, r, http.StatusConflict, "account.deletion_not_pending", "该申请已处理，无法重复审核")
		return
	}
	// 冷静期未结束：不允许通过，避免出现"用户刚提交就被删号"的既成事实。
	if db.Now().Before(req.ScheduledAt) {
		fail(w, r, http.StatusConflict, "account.deletion_cooldown", "仍在冷静期内，请等待冷静期结束后再审核")
		return
	}
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", req.UserID).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "user.not_found", "账号不存在或已删除")
		return
	}
	// 管理员账号不允许通过此流程注销，避免误删最后一个管理员。
	if u.IsAdmin {
		n, _ := h.db.NewSelect().Model((*models.User)(nil)).Where("is_admin = true").Count(r.Context())
		if n <= 1 {
			fail(w, r, http.StatusForbidden, "account.admin_cannot_delete", "管理员账号不支持注销")
			return
		}
	}
	if _, err := h.db.NewUpdate().Model((*models.AccountDeletionRequest)(nil)).
		Set("status = ?", models.DeletionStatusApproved).
		Set("reviewed_by = ?", admin.ID).
		Set("reviewed_at = ?", db.Now()).
		Set("updated_at = ?", db.Now()).
		Where("id = ?", req.ID).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	if err := h.purgeUser(r.Context(), &u); err != nil {
		// 清理失败要把申请退回 pending，避免"已通过但账号还在"的中间态。
		_, _ = h.db.NewUpdate().Model((*models.AccountDeletionRequest)(nil)).
			Set("status = ?", models.DeletionStatusPending).
			Where("id = ?", req.ID).Exec(r.Context())
		internal(w, r, err)
		return
	}
	h.logEvent(r, admin.ID, &models.Event{
		Type:    "account.deleted",
		Summary: "管理员通过注销申请，账号已删除",
		Metadata: map[string]string{
			"username": u.Username,
			"email":    u.Email,
			"targetId": strconv.FormatInt(u.ID, 10),
		},
	})
	ok(w, r, map[string]any{"success": true, "status": models.DeletionStatusCompleted})
}

// POST /api/v1/admin/account-deletion-requests/{id}/reject — 驳回申请（账号保留）
func (h *Handler) handleAdminRejectDeletionRequest(w http.ResponseWriter, r *http.Request) {
	admin, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		fail(w, r, http.StatusBadRequest, "request.invalid_path", "无效的申请 ID")
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	var req models.AccountDeletionRequest
	if err := h.db.NewSelect().Model(&req).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "account.deletion_not_found", "注销申请不存在")
		return
	}
	if req.Status != models.DeletionStatusPending {
		fail(w, r, http.StatusConflict, "account.deletion_not_pending", "该申请已处理，无法重复审核")
		return
	}
	now := db.Now()
	if _, err := h.db.NewUpdate().Model((*models.AccountDeletionRequest)(nil)).
		Set("status = ?", models.DeletionStatusRejected).
		Set("review_note = ?", strings.TrimSpace(body.Note)).
		Set("reviewed_by = ?", admin.ID).
		Set("reviewed_at = ?", now).
		Set("updated_at = ?", now).
		Where("id = ?", req.ID).Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, admin.ID, &models.Event{
		Type:    "account.deletion_rejected",
		Summary: "管理员驳回注销申请",
		Metadata: map[string]string{
			"requestId": req.ID,
			"targetId":  strconv.FormatInt(req.UserID, 10),
		},
	})
	ok(w, r, map[string]any{"success": true, "status": models.DeletionStatusRejected})
}
