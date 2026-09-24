package handler

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strconv"
	"strings"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- Admin users ----

// GET /api/v1/admin/users?q=&page=1&pageSize=20
func (h *Handler) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	_, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	q := h.db.NewSelect().Model((*models.User)(nil))
	if s := strings.TrimSpace(r.URL.Query().Get("q")); s != "" {
		// 转义 LIKE 通配符（% 与 _）：否则搜索 "a_b" 会命中 "axb"，结果不准。
		like := "%" + escapeLike(s) + "%"
		q = q.Where(`username LIKE ? ESCAPE '!' OR display_name LIKE ? ESCAPE '!' OR email LIKE ? ESCAPE '!'`, like, like, like)
	}
	page, pageSize := parsePage(r)
	total, _ := q.Count(r.Context())
	var users []models.User
	if err := q.Order("created_at DESC").Offset((page-1)*pageSize).Limit(pageSize).Scan(r.Context(), &users); err != nil {
		internal(w, r, err)
		return
	}
	if users == nil {
		users = []models.User{}
	}
	ok(w, r, map[string]any{"items": users, "total": total, "page": page, "pageSize": pageSize})
}

// PATCH /api/v1/admin/users/{id}  {isAdmin, displayName, email, passwordSet}
func (h *Handler) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	admin, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_path", "无效的用户 ID")
		return
	}
	var u models.User
	if err := h.db.NewSelect().Model(&u).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.user_not_found", "用户不存在")
		return
	}
	var req struct {
		IsAdmin     *bool   `json:"isAdmin"`
		DisplayName *string `json:"displayName"`
		Email       *string `json:"email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.IsAdmin != nil {
		if id == admin.ID {
			fail(w, r, http.StatusBadRequest, "admin.self_demote", "不能修改自己的管理员状态")
			return
		}
		u.IsAdmin = *req.IsAdmin
	}
	if req.DisplayName != nil {
		u.DisplayName = *req.DisplayName
	}
	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email != "" {
			// 校验邮箱唯一性，避免与其他用户冲突（登录歧义）。
			n, err := h.db.NewSelect().Model((*models.User)(nil)).
				Where("lower(email) = lower(?) AND id != ?", email, id).Count(r.Context())
			if err != nil {
				internal(w, r, err)
				return
			}
			if n > 0 {
				fail(w, r, http.StatusConflict, "email.exists", "该邮箱已被其他用户使用")
				return
			}
		}
		u.Email = email
	}
	if _, err := h.db.NewUpdate().Model(&u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	changes := make([]string, 0, 3)
	if req.IsAdmin != nil {
		changes = append(changes, "管理员状态")
	}
	if req.DisplayName != nil {
		changes = append(changes, "显示名称")
	}
	if req.Email != nil {
		changes = append(changes, "邮箱")
	}
	if len(changes) > 0 {
		h.logEvent(r, admin.ID, &models.Event{
			Type:    "admin.user_updated",
			Summary: "管理员更新用户：" + strings.Join(changes, "、"),
			Metadata: map[string]string{
				"targetUserId": strconv.FormatInt(id, 10),
				"username":     u.Username,
			},
		})
	}
	ok(w, r, u)
}

// createUser 是统一的用户创建入口（注册 / 后台新建 / 初始化 / 三方登录共用）：
// 生成 subject、写入用户、创建默认通知偏好。
func (h *Handler) createUser(ctx context.Context, u *models.User) error {
	if u.Subject == "" {
		u.Subject = auth.NewSubject()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = db.Now()
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	if _, err := h.db.NewInsert().Model(u).Exec(ctx); err != nil {
		return err
	}
	// 默认通知偏好：创建用户时一并写入，避免首次收到通知时才惰性创建。
	_, _ = h.db.NewInsert().Model(&models.NotificationPreference{UserID: u.ID}).Exec(ctx)
	return nil
}

// POST /api/v1/admin/users  {username, email, displayName, password, isAdmin}
func (h *Handler) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	admin, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	var req struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
		Password    string `json:"password"`
		IsAdmin     bool   `json:"isAdmin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	if msg := validateUsername(strings.TrimSpace(req.Username)); msg != "" {
		fail(w, r, http.StatusBadRequest, "username.invalid", msg)
		return
	}
	// 校验邮箱格式与唯一性，避免依赖数据库唯一约束报 500。
	if req.Email != "" {
		if !isValidEmail(req.Email) {
			fail(w, r, http.StatusBadRequest, "email.invalid", "邮箱格式不正确")
			return
		}
		if n, _ := h.db.NewSelect().Model((*models.User)(nil)).Where("lower(email) = lower(?)", strings.ToLower(strings.TrimSpace(req.Email))).Count(r.Context()); n > 0 {
			fail(w, r, http.StatusConflict, "email.exists", "该邮箱已被占用")
			return
		}
	}
	// 用户名唯一性按精确值比对（区分大小写），与登录入口的匹配规则一致。
	if n, _ := h.db.NewSelect().Model((*models.User)(nil)).Where("username = ?", strings.TrimSpace(req.Username)).Count(r.Context()); n > 0 {
		fail(w, r, http.StatusConflict, "user.exists", "该用户名已被占用")
		return
	}
	if msg := validatePassword(h.loadSecurityPolicy(), req.Password); msg != "" {
		fail(w, r, http.StatusBadRequest, "password.too_weak", msg)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		internal(w, r, err)
		return
	}
	username := strings.TrimSpace(req.Username)
	u := &models.User{
		Username:      username,
		DisplayName:   auth.FirstNonEmpty(strings.TrimSpace(req.DisplayName), username),
		Email:         strings.ToLower(strings.TrimSpace(req.Email)),
		EmailVerified: true,
		AvatarURL:     defaultAvatarURL,
		PasswordHash:  hash,
		PasswordSet:   true,
		IsAdmin:       req.IsAdmin,
	}
	if err := h.createUser(r.Context(), u); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, admin.ID, &models.Event{
		Type:    "admin.user_created",
		Summary: "管理员创建用户",
		// 记录目标用户，审计可追溯"谁创建了谁"。
		Metadata: map[string]string{"username": u.Username, "targetUserId": strconv.FormatInt(u.ID, 10)},
	})
	ok(w, r, u)
}

// DELETE /api/v1/admin/users/{id}
func (h *Handler) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	admin, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id == admin.ID {
		fail(w, r, http.StatusBadRequest, "admin.invalid_target", "无效的用户 ID")
		return
	}
	// 目标用户不存在时如实返回 404，避免「什么都没删却回 success」。
	var target models.User
	if err := h.db.NewSelect().Model(&target).Where("id = ?", id).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "admin.user_not_found", "用户不存在")
		return
	}
	// 复用 purgeUser 完成级联删除。此处原先另写了一份删除清单，比 purgeUser 少了
	// trusted_devices、authorization_codes、account_deletion_requests 三张表，
	// 管理员删号会留下孤儿行——可信设备残留尤其危险：用户 ID 被复用后，
	// 新账号可能凭残留记录直接跳过二次验证。清理逻辑只保留一份，避免再次分叉。
	if err := h.purgeUser(r.Context(), &target); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, admin.ID, &models.Event{
		Type:     "admin.user_deleted",
		Summary:  "管理员删除用户",
		Metadata: map[string]string{"targetUserId": strconv.FormatInt(id, 10)},
	})
	ok(w, r, map[string]any{"success": true})
}
