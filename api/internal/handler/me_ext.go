package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- 邮箱验证 ----

// POST /api/v1/me/email/verify — 邮箱验证（免 CSRF，登录态 + token 双重校验）
//
// 由前端 /verify-email 页面调用：页面从邮件链接读取 token，再以 JSON 方式提交，
// 由页面按返回码渲染图形化结果，避免邮件链接直指裸接口、点击后无界面反馈。
// token 一次性消费；未登录返回 401，页面据此引导用户先登录再跳回本页继续验证。
func (h *Handler) handleEmailVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid", "请求参数无效")
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		fail(w, r, http.StatusBadRequest, "email.verify_token_missing", "缺少验证令牌")
		return
	}
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	it, found := h.tokens.Take("email:verify:" + token)
	if !found || it.UserID != u.ID {
		fail(w, r, http.StatusBadRequest, "email.verify_token_invalid", "验证链接无效或已过期")
		return
	}
	if u.Email == "" {
		fail(w, r, http.StatusBadRequest, "email.missing", "当前账号没有绑定邮箱")
		return
	}
	u.EmailVerified = true
	u.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "email.verified", Summary: "验证邮箱"})
	ok(w, r, map[string]any{"success": true})
}

// POST /api/v1/me/email/verify/send — 发送邮箱验证邮件
func (h *Handler) handleEmailVerifySend(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	if u.Email == "" {
		fail(w, r, http.StatusBadRequest, "email.missing", "当前账号没有绑定邮箱")
		return
	}
	if u.EmailVerified {
		fail(w, r, http.StatusBadRequest, "email.already_verified", "邮箱已验证，无需重复验证")
		return
	}
	// 60s 冷却
	if h.tokens.Has("email:verify:last:" + u.Email) {
		fail(w, r, http.StatusTooManyRequests, "email.code_cooldown", "发送过于频繁，请稍后再试")
		return
	}
	token := auth.RandomHex(24)
	h.tokens.Set("email:verify:"+token, u.ID, "")
	h.tokens.Set("email:verify:last:"+u.Email, u.ID, "")
	if err := h.mailer.SendVerifyLink(u.Email, auth.FirstNonEmpty(u.DisplayName, u.Username), token, h.requestBaseURL(r)); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "email.verify_sent", Summary: "发送邮箱验证邮件"})
	ok(w, r, map[string]any{"success": true})
}

// ---- 头像上传 ----

// POST /api/v1/me/avatar — 上传头像（内容寻址 + 不可变 URL）
//
// 采用「先落 file 再改 avatar_url」两步：新头像写入 files 表并生成随机
// publicId，旧头像不立即删除而是标记解绑，进入孤儿回收宽限期。
// 这样换头像后浏览器不会因 immutable 缓存继续显示旧图，
// 且并发上传/回退场景下不会误删仍在使用的对象。
func (h *Handler) handleAvatarUpload(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 站点开关：未开启则禁止上传（前端隐藏，后端兜底）
	if !h.loadSiteSetting().AvatarUploadEnabled {
		fail(w, r, http.StatusForbidden, "avatar.disabled", "管理员已关闭头像上传")
		return
	}
	if !h.loadStorageSetting().IsEnabled {
		fail(w, r, http.StatusForbidden, "storage.disabled", "管理员已关闭文件存储")
		return
	}
	h.uploadAvatar(w, r, u)
}

// uploadAvatar 解析并落盘头像，更新用户 avatar_url。
func (h *Handler) uploadAvatar(w http.ResponseWriter, r *http.Request, u *models.User) {
	// 同上：内存阈值与请求体总上限分离，超限请求不会先完整落盘再被拒绝。
	if err := r.ParseMultipartForm(middleware.MultipartMemoryLimit()); err != nil {
		fail(w, r, http.StatusBadRequest, "avatar.too_large", "头像文件过大，请上传 2MB 以内的图片")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		fail(w, r, http.StatusBadRequest, "avatar.missing", "请选择要上传的图片")
		return
	}
	defer file.Close()

	if header.Size > int64(maxAvatarBytes) {
		fail(w, r, http.StatusBadRequest, "avatar.too_large", "头像文件过大，请上传 2MB 以内的图片")
		return
	}
	// 类型校验：png / jpeg / webp / svg / gif（与通用上传共用同一份白名单）
	ext := strings.ToLower(filepath.Ext(header.Filename))
	expected, allowed := allowedImageExt[ext]
	if !allowed {
		fail(w, r, http.StatusBadRequest, "avatar.invalid_type", "仅支持 PNG、JPG、WebP、SVG 或 GIF 格式的头像图片")
		return
	}
	// 读取内容并嗅探魔数，防止伪装
	buf, err := io.ReadAll(io.LimitReader(file, int64(maxAvatarBytes)+1))
	if err != nil {
		internal(w, r, err)
		return
	}
	if len(buf) > maxAvatarBytes {
		fail(w, r, http.StatusBadRequest, "avatar.too_large", "头像文件过大，请上传 2MB 以内的图片")
		return
	}
	// 校验内容类型与扩展名匹配，防止伪装文件（如 HTML 伪装成图片）。
	// 与通用上传共用 mimeMatches：SVG 是 XML 文本，嗅探永远给不出 image/svg+xml，
	// 需要单独按「内容确实是 <svg 开头」来判定，同时拒绝 HTML / 纯文本。
	if sniffed := http.DetectContentType(buf); !mimeMatches(sniffed, expected, buf) {
		fail(w, r, http.StatusBadRequest, "avatar.invalid_type", "文件类型与扩展名不匹配，仅支持 PNG、JPG、WebP、SVG 或 GIF 格式的头像图片")
		return
	}

	res, err := h.storeFile(r, u.ID, models.FilePurposeAvatar, header.Filename, expected, buf)
	if err != nil {
		internal(w, r, err)
		return
	}
	// 旧头像解绑（不立即删除，进入孤儿回收宽限期）。
	h.detachFile(publicIDFromURL(u.AvatarURL))

	u.AvatarURL = res.URL
	u.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "avatar.updated", Summary: "更新头像"})
	ok(w, r, map[string]any{"avatarUrl": u.AvatarURL, "publicId": res.PublicID})
}

// POST /api/v1/me/avatar/reset — 重置为系统默认头像
func (h *Handler) handleAvatarReset(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	// 旧头像解绑（不立即删除，进入孤儿回收宽限期）。
	h.detachFile(publicIDFromURL(u.AvatarURL))
	u.AvatarURL = defaultAvatarURL
	u.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(u).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	h.logEvent(r, u.ID, &models.Event{Type: "avatar.updated", Summary: "重置为默认头像"})
	ok(w, r, map[string]any{"avatarUrl": u.AvatarURL})
}

// ---- 新邮箱验证码（添加/更换邮箱一步式验证） ----

// POST /api/v1/me/email/code — 向待绑定的「新邮箱」发送验证码
//
// 与登录/注册验证码不同，这里的目标地址来自请求体而不是已登录账号：
// 用于安全中心添加/更换邮箱时，先证明用户对该新邮箱的所有权，再落库。
// 携带校验过的 step-up 令牌方可调用（与新邮箱提交接口同一前置），防止
// 已登录会话被滥用于向任意地址发信。
func (h *Handler) handleSendNewEmailCode(w http.ResponseWriter, r *http.Request) {
	u, cur, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	var req struct {
		Email       string `json:"email"`
		StepUpToken string `json:"stepUpToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return
	}
	// step-up 令牌是本次添加/更换邮箱的前置条件：拿不到令牌就不允许向新邮箱发码。
	if !h.verifyStepUpToken(u.ID, curSessionID(cur), req.StepUpToken) {
		fail(w, r, http.StatusForbidden, "step_up.required", "请先完成二次验证")
		return
	}
	if !h.mailer.Enabled() {
		fail(w, r, http.StatusServiceUnavailable, "mail.not_configured", "邮件服务未配置，无法发送验证码")
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
	if !h.accountLimiter.AllowKey("newemail:" + strconv.FormatInt(u.ID, 10)) {
		w.Header().Set("Retry-After", "900")
		fail(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
		return
	}
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
