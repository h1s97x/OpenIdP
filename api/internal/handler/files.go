package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/storage"
)

// ---- 文件存储（内容寻址 + 不可变 URL）----
//
// 对外只暴露随机 publicId，响应带强 ETag 与一年 immutable 缓存，
// 并支持 Range 请求（206）与条件请求（304）。

// 上传大小上限：头像 2MB、通用附件 10MB。
const (
	maxAvatarBytes     = 2 << 20
	maxAttachmentBytes = 10 << 20
)

// 孤儿文件宽限期：文件被解绑后仍需保留一段时间才允许物理删除，
// 避免「换头像后立刻回退」「并发上传/替换」等场景下误删仍在使用的对象。
const orphanGracePeriod = 7 * 24 * time.Hour

// allowedImageExt 是允许上传的图片扩展名 → 标准 MIME。
var allowedImageExt = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".webp": "image/webp",
	".svg":  "image/svg+xml",
	".gif":  "image/gif",
}

// allowedAttachmentExt 是通用附件允许的扩展名 → MIME。
// 刻意保持白名单：不在此表中的类型一律拒绝，避免上传目录成为任意内容托管点。
var allowedAttachmentExt = map[string]string{
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif",
	".svg": "image/svg+xml",
	".pdf": "application/pdf",
	".txt": "text/plain", ".md": "text/markdown", ".csv": "text/csv",
	".json": "application/json",
	".zip":  "application/zip",
}

// baseMime 去掉 MIME 类型上的参数（如 “; charset=utf-8“），只保留主类型。
//
// Go 的 http.DetectContentType 对文本类内容会返回带 charset 的值：
//
//	DetectContentType("hello") → "text/plain; charset=utf-8"
//
// 而扩展名白名单里声明的是不带参数的 "text/plain"。此前只在 SVG 分支剥离
// charset、其余分支做严格相等，导致 txt/md/csv/json 这些文本附件全部被
// 误判为「内容与扩展名不匹配」而拒绝上传。
func baseMime(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// textSniffWhitelist 是「嗅探结果无法精确还原、只能退化为 text/plain」的
// 扩展名声明 → 允许的嗅探主类型集合。
//
// Go 的嗅探器只能识别出少量文本魔数（HTML / XML / JSON 等），markdown、CSV
// 这类纯文本一律回落成 text/plain。若直接与声明类型严格比较，.md/.csv/.json
// 会被永久拒绝，因此这里显式声明「该扩展名允许的嗅探结果」。
//
// 放宽的只是「是否可能是文本」，不放松可执行/可解析类型的检查：HTML 仍是
// text/html，不会被任何一项接受。
var textSniffWhitelist = map[string][]string{
	"text/plain":       {"text/plain"},
	"text/markdown":    {"text/plain", "text/markdown"},
	"text/csv":         {"text/plain", "text/csv"},
	"application/json": {"text/plain", "application/json"},
}

// mimeMatches 判定嗅探结果与扩展名声明的类型是否一致。
//
// 判定分三层：
//  1. 主类型相同即通过（剥离 “; charset=…“ 参数，兼容 Go 的文本嗅探产出）；
//  2. 声明为文本类（txt/md/csv/json）时，按 textSniffWhitelist 允许 text/plain；
//  3. SVG 单独放行：它是 XML 文本，DetectContentType 只会给出 text/xml（有时
//     是 text/plain），永远嗅探不出 image/svg+xml。这里要求内容确实以「<svg」
//     或「<?xml」开头，避免把任意文本/HTML 当成 SVG 放行。
//
// SVG 可以内嵌脚本，是潜在的 XSS 载体；防护依赖 serveFile 输出时设置的
// Content-Security-Policy: default-src 'none'; sandbox 与 X-Content-Type-Options:
// nosniff，使浏览器以受限沙箱文档渲染而非在当前站点上下文中执行脚本。
func mimeMatches(sniffed, expected string, buf []byte) bool {
	got := baseMime(sniffed)
	want := baseMime(expected)
	if got == want {
		return true
	}
	if allowed, ok := textSniffWhitelist[want]; ok {
		for _, a := range allowed {
			if got == a {
				return true
			}
		}
	}
	if want != "image/svg+xml" {
		return false
	}
	if got != "text/xml" && got != "text/plain" {
		return false
	}
	head := string(buf)
	if len(head) > 512 {
		head = head[:512]
	}
	head = strings.TrimSpace(head)
	// 允许 XML 声明 / 注释 / DOCTYPE 前缀，但正文必须以 <svg 开头。
	// 逐个剥离可能出现的 XML 声明形态，避免只认单引号/双引号中的一种。
	for _, decl := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<?xml version='1.0' encoding='UTF-8'?>`,
		`<?xml version="1.0"?>`,
		`<?xml version='1.0'?>`,
	} {
		head = strings.TrimPrefix(head, decl)
		head = strings.TrimSpace(head)
	}
	return strings.HasPrefix(strings.ToLower(head), "<svg")
}

// newPublicID 生成 URL 中使用的公开 ID：18 字节随机数 → 24 字符 Base64URL。
// 随机（而非自增或内容派生）保证 URL 不可枚举、不可猜测。
func newPublicID() (string, error) {
	// auth.RandomToken 返回 n 字节随机数的 Base64URL 编码，
	// 18 字节 → 24 字符，与公开 ID 的长度约定一致。
	return auth.RandomToken(18), nil
}

// uploadResult 是上传成功的响应体。
type uploadResult struct {
	PublicID         string `json:"publicId"`
	URL              string `json:"url"`
	MimeType         string `json:"mimeType"`
	ByteSize         int64  `json:"byteSize"`
	ContentHash      string `json:"contentHash"`
	OriginalFilename string `json:"originalFilename,omitempty"`
	Purpose          string `json:"purpose"`
}

// POST /api/v1/files — 上传通用文件（用途由 purpose 指定，默认 attachment）
func (h *Handler) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	u, _, err := h.currentUser(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "session.unauthenticated", "未登录或会话已过期")
		return
	}
	h.uploadFile(w, r, u.ID, models.FilePurposeAttachment)
}

// uploadFile 处理 multipart 上传的公共逻辑。
//
// 校验顺序：大小 → 扩展名白名单 → 内容嗅探与扩展名一致性，
// 三层校验共同防止「改扩展名伪装」与「超大文件打爆磁盘」。
func (h *Handler) uploadFile(w http.ResponseWriter, r *http.Request, ownerID int64, purpose string) {
	st := h.loadStorageSetting()
	if !st.IsEnabled {
		fail(w, r, http.StatusForbidden, "storage.disabled", "管理员已关闭文件存储")
		return
	}
	maxBytes := maxAttachmentBytes
	allow := allowedAttachmentExt
	if purpose == models.FilePurposeAvatar {
		maxBytes = maxAvatarBytes
		allow = allowedImageExt
	}

	// 内存阈值小于请求体总上限：超出部分由 ParseMultipartForm 落临时文件，
	// 总量由 BodyLimit 的 MaxBytesReader 兜底，避免请求体先完整落盘再被拒绝。
	if err := r.ParseMultipartForm(middleware.MultipartMemoryLimit()); err != nil {
		fail(w, r, http.StatusBadRequest, "file.too_large", fmt.Sprintf("文件过大，请上传 %d MB 以内的文件", maxBytes>>20))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		fail(w, r, http.StatusBadRequest, "file.missing", "请选择要上传的文件")
		return
	}
	defer file.Close()

	if header.Size > int64(maxBytes) {
		fail(w, r, http.StatusBadRequest, "file.too_large", fmt.Sprintf("文件过大，请上传 %d MB 以内的文件", maxBytes>>20))
		return
	}
	ext := strings.ToLower(filepath.Ext(header.Filename))
	expected, allowed := allow[ext]
	if !allowed {
		fail(w, r, http.StatusBadRequest, "file.invalid_type", "不支持的文件类型")
		return
	}
	// 多读 1 字节用于识别「超出上限」的文件，避免截断后被当成合法文件。
	buf, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		internal(w, r, err)
		return
	}
	if len(buf) > maxBytes {
		fail(w, r, http.StatusBadRequest, "file.too_large", fmt.Sprintf("文件过大，请上传 %d MB 以内的文件", maxBytes>>20))
		return
	}
	// 内容嗅探：确保实际内容与扩展名声明的类型一致。
	if sniffed := http.DetectContentType(buf); !mimeMatches(sniffed, expected, buf) {
		fail(w, r, http.StatusBadRequest, "file.invalid_type", "文件内容与扩展名不匹配")
		return
	}

	f, err := h.storeFile(r, ownerID, purpose, header.Filename, expected, buf)
	if err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, f)
}

// storeFile 落盘并写入 files 表记录。
func (h *Handler) storeFile(r *http.Request, ownerID int64, purpose, filename, mimeType string, buf []byte) (*uploadResult, error) {
	st := h.loadStorageSetting()
	publicID, err := newPublicID()
	if err != nil {
		return nil, err
	}
	// key 与内容无关、按用途+日期分片，避免单目录文件过多。
	key := fmt.Sprintf("%s/%s/%s", purpose, db.Now().Format("2006/01"), publicID)
	obj, err := h.storageProvider().Put(r.Context(), key, bytes.NewReader(buf), mimeType)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(buf)
	f := &models.File{
		PublicID:         publicID,
		Backend:          st.Backend,
		Key:              obj.Key,
		Purpose:          purpose,
		MimeType:         mimeType,
		ByteSize:         int64(len(buf)),
		ContentHash:      hex.EncodeToString(sum[:]),
		OriginalFilename: filename,
		OwnerUserID:      ownerID,
		CreatedAt:        db.Now(),
	}
	if _, err := h.db.NewInsert().Model(f).Exec(r.Context()); err != nil {
		// 元数据写入失败时清理已落盘的对象，避免产生无记录的孤儿文件。
		_ = h.storageProvider().Delete(r.Context(), key)
		return nil, err
	}
	return &uploadResult{
		PublicID:         f.PublicID,
		URL:              f.URL(),
		MimeType:         f.MimeType,
		ByteSize:         f.ByteSize,
		ContentHash:      f.ContentHash,
		OriginalFilename: f.OriginalFilename,
		Purpose:          f.Purpose,
	}, nil
}

// GET /api/v1/files/{publicId} — 读取文件内容
//
// 头像等公开用途免鉴权直出；其余用途需登录且为文件所有者或管理员，
// 避免通用文件端点成为越权读取面。
func (h *Handler) handleFileGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		fail(w, r, http.StatusMethodNotAllowed, "file.method_not_allowed", "仅支持 GET / HEAD")
		return
	}
	publicID := chi.URLParam(r, "publicId")
	f := &models.File{}
	if err := h.db.NewSelect().Model(f).Where("public_id = ?", publicID).Scan(r.Context()); err != nil {
		// 一律 404：不区分「不存在」与「无权访问」，避免泄露文件存在性。
		fail(w, r, http.StatusNotFound, "file.not_found", "文件不存在")
		return
	}
	if f.Purpose != models.FilePurposeAvatar {
		u, _, err := h.currentUser(r)
		if err != nil {
			fail(w, r, http.StatusNotFound, "file.not_found", "文件不存在")
			return
		}
		if f.OwnerUserID != u.ID && !u.IsAdmin {
			fail(w, r, http.StatusNotFound, "file.not_found", "文件不存在")
			return
		}
	}
	h.serveFile(w, r, f)
}

// serveFile 输出文件内容，带强 ETag、immutable 缓存与 Range 支持。
//
// URL 与内容一一绑定且永不原地覆盖，因此可以安全地设置一年 immutable 缓存；
// 配合强 ETag（内容 SHA-256）支持条件请求返回 304。
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, f *models.File) {
	etag := `"` + f.ContentHash + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, immutable, max-age=31536000")
	w.Header().Set("Content-Type", f.MimeType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// 内容已由服务端嗅探判定，禁止浏览器再次嗅探后当作 HTML 执行。
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")

	if match := r.Header.Get("If-None-Match"); match != "" {
		if strings.TrimSpace(match) == etag || strings.Contains(match, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	// apiNoStore 在 rootHandler 里对所有 /api/ 路径统一设置了 no-store，
	// 这里必须覆盖掉，否则 immutable 缓存头不生效。
	w.Header().Set("Pragma", "")
	w.Header().Del("Expires")

	rc, err := h.storageProvider().Get(r.Context(), f.Key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			fail(w, r, http.StatusNotFound, "file.not_found", "文件不存在")
			return
		}
		internal(w, r, err)
		return
	}
	defer rc.Close()

	// Range 支持（RFC 7233）：仅支持单区间，多区间直接回退为完整响应。
	start, end, ok := parseRange(r.Header.Get("Range"), f.ByteSize)
	w.Header().Set("Accept-Ranges", "bytes")
	if ok {
		if start >= f.ByteSize {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", f.ByteSize))
			fail(w, r, http.StatusRequestedRangeNotSatisfiable, "file.range_invalid", "请求范围无效")
			return
		}
		if _, err := io.CopyN(io.Discard, rc, start); err != nil {
			return
		}
		length := end - start + 1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, f.ByteSize))
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		w.WriteHeader(http.StatusPartialContent)
		if r.Method != http.MethodHead {
			_, _ = io.CopyN(w, rc, length)
		}
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(f.ByteSize, 10))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, rc)
	}
}

// parseRange 解析单行 Range 头，返回 [start, end] 闭区间。
// ok 为 false 表示无 Range 头或格式不支持（交由调用方回退为完整响应）。
func parseRange(header string, size int64) (start, end int64, ok bool) {
	if size <= 0 {
		return 0, 0, false
	}
	const prefix = "bytes="
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(header)), prefix) {
		return 0, 0, false
	}
	spec := strings.TrimSpace(header[len(prefix):])
	// 多区间（含逗号）不处理，直接返回完整内容。
	if strings.Contains(spec, ",") {
		return 0, 0, false
	}
	dash := strings.Index(spec, "-")
	if dash < 0 {
		return 0, 0, false
	}
	first := strings.TrimSpace(spec[:dash])
	last := strings.TrimSpace(spec[dash+1:])
	switch {
	case first == "" && last != "":
		// suffix-range: bytes=-N 表示最后 N 字节。
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true
	case first != "":
		s, err := strconv.ParseInt(first, 10, 64)
		if err != nil || s < 0 {
			return 0, 0, false
		}
		e := size - 1
		if last != "" {
			if v, err := strconv.ParseInt(last, 10, 64); err == nil && v >= s {
				e = v
			}
		}
		if e > size-1 {
			e = size - 1
		}
		return s, e, true
	}
	return 0, 0, false
}

// ---- 管理端点 ----

// GET /api/v1/admin/files?purpose=&page=&pageSize= — 文件记录列表
func (h *Handler) handleAdminFiles(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	page, pageSize := parsePage(r)
	q := h.db.NewSelect().Model((*models.File)(nil))
	if p := strings.TrimSpace(r.URL.Query().Get("purpose")); p != "" {
		q = q.Where("purpose = ?", p)
	}
	var files []models.File
	total, err := q.Clone().Count(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	if err := q.Order("created_at DESC").Limit(pageSize).Offset((page-1)*pageSize).Scan(r.Context(), &files); err != nil {
		internal(w, r, err)
		return
	}
	if files == nil {
		files = []models.File{}
	}
	ok(w, r, map[string]any{
		"items":    h.filePayloads(files),
		"page":     page,
		"pageSize": pageSize,
		"total":    total,
	})
}

// DELETE /api/v1/admin/files/{publicId} — 删除单个文件（元数据 + 存储对象）
func (h *Handler) handleAdminDeleteFile(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	publicID := chi.URLParam(r, "publicId")
	f := &models.File{}
	if err := h.db.NewSelect().Model(f).Where("public_id = ?", publicID).Scan(r.Context()); err != nil {
		fail(w, r, http.StatusNotFound, "file.not_found", "文件不存在")
		return
	}
	if err := h.storageProvider().Delete(r.Context(), f.Key); err != nil && !errors.Is(err, storage.ErrNotFound) {
		internal(w, r, err)
		return
	}
	if _, err := h.db.NewDelete().Model(f).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, map[string]any{"success": true})
}

// GET /api/v1/admin/files/orphans?limit= — 孤儿文件列表
//
// 孤儿定义：已被解绑（detached_at 非空）且宽限期已过的文件。
// 仍在宽限期内的只列入待清理统计，不返回给前端，避免误删。
func (h *Handler) handleAdminOrphanFiles(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	cutoff := db.Now().Add(-orphanGracePeriod)
	var files []models.File
	if err := h.db.NewSelect().Model(&files).
		Where("detached_at IS NOT NULL AND detached_at < ?", cutoff).
		Order("detached_at ASC").Scan(r.Context(), &files); err != nil {
		internal(w, r, err)
		return
	}
	if files == nil {
		files = []models.File{}
	}
	// 待清理：已解绑但仍在宽限期内。
	pending, _ := h.db.NewSelect().Model((*models.File)(nil)).
		Where("detached_at IS NOT NULL AND detached_at >= ?", cutoff).Count(r.Context())
	ok(w, r, map[string]any{
		"items":       h.filePayloads(files),
		"total":       len(files),
		"pending":     pending,
		"gracePeriod": int(orphanGracePeriod.Hours()),
	})
}

// POST /api/v1/admin/files/orphans/cleanup — 清理孤儿文件
// 返回 { deleted, failed }：单个对象删除失败不影响其余文件继续回收。
func (h *Handler) handleAdminCleanupOrphans(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	// 与任务调度器共用同一份回收实现，避免两套逻辑漂移。
	deleted, failed := cleanupOrphanFilesWith(h.db, h.storageProvider(), r.Context(), db.Now().Add(-orphanGracePeriod))
	ok(w, r, map[string]any{"deleted": deleted, "failed": failed})
}

// storageUsage 汇总存储用量：按用途的文件数与字节、总量、待回收量。
// 供「存储管理」统计卡与「数据清理」的占用概览共用 —— 两处各写一遍聚合口径，
// 迟早会出现同一份数据在两个页面对不上的情况。
func (h *Handler) storageUsage(ctx context.Context) (map[string]any, error) {
	type row struct {
		Purpose string `bun:"purpose"`
		Count   int    `bun:"count"`
		Bytes   int64  `bun:"bytes"`
	}
	var rows []row
	if err := h.db.NewSelect().Model((*models.File)(nil)).
		Column("purpose").
		ColumnExpr("COUNT(*) AS count").
		ColumnExpr("COALESCE(SUM(byte_size), 0) AS bytes").
		Group("purpose").Scan(ctx, &rows); err != nil {
		return nil, err
	}

	byPurpose := map[string]any{}
	var totalBytes int64
	var totalCount int
	for _, r2 := range rows {
		byPurpose[r2.Purpose] = map[string]any{"count": r2.Count, "bytes": r2.Bytes}
		totalBytes += r2.Bytes
		totalCount += r2.Count
	}
	// 已解绑待回收的容量（含宽限期内）。
	var orphanBytes int64
	_ = h.db.NewSelect().Model((*models.File)(nil)).
		ColumnExpr("COALESCE(SUM(byte_size), 0)").
		Where("detached_at IS NOT NULL").Scan(ctx, &orphanBytes)

	st := h.loadStorageSetting()
	return map[string]any{
		"backend":     st.Backend,
		"isEnabled":   st.IsEnabled,
		"totalFiles":  totalCount,
		"totalBytes":  totalBytes,
		"orphanBytes": orphanBytes,
		"byPurpose":   byPurpose,
	}, nil
}

// GET /api/v1/admin/storage/stats — 存储用量统计
func (h *Handler) handleAdminStorageStats(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	usage, err := h.storageUsage(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	ok(w, r, usage)
}

// filePayloads 构造管理端展示用负载（补上可访问 URL）。
func (h *Handler) filePayloads(files []models.File) []map[string]any {
	out := make([]map[string]any, 0, len(files))
	for i := range files {
		f := &files[i]
		out = append(out, map[string]any{
			"id":               f.ID,
			"publicId":         f.PublicID,
			"url":              f.URL(),
			"purpose":          f.Purpose,
			"mimeType":         f.MimeType,
			"byteSize":         f.ByteSize,
			"contentHash":      f.ContentHash,
			"originalFilename": f.OriginalFilename,
			"ownerUserId":      f.OwnerUserID,
			"detachedAt":       f.DetachedAt,
			"createdAt":        f.CreatedAt,
		})
	}
	return out
}

// detachFile 标记文件已不被业务引用，进入孤儿回收宽限期。
// 不立即删除：并发上传/回退场景下对象可能仍在使用。
func (h *Handler) detachFile(publicID string) {
	if publicID == "" {
		return
	}
	now := db.Now()
	_, _ = h.db.NewUpdate().Model((*models.File)(nil)).
		Set("detached_at = ?", now).
		Where("public_id = ?", publicID).
		Where("detached_at IS NULL").
		Exec(context.Background())
}

// publicIDFromURL 从头像 URL 中提取 publicId（用于换头像时解绑旧文件）。
func publicIDFromURL(raw string) string {
	const prefix = "/api/v1/files/"
	i := strings.Index(raw, prefix)
	if i < 0 {
		return ""
	}
	id := raw[i+len(prefix):]
	// URL 中可能带查询串或路径片段，只取第一段。
	if j := strings.IndexAny(id, "?#/"); j >= 0 {
		id = id[:j]
	}
	return id
}

// parsePage 解析分页参数（page / pageSize），页码从 1 开始。
// 非法值回退到默认页大小，且对 pageSize 设上限，避免一次拉取过多行。
func parsePage(r *http.Request) (page, pageSize int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ = strconv.Atoi(r.URL.Query().Get("pageSize"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return page, pageSize
}
