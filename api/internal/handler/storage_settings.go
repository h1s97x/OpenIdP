package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/uptrace/bun"

	"github.com/h1s97x/openidp/api/internal/storage"
)

// ---- 对象存储配置（单行，id=1；管理后台「存储管理」维护）----

// loadStorageSetting 返回持久化的对象存储配置。
func (h *Handler) loadStorageSetting() *models.StorageSetting {
	return cached(h.conf, peekStorage, storeStorage, h.fetchStorageSetting)
}

// fetchStorageSetting 读取对象存储配置；缺失时写入一行空配置。
// 初始化不填入任何内容：本地目录与 S3 连接参数全部留空，由管理员在
// 「系统设置 → 存储管理」中自行填写；LocalPath 留空时回退 DATA_DIR。
func (h *Handler) fetchStorageSetting() *models.StorageSetting {
	st := &models.StorageSetting{}
	err := h.db.NewSelect().Model(st).Where("id = 1").Scan(context.Background())
	if err != nil {
		st = &models.StorageSetting{
			ID:              1,
			IsEnabled:       true,
			Backend:         h.cfg.StorageBackend,
			LocalPath:       "",
			S3Endpoint:      "",
			S3Bucket:        "",
			S3Region:        "",
			S3Prefix:        "",
			S3PublicBaseURL: "",
			S3AccessKey:     "",
			S3SecretKey:     "",
			UpdatedAt:       db.Now(),
		}
		_, _ = h.db.NewInsert().Model(st).Exec(context.Background())
	}
	if st.Backend == "" {
		st.Backend = "local"
	}
	return st
}

// GET /api/v1/admin/storage — 读取存储配置（密钥不回传明文）
func (h *Handler) handleAdminGetStorage(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	ok(w, r, h.storagePayload(h.loadStorageSetting()))
}

// storageRequest 是存储配置更新/测试接口的请求体。
type storageRequest struct {
	IsEnabled       *bool  `json:"isEnabled"`
	Backend         string `json:"backend"`
	LocalPath       string `json:"localPath"`
	S3Endpoint      string `json:"s3Endpoint"`
	S3Bucket        string `json:"s3Bucket"`
	S3Region        string `json:"s3Region"`
	S3Prefix        string `json:"s3Prefix"`
	S3PublicBaseURL string `json:"s3PublicBaseUrl"`
	S3AccessKey     string `json:"s3AccessKey"`
	// S3SecretKey 为空表示保持原值不变（前端不回显密钥）。
	S3SecretKey string `json:"s3SecretKey"`
}

// applyStorageRequest 把请求体合并到当前配置上（不落库）。
// 返回 nil 表示校验失败，调用方已写出错误响应。
//
// 校验错误通过返回值传递而非直接写响应，是为了让「测试连通性」与「保存」
// 共用同一份合并逻辑，避免两处实现漂移（此前 pendingStorageFrom 与
// handleAdminUpdateStorage 各写一份，行为已经不一致）。
func (h *Handler) applyStorageRequest(w http.ResponseWriter, r *http.Request, req *storageRequest) *models.StorageSetting {
	st := h.loadStorageSetting()
	backend := strings.ToLower(strings.TrimSpace(req.Backend))
	if backend != "" {
		if backend != "local" && backend != "s3" {
			fail(w, r, http.StatusBadRequest, "storage.invalid_backend", "存储后端只能是 local 或 s3")
			return nil
		}
		st.Backend = backend
	}
	if req.IsEnabled != nil {
		st.IsEnabled = *req.IsEnabled
	}
	st.LocalPath = strings.TrimSpace(req.LocalPath)
	st.S3Endpoint = strings.TrimSpace(req.S3Endpoint)
	st.S3Bucket = strings.TrimSpace(req.S3Bucket)
	st.S3Region = strings.TrimSpace(req.S3Region)
	st.S3Prefix = strings.TrimSpace(req.S3Prefix)
	st.S3PublicBaseURL = strings.TrimSpace(req.S3PublicBaseURL)
	st.S3AccessKey = strings.TrimSpace(req.S3AccessKey)
	if strings.TrimSpace(req.S3SecretKey) != "" {
		st.S3SecretKey = secretpkg.Encrypt(strings.TrimSpace(req.S3SecretKey))
	}
	if st.Backend == "s3" {
		if st.S3Bucket == "" {
			fail(w, r, http.StatusBadRequest, "storage.missing_bucket", "使用 S3 存储时必须填写存储桶")
			return nil
		}
		if st.S3SecretKey == "" {
			fail(w, r, http.StatusBadRequest, "storage.missing_secret", "使用 S3 存储时必须填写 SecretKey")
			return nil
		}
	}
	return st
}

// persistStorage 落库并热切换运行期的存储 Provider。
func (h *Handler) persistStorage(w http.ResponseWriter, r *http.Request, st *models.StorageSetting) bool {
	st.UpdatedAt = db.Now()
	if _, err := h.db.NewUpdate().Model(st).WherePK().Exec(r.Context()); err != nil {
		internal(w, r, err)
		return false
	}
	h.conf.invalidate()
	// 重建存储 Provider，使新配置立即生效（无需重启）。
	h.applyStorageSetting(st)
	h.auditConfigChange(r, "storage", "update", 0, []string{
		"isEnabled", "backend", "localPath",
		"s3Endpoint", "s3Bucket", "s3Region", "s3Prefix", "s3PublicBaseUrl",
		"s3AccessKey", "s3SecretKey",
	})
	return true
}

// PUT /api/v1/admin/storage — 更新存储配置（先测试连通性再落库）
//
// 与「直接落库 + 单独测试」不同：配置不可用时直接拒绝保存，
// 避免管理员误配后上传全部失败却已经持久化了错误配置。
func (h *Handler) handleAdminUpdateStorage(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req storageRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	st := h.applyStorageRequest(w, r, &req)
	if st == nil {
		return
	}
	if err := h.probeStorage(r, st); err != nil {
		fail(w, r, http.StatusBadRequest, "storage.test_failed", "存储配置测试失败："+err.Error())
		return
	}
	if !h.persistStorage(w, r, st) {
		return
	}
	ok(w, r, h.storagePayload(st))
}

// POST /api/v1/admin/storage/test-and-save — 测试连通性，通过后才落库
//
// 请求体只能解码一次：此前先 pendingStorageFrom（内部 decodeJSONBody 吃光
// body）再调 handleAdminUpdateStorage 重新解码，body 已到 EOF，必然 400，
// 导致「测试连通性并保存」完全不可用。这里改为解码一次、合并一次、共用落库。
func (h *Handler) handleAdminStorageTestAndSave(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	var req storageRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	st := h.applyStorageRequest(w, r, &req)
	if st == nil {
		return
	}
	// 配置校验与落库路径与 PUT 完全一致，测试即真实写入一个探针对象。
	if err := h.probeStorage(r, st); err != nil {
		fail(w, r, http.StatusBadRequest, "storage.test_failed", "存储配置测试失败："+err.Error())
		return
	}
	if !h.persistStorage(w, r, st) {
		return
	}
	ok(w, r, h.storagePayload(st))
}

// probeStorage 写入并删除一个探针对象，验证配置可用。
func (h *Handler) probeStorage(r *http.Request, st *models.StorageSetting) error {
	p := h.providerFrom(st)
	key := ".openidp-probe-" + db.Now().Format("20060102150405")
	obj, err := p.Put(r.Context(), key, strings.NewReader("openidp"), "text/plain")
	if err != nil {
		return err
	}
	// 读回校验，确认权限配置既能写也能读。
	rc, err := p.Get(r.Context(), obj.Key)
	if err == nil {
		_ = rc.Close()
	}
	_ = p.Delete(r.Context(), obj.Key)
	return err
}

// providerFrom 按配置构造一个独立的存储 Provider（用于测试与热切换）。
func (h *Handler) providerFrom(st *models.StorageSetting) storage.Provider {
	localDir := auth.FirstNonEmpty(st.LocalPath, h.cfg.StorageLocalDir, h.cfg.DataDir)
	return storage.New(storage.Config{
		Backend:         st.Backend,
		LocalDir:        localDir,
		S3Endpoint:      st.S3Endpoint,
		S3Bucket:        st.S3Bucket,
		S3Region:        auth.FirstNonEmpty(st.S3Region, "us-east-1"),
		S3KeyID:         st.S3AccessKey,
		S3Secret:        secretpkg.Decrypt(st.S3SecretKey),
		S3PublicBaseURL: st.S3PublicBaseURL,
	})
}

// applyStorageSetting 按配置重建运行期的存储 Provider。
func (h *Handler) applyStorageSetting(st *models.StorageSetting) {
	// 整体替换 Provider：切换后端时并发的文件读写仍持有旧 Provider 的一份引用，
	// 不会读到「改了一半」的状态。
	h.setStorageProvider(h.providerFrom(st))
}

// InitStorage 在启动时加载持久化的存储配置并重建 Provider。
// 必须在建表（Migrate）之后调用，否则读取配置会打到不存在的表。
func (h *Handler) InitStorage() {
	st := h.loadStorageSetting()
	h.applyStorageSetting(st)
}

// CleanupOrphanFiles 定期回收孤儿文件（供任务调度器调用）。
// 返回被删除与失败的数量，便于写入运行日志。
func (h *Handler) CleanupOrphanFiles(ctx context.Context) (deleted, failed int) {
	return cleanupOrphanFilesWith(h.db, h.storageProvider(), ctx, db.Now().Add(-orphanGracePeriod))
}

// storagePayload 构造存储配置的对外负载：密钥只回传是否已配置。
func (h *Handler) storagePayload(st *models.StorageSetting) map[string]any {
	return map[string]any{
		"isEnabled":       st.IsEnabled,
		"backend":         st.Backend,
		"localPath":       st.LocalPath,
		"s3Endpoint":      st.S3Endpoint,
		"s3Bucket":        st.S3Bucket,
		"s3Region":        st.S3Region,
		"s3Prefix":        st.S3Prefix,
		"s3PublicBaseUrl": st.S3PublicBaseURL,
		"s3AccessKey":     st.S3AccessKey,
		"hasSecretKey":    st.S3SecretKey != "",
	}
}

// cleanupOrphanFilesWith 物理删除宽限期已过的孤儿文件（无 HTTP 上下文版本）。
// 与 cleanupOrphanFiles 行为一致：单个对象删除失败不影响其余文件继续回收。
func cleanupOrphanFilesWith(db *bun.DB, store storage.Provider, ctx context.Context, cutoff time.Time) (deleted, failed int) {
	var files []models.File
	if err := db.NewSelect().Model(&files).
		Where("detached_at IS NOT NULL AND detached_at < ?", cutoff).Scan(ctx); err != nil {
		return 0, 0
	}
	for i := range files {
		f := &files[i]
		if err := store.Delete(ctx, f.Key); err != nil && !errors.Is(err, storage.ErrNotFound) {
			failed++
			continue
		}
		if _, err := db.NewDelete().Model(f).WherePK().Exec(ctx); err != nil {
			failed++
			continue
		}
		deleted++
	}
	return deleted, failed
}
