package handler

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/uptrace/bun"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/logging"
	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---- 数据备份（导出 / 恢复）----
//
// 备份是一个 ZIP，内容分两部分：
//
//	manifest.json   格式标识、版本、导出者、包含的分组与各表行数
//	settings.json   系统设置（品牌 / 安全策略 / 邮件 / 人机验证 / 短信 / 存储 /
//	                归属地 / 审计 / 清理 / 代理 + 登录提供商 + OAuth 应用 + 权限项）
//	data/*.json     业务数据表，一张表一个条目（users / sessions / events …）
//
// 分组是可选的：默认只导出系统设置；用户、会话、事件等业务数据体积大且敏感，
// 必须由管理员显式勾选（见 parseBackupGroups）。
//
// 有意不包含 files（文件记录）：文件本体在本地磁盘或对象存储里，元数据单独搬运
// 会造出「记录在、文件不在」的悬空数据；迁移实例时应连同存储目录一起搬运。
//
// 密钥：**导出时解密**（secrets 段与 ClientSecret 等字段为明文），否则换一台
// 实例恢复时 ENCRYPTION_KEY 不同，SMTP 密码、存储密钥、提供商密钥全都解不开。
// 代价是备份文件本身就是凭据明文，必须当作机密文件保管（接口按附件下载、
// 禁止缓存）。恢复时按 manifest 的 secretsPlaintext 标记重新加密落库，
// 保证库内始终是密文。
//
// 恢复边界：账号数据不参与「设置」恢复，且任何数据分组里属于当前登录管理员的行
// 都会被跳过（见 backupDataTable.UserColumn）—— 执行恢复的人不会被自己的旧备份覆盖。
const (
	// backupFormat 是备份容器的格式标识。恢复时严格校验，避免误传其它 ZIP。
	backupFormat = "openidp.backup"
	// backupVersion 是容器版本。结构变化时递增，恢复时只接受已知版本。
	backupVersion = 2

	// ZIP 内的固定条目名。
	backupManifestEntry = "manifest.json"
	backupSettingsEntry = "settings.json"
	// backupDataPrefix 是数据表条目的前缀（后接表名 + ".json"）。
	backupDataPrefix = "data/"

	// 备份分组标识。与前端 BACKUP_GROUPS 是同一个契约，改动需两侧同步。
	groupSettings = "settings"
	groupUsers    = "users"
	groupSessions = "sessions"
	groupEvents   = "events"
	groupOAuth    = "oauth"
)

// backupGroupOrder 是分组的固定展示顺序（解析回执、manifest 均按它排序），
// 让同一份备份每次解析出来的顺序稳定，便于人工比对。
var backupGroupOrder = []string{groupSettings, groupUsers, groupSessions, groupEvents, groupOAuth}

// backupManifest 是 ZIP 的目录文件：说明这份备份是什么、装了什么。
type backupManifest struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exportedAt"`
	// ExportedBy 记录导出者用户名，便于人工核对备份来源。
	ExportedBy string `json:"exportedBy,omitempty"`
	// SecretsPlaintext 标记 settings.json 里的凭据是明文（当前固定为 true）：
	// 恢复时据此重新加密落库，未来若要改回密文导出，恢复端无需跟着改。
	SecretsPlaintext bool     `json:"secretsPlaintext"`
	Groups           []string `json:"groups"`
	Tables           []string `json:"tables,omitempty"`
	// Counts 是各数据表导出的行数（仅数据分组）。
	Counts map[string]int `json:"counts,omitempty"`
}

// backupDocument 是 settings.json 的结构：每个字段对应一类设置。
//
// 指针 + omitempty 表达「该分区是否参与本次导出/恢复」：分区为 nil 时恢复不动
// 对应配置，为将来做「只恢复某几个分区」留出空间，也让导出结果保持精简。
type backupDocument struct {
	Site     *models.SiteSetting        `json:"site,omitempty"`
	Security *models.SecurityPolicy     `json:"security,omitempty"`
	Mail     *models.MailSetting        `json:"mail,omitempty"`
	Captcha  *models.CaptchaSetting     `json:"captcha,omitempty"`
	Sms      *models.SmsSetting         `json:"sms,omitempty"`
	Storage  *models.StorageSetting     `json:"storage,omitempty"`
	Location *models.LocationSetting    `json:"location,omitempty"`
	Audit    *models.AuditSetting       `json:"audit,omitempty"`
	Cleanup  *models.DataCleanupSetting `json:"cleanup,omitempty"`
	Proxy    *models.ProxySetting       `json:"proxy,omitempty"`

	OAuthProviders []models.OAuthProvider `json:"oauthProviders,omitempty"`
	OAuthClients   []models.OAuthClient   `json:"oauthClients,omitempty"`
	OAuthScopes    []models.OAuthScope    `json:"oauthScopes,omitempty"`

	// Secrets 承载 models 里被 `json:"-"` 隐藏的凭据（导出为明文，恢复时加密落库）。
	Secrets backupSecrets `json:"secrets"`
}

// backupSecrets 集中承载各配置里的凭据字段。
type backupSecrets struct {
	MailPassword           string           `json:"mailPassword,omitempty"`
	CaptchaGeetestKey      string           `json:"captchaGeetestKey,omitempty"`
	CaptchaTurnstileSecret string           `json:"captchaTurnstileSecret,omitempty"`
	StorageS3SecretKey     string           `json:"storageS3SecretKey,omitempty"`
	ProxyPassword          string           `json:"proxyPassword,omitempty"`
	Sms                    backupSmsSecrets `json:"sms"`

	// OAuthProviders / OAuthClients 以主键为键（提供商 ID / 客户端 ID）。
	OAuthProviders map[string]string `json:"oauthProviders,omitempty"`
	OAuthClients   map[string]string `json:"oauthClients,omitempty"`
}

// backupSmsSecrets 是短信服务商凭据，键名与 models.SmsSetting 字段一一对应。
type backupSmsSecrets struct {
	AliyunAccessKeySecret string `json:"aliyunAccessKeySecret,omitempty"`
	TencentSecretKey      string `json:"tencentSecretKey,omitempty"`
	VolcAccessKeySecret   string `json:"volcAccessKeySecret,omitempty"`
	HuaweiAppSecret       string `json:"huaweiAppSecret,omitempty"`
	QimoAuthToken         string `json:"qimoAuthToken,omitempty"`
	SubmailAppKey         string `json:"submailAppKey,omitempty"`
	CustomSecret          string `json:"customSecret,omitempty"`
}

// backupGroupResult 是一个分组的恢复回执。
type backupGroupResult struct {
	Name string `json:"name"`
	// Sections 仅 settings 分组使用：本次恢复到的设置分区名。
	Sections []string `json:"sections,omitempty"`
	// Tables 仅数据分组使用：各表的增改与被跳过的行数。
	Tables []backupTableResult `json:"tables,omitempty"`
}

// backupUserRef 回执「当前登录的管理员账号」：明确告诉恢复者这个账号没被动过。
type backupUserRef struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// backupRestoreSummary 是恢复结果回执。
type backupRestoreSummary struct {
	Groups []backupGroupResult `json:"groups"`
	// Missing 是请求恢复但备份文件里不存在的条目（分组或表名）。
	Missing []string `json:"missing,omitempty"`
	// CurrentUser 是恢复边界：当前账号的数据不参与恢复，执行者始终保持登录态。
	CurrentUser backupUserRef `json:"currentUser"`
}

// GET /api/v1/admin/backup/export?groups=settings,users,...
//
// 导出备份 ZIP（仅管理员）。groups 缺省为 settings。
func (h *Handler) handleAdminBackupExport(w http.ResponseWriter, r *http.Request) {
	u, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	groups, err := parseBackupGroups(r.URL.Query().Get("groups"))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "backup.invalid_group", err.Error())
		return
	}

	// 响应头必须在写出第一块数据之前设置：ZIP 一旦开始输出，状态码就改不了了。
	// 因此所有校验（鉴权、分组、用户）都在这之前完成，流中间的错误只能中止。
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="openidp-backup-`+db.Now().Format("20060102-150405")+`.zip"`)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")

	ctx := r.Context()
	zw := zip.NewWriter(w)
	manifest := backupManifest{
		Format:           backupFormat,
		Version:          backupVersion,
		ExportedAt:       db.Now(),
		SecretsPlaintext: true,
		Counts:           map[string]int{},
	}
	if u != nil {
		manifest.ExportedBy = u.Username
	}

	if containsBackupGroup(groups, groupSettings) {
		doc, err := h.buildSettingsSnapshot(ctx)
		if err != nil {
			h.abortBackupExport(r, zw, err)
			return
		}
		if err := writeZipJSON(zw, backupSettingsEntry, doc); err != nil {
			h.abortBackupExport(r, zw, err)
			return
		}
		manifest.Groups = append(manifest.Groups, groupSettings)
	}

	for _, t := range backupDataTables {
		if !containsBackupGroup(groups, t.Group) {
			continue
		}
		n, err := dumpTableToZip(ctx, h.db, zw, t)
		if err != nil {
			h.abortBackupExport(r, zw, err)
			return
		}
		manifest.Counts[t.Name] = n
		manifest.Tables = append(manifest.Tables, t.Name)
		if !containsBackupGroup(manifest.Groups, t.Group) {
			manifest.Groups = append(manifest.Groups, t.Group)
		}
	}

	// manifest 最后写入：它要带各表行数，只有全部导出完成才知道；
	// ZIP 条目顺序不影响读取（读取端按名字取条目）。
	manifest.Groups = orderBackupGroups(manifest.Groups)
	if err := writeZipJSON(zw, backupManifestEntry, manifest); err != nil {
		h.abortBackupExport(r, zw, err)
		return
	}
	if err := zw.Close(); err != nil {
		h.abortBackupExport(r, zw, err)
		return
	}

	h.audit(r, "success", "backup", "export", u.ID, "导出数据备份："+strings.Join(manifest.Groups, ","))
	h.logEvent(r, u.ID, &models.Event{
		Type:     "admin.backup_exported",
		Summary:  "导出数据备份",
		Metadata: map[string]string{"groups": strings.Join(manifest.Groups, ","), "tables": strings.Join(manifest.Tables, ",")},
	})
}

// abortBackupExport 处理「响应已开始输出」之后的错误：状态码已无法修改，
// 只能记日志并关闭 ZIP（客户端会拿到一个不完整的归档，解压时报错）。
func (h *Handler) abortBackupExport(r *http.Request, zw *zip.Writer, err error) {
	logging.Error("导出数据备份中断：%v (request_id=%s)", err, middleware.RequestID(r.Context()))
	_ = zw.Close()
}

// POST /api/v1/admin/backup/restore?groups=settings,users,...
//
// 用备份 ZIP 恢复（仅管理员）：Body 为 ZIP 二进制。
func (h *Handler) handleAdminBackupRestore(w http.ResponseWriter, r *http.Request) {
	u, authorized := h.requireAdmin(r)
	if !authorized {
		adminForbidden(w, r)
		return
	}
	groups, err := parseBackupGroups(r.URL.Query().Get("groups"))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "backup.invalid_group", err.Error())
		return
	}

	zr, cleanup, err := h.spoolBackupArchive(r)
	if err != nil {
		h.failBackupUpload(w, r, err)
		return
	}
	defer cleanup()

	// 先读目录校验格式与版本，再动数据库：避免用一份陌生文件写坏配置。
	manifest, err := readBackupManifest(zr)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "backup.invalid_manifest", err.Error())
		return
	}
	if manifest.Format != backupFormat {
		fail(w, r, http.StatusBadRequest, "backup.invalid_format", "不是有效的 OpenIdP 数据备份")
		return
	}
	if manifest.Version != backupVersion {
		fail(w, r, http.StatusBadRequest, "backup.unsupported_version", "备份文件版本不受支持")
		return
	}

	summary := backupRestoreSummary{CurrentUser: backupUserRef{ID: u.ID, Username: u.Username}}
	// 全部写在一个事务里：恢复是「整份替换 + 批量合并」，写一半失败会留下
	// 半新半旧的数据，比保持原样更难排查，也让重试结果不可预期。
	err = h.db.RunInTx(r.Context(), nil, func(ctx context.Context, tx bun.Tx) error {
		return h.applyBackupArchive(ctx, tx, zr, manifest, groups, u, &summary)
	})
	if err != nil {
		internal(w, r, err)
		return
	}

	// 让新配置立即生效：先清进程内配置缓存，再把邮件 / 人机验证 / 短信重新装载。
	h.conf.invalidate()
	h.applyPersistedSettings()

	h.audit(r, "success", "backup", "restore", u.ID, "恢复数据备份："+strings.Join(groups, ","))
	h.auditConfigChange(r, "backup", "restore", u.ID, groups)
	h.logEvent(r, u.ID, &models.Event{
		Type:     "admin.backup_restored",
		Summary:  "恢复数据备份",
		Metadata: map[string]string{"groups": strings.Join(groups, ",")},
	})
	ok(w, r, summary)
}

// POST /api/v1/admin/backup/inspect
//
// 上传备份 ZIP，只解析目录并回报「这份文件里到底有什么」（仅管理员）。
//
// 存在的意义：恢复界面不该凭空猜文件内容 —— 先解析、再把可选项限定为文件里
// 实际存在的分组与表，用户看到的每一个勾选框都对应归档里的真实数据。
func (h *Handler) handleAdminBackupInspect(w http.ResponseWriter, r *http.Request) {
	if _, authorized := h.requireAdmin(r); !authorized {
		adminForbidden(w, r)
		return
	}
	zr, cleanup, err := h.spoolBackupArchive(r)
	if err != nil {
		h.failBackupUpload(w, r, err)
		return
	}
	defer cleanup()

	manifest, err := readBackupManifest(zr)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "backup.invalid_manifest", err.Error())
		return
	}
	if manifest.Format != backupFormat {
		fail(w, r, http.StatusBadRequest, "backup.invalid_format", "不是有效的 OpenIdP 数据备份")
		return
	}
	if manifest.Version != backupVersion {
		fail(w, r, http.StatusBadRequest, "backup.unsupported_version", "备份文件版本不受支持")
		return
	}

	// 以归档内实际存在的条目为准（而不是 manifest 的自述）：
	// manifest 缺失某张表、或文件被手工改过时，界面展示的仍是真实可恢复的内容。
	present := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		present[f.Name] = true
	}
	resp := backupInspectResult{
		Format:           manifest.Format,
		Version:          manifest.Version,
		ExportedAt:       manifest.ExportedAt,
		ExportedBy:       manifest.ExportedBy,
		SecretsPlaintext: manifest.SecretsPlaintext,
	}
	if present[backupSettingsEntry] {
		resp.Groups = append(resp.Groups, backupInspectGroup{Name: groupSettings})
	}
	for _, group := range backupGroupOrder {
		if group == groupSettings {
			continue
		}
		names := make([]string, 0, 4)
		for _, t := range backupDataTables {
			if t.Group != group {
				continue
			}
			if present[backupDataPrefix+t.Name+".json"] {
				names = append(names, t.Name)
			}
		}
		if len(names) > 0 {
			resp.Groups = append(resp.Groups, backupInspectGroup{Name: group, Tables: names})
		}
	}
	ok(w, r, resp)
}

// backupInspectGroup 是「文件里存在」的一个分组及其数据表。
type backupInspectGroup struct {
	Name string `json:"name"`
	// Tables 是该分组在归档中实际存在的表名；settings 分组为空（它是单个文件）。
	Tables []string `json:"tables,omitempty"`
}

// backupInspectResult 是上传解析的回执：文件元信息 + 实际包含的分组。
type backupInspectResult struct {
	Format           string               `json:"format"`
	Version          int                  `json:"version"`
	ExportedAt       time.Time            `json:"exportedAt"`
	ExportedBy       string               `json:"exportedBy,omitempty"`
	SecretsPlaintext bool                 `json:"secretsPlaintext"`
	Groups           []backupInspectGroup `json:"groups"`
}

// 上传阶段的哨兵错误：由 failBackupUpload 统一映射为对外错误码。
var (
	errBackupRead   = errors.New("backup: read failed")
	errBackupEmpty  = errors.New("backup: archive is empty")
	errBackupNotZip = errors.New("backup: not a zip archive")
)

// spoolBackupArchive 把请求体（ZIP 二进制）落到临时文件并返回可随机访问的 reader。
//
// 为什么必须落盘：zip.NewReader 需要 io.ReaderAt，而完整备份可能有几十 MB，
// 整块读进内存不合适。临时文件建在数据目录下（与数据库同级），避免落到系统
// 临时目录后被清理策略带走。返回的 cleanup 由调用方 defer。
func (h *Handler) spoolBackupArchive(r *http.Request) (*zip.Reader, func(), error) {
	tmp, err := os.CreateTemp(h.cfg.DataDir, "backup-*.zip")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}
	size, err := io.Copy(tmp, r.Body)
	if err != nil {
		cleanup()
		return nil, nil, errBackupRead
	}
	if size == 0 {
		cleanup()
		return nil, nil, errBackupEmpty
	}
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		cleanup()
		return nil, nil, errBackupNotZip
	}
	return zr, cleanup, nil
}

// failBackupUpload 把上传解析阶段的错误映射成统一的响应：
// 已知的输入问题回 400，其余（如建临时文件失败）按内部错误处理。
func (h *Handler) failBackupUpload(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errBackupEmpty):
		fail(w, r, http.StatusBadRequest, "backup.empty", "备份文件为空")
	case errors.Is(err, errBackupNotZip):
		fail(w, r, http.StatusBadRequest, "backup.invalid_archive", "不是有效的 ZIP 备份文件")
	case errors.Is(err, errBackupRead):
		fail(w, r, http.StatusBadRequest, "backup.read_failed", "备份文件读取失败")
	default:
		internal(w, r, err)
	}
}

// applyBackupArchive 按分组把归档内容写入数据库。
func (h *Handler) applyBackupArchive(
	ctx context.Context,
	tx bun.Tx,
	zr *zip.Reader,
	manifest *backupManifest,
	groups []string,
	u *models.User,
	summary *backupRestoreSummary,
) error {
	if containsBackupGroup(groups, groupSettings) {
		doc, err := readSettingsEntry(zr)
		if err != nil {
			return err
		}
		if doc == nil {
			summary.Missing = append(summary.Missing, groupSettings)
		} else {
			if !doc.hasAnySection() {
				return errors.New("backup: settings.json has no recognizable section")
			}
			sections, err := applySettingsDocument(ctx, tx, doc, manifest.SecretsPlaintext)
			if err != nil {
				return err
			}
			summary.Groups = append(summary.Groups, backupGroupResult{Name: groupSettings, Sections: sections})
		}
	}

	// 数据分组：逐表合并（合并语义见 loadTableFromZip），再按请求顺序归组，
	// 让回执顺序与界面上的勾选顺序一致。
	tableResults := map[string][]backupTableResult{}
	for _, t := range backupDataTables {
		if !containsBackupGroup(groups, t.Group) {
			continue
		}
		rc, err := openZipEntry(zr, backupDataPrefix+t.Name+".json")
		if err != nil {
			// 备份文件里没有这张表（导出时未包含，或来自更早的版本）：跳过而不是失败，
			// 让「只恢复系统设置」这类子集恢复不会因为缺表而整体报错。
			summary.Missing = append(summary.Missing, t.Name)
			continue
		}
		res, err := loadTableFromZip(ctx, tx, t, rc, u.ID)
		_ = rc.Close()
		if err != nil {
			return err
		}
		tableResults[t.Group] = append(tableResults[t.Group], res)
	}
	for _, g := range groups {
		if g == groupSettings {
			continue
		}
		if tables, ok := tableResults[g]; ok {
			summary.Groups = append(summary.Groups, backupGroupResult{Name: g, Tables: tables})
		} else {
			summary.Missing = append(summary.Missing, g)
		}
	}
	return nil
}

// buildSettingsSnapshot 汇总当前落库的全部设置（凭据解密后导出）。
//
// 单行配置统一走各自的 load* 方法：缓存命中时拿到副本、缺行时补一行默认值，
// 因此导出结果一定包含全部十个分区（不会因为某张表还没写过而缺段）。
func (h *Handler) buildSettingsSnapshot(ctx context.Context) (*backupDocument, error) {
	doc := &backupDocument{
		Secrets: backupSecrets{
			OAuthProviders: map[string]string{},
			OAuthClients:   map[string]string{},
		},
	}

	doc.Site = h.loadSiteSetting()
	doc.Security = h.loadSecurityPolicy()
	doc.Mail = h.loadMailSetting()
	doc.Captcha = h.loadCaptchaSetting()
	doc.Sms = h.loadSmsSetting()
	doc.Storage = h.loadStorageSetting()
	doc.Location = h.loadLocationSetting()
	doc.Audit = h.loadAuditSetting()
	doc.Cleanup = h.loadDataCleanupSetting()
	doc.Proxy = h.loadProxySetting()

	// 凭据解密导出：换实例恢复时不会因为加密密钥不同而全部失效。
	doc.Secrets.MailPassword = secretpkg.Decrypt(doc.Mail.Password)
	doc.Secrets.CaptchaGeetestKey = secretpkg.Decrypt(doc.Captcha.GeetestCaptchaKey)
	doc.Secrets.CaptchaTurnstileSecret = secretpkg.Decrypt(doc.Captcha.TurnstileSecretKey)
	doc.Secrets.StorageS3SecretKey = secretpkg.Decrypt(doc.Storage.S3SecretKey)
	doc.Secrets.ProxyPassword = secretpkg.Decrypt(doc.Proxy.Password)
	doc.Secrets.Sms = backupSmsSecrets{
		AliyunAccessKeySecret: secretpkg.Decrypt(doc.Sms.AliyunAccessKeySecret),
		TencentSecretKey:      secretpkg.Decrypt(doc.Sms.TencentSecretKey),
		VolcAccessKeySecret:   secretpkg.Decrypt(doc.Sms.VolcAccessKeySecret),
		HuaweiAppSecret:       secretpkg.Decrypt(doc.Sms.HuaweiAppSecret),
		QimoAuthToken:         secretpkg.Decrypt(doc.Sms.QimoAuthToken),
		SubmailAppKey:         secretpkg.Decrypt(doc.Sms.SubmailAppKey),
		CustomSecret:          secretpkg.Decrypt(doc.Sms.CustomSecret),
	}

	// 列表按主键排序，让同一份配置每次导出的字节序稳定（便于人工 diff 与校验和比对）。
	if err := h.db.NewSelect().Model(&doc.OAuthProviders).Order("id ASC").Scan(ctx); err != nil {
		return nil, err
	}
	if err := h.db.NewSelect().Model(&doc.OAuthClients).Order("id ASC").Scan(ctx); err != nil {
		return nil, err
	}
	if err := h.db.NewSelect().Model(&doc.OAuthScopes).Order("name ASC").Scan(ctx); err != nil {
		return nil, err
	}
	for i := range doc.OAuthProviders {
		p := &doc.OAuthProviders[i]
		if p.ClientSecret != "" {
			doc.Secrets.OAuthProviders[p.ID] = secretpkg.Decrypt(p.ClientSecret)
		}
	}
	for i := range doc.OAuthClients {
		c := &doc.OAuthClients[i]
		if c.SecretHash != "" {
			doc.Secrets.OAuthClients[c.ID] = c.SecretHash
		}
	}
	return doc, nil
}

// hasAnySection 判断 settings.json 是否至少包含一个分区的数据。
func (d *backupDocument) hasAnySection() bool {
	return d.Site != nil || d.Security != nil || d.Mail != nil || d.Captcha != nil ||
		d.Sms != nil || d.Storage != nil || d.Location != nil || d.Audit != nil ||
		d.Cleanup != nil || d.Proxy != nil || d.OAuthProviders != nil ||
		d.OAuthClients != nil || d.OAuthScopes != nil
}

// applySettingsDocument 在事务内把设置文档写入数据库，返回恢复到的分区名。
//
// secretsPlaintext 为真时把凭据重新加密落库：导出是明文（为了跨实例可恢复），
// 库内则始终保持密文（见 internal/secret）。
func applySettingsDocument(ctx context.Context, tx bun.Tx, doc *backupDocument, secretsPlaintext bool) ([]string, error) {
	var sections []string
	// encrypt 按需把明文凭据加密：宁可多一次判断，也不要在「明文文件恢复后
	// 库里变成明文」这种静默降级上翻车。
	encrypt := func(v string) string {
		if secretsPlaintext {
			return secretpkg.Encrypt(v)
		}
		return v
	}

	// ---- 单行配置：整行还原（固定主键 id=1）----
	//
	// 每个分区都先显式判空：备份里没有的分区一律不动（部分恢复的语义）。
	// 这里刻意不写成「表驱动 + 统一判空」的循环 —— 分区字段是各类型的指针，
	// 存进 any 后即便指针为空、接口也不为 nil，判空会失效并直接解引用崩溃。
	if doc.Site != nil {
		d := doc.Site
		d.ID, d.UpdatedAt = 1, db.Now()
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "site")
	}
	if doc.Security != nil {
		d := doc.Security
		d.ID, d.UpdatedAt = 1, db.Now()
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "security")
	}
	if doc.Mail != nil {
		d := doc.Mail
		d.ID, d.UpdatedAt = 1, db.Now()
		// 密码从 secrets 段取：模型回显里它是空的，不回填会清掉 SMTP 凭据。
		d.Password = encrypt(doc.Secrets.MailPassword)
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "mail")
	}
	if doc.Captcha != nil {
		d := doc.Captcha
		d.ID, d.UpdatedAt = 1, db.Now()
		d.GeetestCaptchaKey = encrypt(doc.Secrets.CaptchaGeetestKey)
		d.TurnstileSecretKey = encrypt(doc.Secrets.CaptchaTurnstileSecret)
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "captcha")
	}
	if doc.Sms != nil {
		d := doc.Sms
		d.ID, d.UpdatedAt = 1, db.Now()
		d.AliyunAccessKeySecret = encrypt(doc.Secrets.Sms.AliyunAccessKeySecret)
		d.TencentSecretKey = encrypt(doc.Secrets.Sms.TencentSecretKey)
		d.VolcAccessKeySecret = encrypt(doc.Secrets.Sms.VolcAccessKeySecret)
		d.HuaweiAppSecret = encrypt(doc.Secrets.Sms.HuaweiAppSecret)
		d.QimoAuthToken = encrypt(doc.Secrets.Sms.QimoAuthToken)
		d.SubmailAppKey = encrypt(doc.Secrets.Sms.SubmailAppKey)
		d.CustomSecret = encrypt(doc.Secrets.Sms.CustomSecret)
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "sms")
	}
	if doc.Storage != nil {
		d := doc.Storage
		d.ID, d.UpdatedAt = 1, db.Now()
		d.S3SecretKey = encrypt(doc.Secrets.StorageS3SecretKey)
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "storage")
	}
	if doc.Location != nil {
		d := doc.Location
		d.ID, d.UpdatedAt = 1, db.Now()
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "location")
	}
	if doc.Audit != nil {
		d := doc.Audit
		d.ID, d.UpdatedAt = 1, db.Now()
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "audit")
	}
	if doc.Cleanup != nil {
		d := doc.Cleanup
		d.ID, d.UpdatedAt = 1, db.Now()
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "cleanup")
	}
	if doc.Proxy != nil {
		d := doc.Proxy
		d.ID, d.UpdatedAt = 1, db.Now()
		d.Password = encrypt(doc.Secrets.ProxyPassword)
		if err := replaceSingleRow(ctx, tx, d); err != nil {
			return nil, err
		}
		sections = append(sections, "proxy")
	}

	// ---- 登录提供商：整体替换 ----
	if doc.OAuthProviders != nil {
		providers := doc.OAuthProviders
		for i := range providers {
			if providers[i].CreatedAt.IsZero() {
				providers[i].CreatedAt = db.Now()
			}
			providers[i].ClientSecret = encrypt(doc.Secrets.OAuthProviders[providers[i].ID])
		}
		if err := restoreKeyedTable(ctx, tx, providers, "id",
			func(p *models.OAuthProvider) string { return p.ID }); err != nil {
			return nil, err
		}
		sections = append(sections, "oauthProviders")
	}

	// ---- OAuth 应用：整体替换 ----
	if doc.OAuthClients != nil {
		clients := doc.OAuthClients
		for i := range clients {
			if clients[i].CreatedAt.IsZero() {
				clients[i].CreatedAt = db.Now()
			}
			// SecretHash 本身就是不可逆摘要，不参与加解密。
			clients[i].SecretHash = doc.Secrets.OAuthClients[clients[i].ID]
		}
		if err := restoreKeyedTable(ctx, tx, clients, "id",
			func(c *models.OAuthClient) string { return c.ID }); err != nil {
			return nil, err
		}
		sections = append(sections, "oauthClients")
	}

	// ---- OAuth 权限项：只覆盖、不删除 ----
	// 权限项由代码定义（含 openid 这类 Required 的基础项），删除库里多出来的项会让
	// 旧备份把新版本新增的权限项抹掉，进而影响授权流程；因此这里只按 name 覆盖备份
	// 中出现的项（开关状态与文案），其余保持原样。
	if doc.OAuthScopes != nil {
		scopes := doc.OAuthScopes
		for i := range scopes {
			if scopes[i].UpdatedAt.IsZero() {
				scopes[i].UpdatedAt = db.Now()
			}
		}
		if err := upsertKeyedTable(ctx, tx, scopes, "name",
			func(s *models.OAuthScope) string { return s.Name }); err != nil {
			return nil, err
		}
		sections = append(sections, "oauthScopes")
	}
	return sections, nil
}

// replaceSingleRow 整行替换单行配置表（固定主键 id=1）。
//
// 用「先删后插」而不是 UPDATE：恢复的语义是整行还原，而 bun 的 UPDATE 会跳过
// 零值字段（空串 / false / 0），备份里被清空的配置（例如关掉 SMTP、清空 Logo）
// 会原封不动留在库里，恢复结果与备份不一致。单行配置表不被任何表外键引用，
// 重建一行的代价可以忽略。
func replaceSingleRow[T any](ctx context.Context, tx bun.Tx, row *T) error {
	if _, err := tx.NewDelete().Model(row).Where("id = 1").Exec(ctx); err != nil {
		return err
	}
	_, err := tx.NewInsert().Model(row).Exec(ctx)
	return err
}

// restoreKeyedTable 用备份快照整体替换一张字符串主键的配置表：
//   - 备份中存在的主键：整行还原（先删后插，零值字段同样被还原）；
//   - 备份中不存在的主键：删除（恢复 = 回到备份时的那份配置）。
//
// 之所以要删：只做 upsert 会留下备份之后新建的提供商/应用，结果既不是备份状态、
// 也不是当前状态。这两张表不被用户数据外键引用（identities / grants 只按 ID
// 字符串关联），删除不会连带影响用户自己的绑定与授权记录。
func restoreKeyedTable[T any](
	ctx context.Context,
	tx bun.Tx,
	rows []T,
	idColumn string,
	idOf func(*T) string,
) error {
	ids := make([]string, 0, len(rows))
	for i := range rows {
		if id := idOf(&rows[i]); id != "" {
			ids = append(ids, id)
		}
	}
	// 备份里带 id 的行为空时（理论上不会出现）视为「整表清空」。
	del := tx.NewDelete().Model(new(T))
	if len(ids) > 0 {
		del = del.Where(idColumn+" NOT IN (?)", bun.In(ids))
	}
	if _, err := del.Exec(ctx); err != nil {
		return err
	}
	return upsertKeyedTable(ctx, tx, rows, idColumn, idOf)
}

// upsertKeyedTable 按主键逐行覆盖（先删后插）。
func upsertKeyedTable[T any](
	ctx context.Context,
	tx bun.Tx,
	rows []T,
	idColumn string,
	idOf func(*T) string,
) error {
	for i := range rows {
		row := &rows[i]
		id := idOf(row)
		if id == "" {
			continue
		}
		if _, err := tx.NewDelete().Model(new(T)).Where(idColumn+" = ?", id).Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ---- ZIP 与分组辅助 ----

// parseBackupGroups 解析 groups 查询参数（逗号分隔）。
//
// 缺省与空值都退化为「仅系统设置」：业务数据（用户、会话、事件）体积大且敏感，
// 必须由管理员显式选择，绝不能因为漏传参数而默认带走。
func parseBackupGroups(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		g := strings.TrimSpace(part)
		if g == "" {
			continue
		}
		if !isBackupGroup(g) {
			return nil, fmt.Errorf("未知的备份分组：%s", g)
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return []string{groupSettings}, nil
	}
	return out, nil
}

// isBackupGroup 判定分组标识是否受支持。
func isBackupGroup(g string) bool {
	switch g {
	case groupSettings, groupUsers, groupSessions, groupEvents, groupOAuth:
		return true
	}
	return false
}

func containsBackupGroup(groups []string, g string) bool {
	for _, v := range groups {
		if v == g {
			return true
		}
	}
	return false
}

// orderBackupGroups 按 backupGroupOrder 整理分组清单，保证顺序稳定。
func orderBackupGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range backupGroupOrder {
		if containsBackupGroup(groups, g) {
			out = append(out, g)
		}
	}
	return out
}

// writeZipJSON 把一个对象写成 ZIP 条目（带缩进，便于人工查看与比对）。
func writeZipJSON(zw *zip.Writer, name string, v any) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// openZipEntry 按名字打开条目；不存在时返回 os.ErrNotExist。
func openZipEntry(zr *zip.Reader, name string) (io.ReadCloser, error) {
	for _, f := range zr.File {
		if f.Name == name {
			return f.Open()
		}
	}
	return nil, os.ErrNotExist
}

// readBackupManifest 读取并解析 manifest.json。
func readBackupManifest(zr *zip.Reader) (*backupManifest, error) {
	rc, err := openZipEntry(zr, backupManifestEntry)
	if err != nil {
		return nil, errors.New("压缩包内缺少 manifest.json，不是本系统导出的备份")
	}
	defer func() { _ = rc.Close() }()
	var m backupManifest
	if err := json.NewDecoder(rc).Decode(&m); err != nil {
		return nil, errors.New("manifest.json 解析失败：" + err.Error())
	}
	return &m, nil
}

// readSettingsEntry 读取 settings.json；不存在时返回 (nil, nil)。
func readSettingsEntry(zr *zip.Reader) (*backupDocument, error) {
	rc, err := openZipEntry(zr, backupSettingsEntry)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = rc.Close() }()
	var doc backupDocument
	if err := json.NewDecoder(rc).Decode(&doc); err != nil {
		return nil, errors.New("settings.json 解析失败：" + err.Error())
	}
	return &doc, nil
}
