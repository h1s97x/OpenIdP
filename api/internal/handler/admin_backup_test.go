package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	secretpkg "github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
)

// doBackupExport 发起一次导出请求（响应体是 ZIP 二进制，不套 JSON 信封）。
func doBackupExport(t *testing.T, router http.Handler, h *Handler, sessID, groups string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/v1/admin/backup/export"
	if groups != "" {
		path += "?groups=" + groups
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if sessID != "" {
		req.AddCookie(&http.Cookie{Name: h.cfg.SessionCookieName, Value: sessID})
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// doBackupRestore 以管理员身份上传 ZIP 备份执行恢复。
func doBackupRestore(t *testing.T, router http.Handler, h *Handler, sessID, csrf, groups string, archive []byte) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/v1/admin/backup/restore"
	if groups != "" {
		path += "?groups=" + url.QueryEscape(groups)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(archive))
	req.Header.Set("Content-Type", "application/zip")
	if csrf != "" {
		req.Header.Set(h.cfg.CSRFHeader, csrf)
	}
	if sessID != "" {
		req.AddCookie(&http.Cookie{Name: h.cfg.SessionCookieName, Value: sessID})
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// doBackupInspect 上传备份 ZIP 做内容解析。
func doBackupInspect(t *testing.T, router http.Handler, h *Handler, sessID, csrf string, archive []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/backup/inspect", bytes.NewReader(archive))
	req.Header.Set("Content-Type", "application/zip")
	if csrf != "" {
		req.Header.Set(h.cfg.CSRFHeader, csrf)
	}
	if sessID != "" {
		req.AddCookie(&http.Cookie{Name: h.cfg.SessionCookieName, Value: sessID})
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// unzipBackup 把导出的 ZIP 展开成「条目名 → 内容」。
func unzipBackup(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse exported zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry %s: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read zip entry %s: %v", f.Name, err)
		}
		out[f.Name] = body
	}
	return out
}

// decodeRestoreSummary 解出恢复回执（JSON 信封内的 data）。失败即终止用例。
func decodeRestoreSummary(t *testing.T, rec *httptest.ResponseRecorder) backupRestoreSummary {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("restore = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data backupRestoreSummary `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode restore summary: %v", err)
	}
	return envelope.Data
}

// tableResultOf 从回执里取某个分组中某张表的行数统计。
func tableResultOf(t *testing.T, summary backupRestoreSummary, group, table string) backupTableResult {
	t.Helper()
	for _, g := range summary.Groups {
		if g.Name != group {
			continue
		}
		for _, tb := range g.Tables {
			if tb.Table == table {
				return tb
			}
		}
	}
	t.Fatalf("restore summary has no table %s in group %s: %+v", table, group, summary.Groups)
	return backupTableResult{}
}

// TestAdminBackupForbiddenForNonAdmin 备份的导出与恢复都必须仅管理员可用。
func TestAdminBackupForbiddenForNonAdmin(t *testing.T) {
	h, router := newTestHandler(t)
	u := createTestUser(t, h.db, "plainuser", "Str0ngPassw0rd!")
	sessID := auth.NewID()
	insertSession(t, h.db, u.ID, sessID)
	csrf := auth.RandomToken(32)
	h.tokens.Set(csrf, u.ID, sessID)

	if rec := doBackupExport(t, router, h, sessID, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin export = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := doBackupRestore(t, router, h, sessID, csrf, "", []byte("PK\x03\x04")); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin restore = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	// 未登录同样拒绝（requireAdmin 内部先解析会话）。
	if rec := doBackupExport(t, router, h, "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous export = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestAdminBackupSettingsRoundTrip 覆盖设置的「导出 → 改坏 → 恢复」：
//   - 导出的是 ZIP，settings.json 里的凭据为**明文**（否则换实例恢复解不开）；
//   - 恢复后设置回到备份状态，库内凭据重新变成密文；
//   - 当前登录的管理员账号与会话不受影响。
func TestAdminBackupSettingsRoundTrip(t *testing.T) {
	h, router := newTestHandler(t)
	ctx := context.Background()
	// 打开真实加密链路：验证「明文导出、密文落库」这个往返。
	if err := secretpkg.Init("", filepath.Join(h.cfg.DataDir, "encryption.key")); err != nil {
		t.Fatalf("init secret: %v", err)
	}
	admin := createTestUser(t, h.db, "backupadmin", "Str0ngPassw0rd!")
	sessID, csrf := newAdminSession(t, h, admin)

	// mustExec 收敛写库语句的错误处理：参数 (sql.Result, error) 恰好对应 Exec 的
	// 两个返回值，因此可以写成 mustExec(...Exec(ctx))；若给 mustExec 再加参数，
	// 「多返回值不能与其它实参混用」的规则会让这个写法直接编译失败。
	mustExec := func(_ sql.Result, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
	}

	// ---- 1) 造一份非默认配置 ----
	h.loadSiteSetting()
	h.loadMailSetting()
	h.loadCaptchaSetting()

	const siteName = "OpenIdP"
	const mailPlain = "smtp-pass-original"
	const captchaPlain = "turnstile-secret-original"
	mailCipher := secretpkg.Encrypt(mailPlain)
	captchaCipher := secretpkg.Encrypt(captchaPlain)
	mustExec(h.db.NewUpdate().Model((*models.SiteSetting)(nil)).
		Set("display_name = ?", siteName).
		Set("logo_url = ?", "/images/logo.svg").
		Where("id = 1").Exec(ctx))
	mustExec(h.db.NewUpdate().Model((*models.MailSetting)(nil)).
		Set("enabled = ?", true).
		Set("host = ?", "smtp.example.com").
		Set("port = ?", 465).
		Set("user = ?", "noreply@example.com").
		Set("password = ?", mailCipher).
		Where("id = 1").Exec(ctx))
	mustExec(h.db.NewUpdate().Model((*models.CaptchaSetting)(nil)).
		Set("provider = ?", "turnstile").
		Set("turnstile_site_key = ?", "site-key-1").
		Set("turnstile_secret_key = ?", captchaCipher).
		Set("required_for_login = ?", true).
		Where("id = 1").Exec(ctx))
	mustExec(h.db.NewInsert().Model(&models.OAuthProvider{
		ID: "custom_backup", Name: "backup-provider", DisplayName: "备份提供商",
		ProviderType: "custom", Enabled: true, Custom: true,
		AuthorizeURL: "https://example.com/authorize", TokenURL: "https://example.com/token",
		UserInfoURL: "https://example.com/userinfo",
		ClientID:    "client-1", ClientSecret: secretpkg.Encrypt("provider-secret-1"),
	}).Exec(ctx))
	mustExec(h.db.NewInsert().Model(&models.OAuthScope{
		Name: "custom.scope", DisplayName: "自定义权限", Description: "备份前写入", Enabled: true,
	}).Exec(ctx))
	h.conf.invalidate()

	// ---- 2) 导出（默认分组 = 仅系统设置）----
	rec := doBackupExport(t, router, h, sessID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("export content-type = %q, want application/zip", ct)
	}
	archive := rec.Body.Bytes()
	entries := unzipBackup(t, archive)
	if _, ok := entries[backupSettingsEntry]; !ok {
		t.Fatalf("export entry %s is missing (entries=%v)", backupSettingsEntry, keysOf(entries))
	}
	if _, ok := entries[backupDataPrefix+"users.json"]; ok {
		t.Fatal("default export must not include user data")
	}
	manifestRaw := entries[backupManifestEntry]
	if len(manifestRaw) == 0 {
		t.Fatalf("export entry %s is missing", backupManifestEntry)
	}
	var manifest backupManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.Format != backupFormat || manifest.Version != backupVersion {
		t.Fatalf("manifest = %+v, want %s v%d", manifest, backupFormat, backupVersion)
	}
	if !manifest.SecretsPlaintext {
		t.Fatal("manifest must declare secretsPlaintext")
	}
	if manifest.ExportedBy != admin.Username {
		t.Fatalf("manifest exportedBy = %q, want %q", manifest.ExportedBy, admin.Username)
	}

	var doc backupDocument
	if err := json.Unmarshal(entries[backupSettingsEntry], &doc); err != nil {
		t.Fatalf("decode settings entry: %v", err)
	}
	if doc.Site == nil || doc.Site.DisplayName != siteName {
		t.Fatalf("exported site = %+v, want displayName %q", doc.Site, siteName)
	}
	if doc.Mail == nil || doc.Mail.Host != "smtp.example.com" || doc.Mail.Port != 465 {
		t.Fatalf("exported mail = %+v, want smtp.example.com:465", doc.Mail)
	}
	// 导出必须是明文凭据：密文导出换实例就解不开了。
	if doc.Secrets.MailPassword != mailPlain {
		t.Fatalf("exported mail secret = %q, want plaintext %q", doc.Secrets.MailPassword, mailPlain)
	}
	if doc.Secrets.CaptchaTurnstileSecret != captchaPlain {
		t.Fatalf("exported captcha secret = %q, want plaintext %q", doc.Secrets.CaptchaTurnstileSecret, captchaPlain)
	}
	if doc.Secrets.OAuthProviders["custom_backup"] != "provider-secret-1" {
		t.Fatalf("exported provider secret = %q, want plaintext", doc.Secrets.OAuthProviders["custom_backup"])
	}

	// ---- 3) 把配置改坏 ----
	mustExec(h.db.NewUpdate().Model((*models.SiteSetting)(nil)).
		Set("display_name = ?", "被改坏的站点名").
		Set("logo_url = ?", "").
		Where("id = 1").Exec(ctx))
	mustExec(h.db.NewUpdate().Model((*models.MailSetting)(nil)).
		Set("enabled = ?", false).
		Set("host = ?", "wrong.example.com").
		Set("password = ?", secretpkg.Encrypt("smtp-pass-broken")).
		Where("id = 1").Exec(ctx))
	mustExec(h.db.NewInsert().Model(&models.OAuthProvider{
		ID: "custom_after_backup", Name: "later", DisplayName: "备份之后新增",
		ProviderType: "custom", Custom: true,
	}).Exec(ctx))
	h.conf.invalidate()

	// ---- 4) 用导出的 ZIP 恢复 ----
	summary := decodeRestoreSummary(t, doBackupRestore(t, router, h, sessID, csrf, groupSettings, archive))
	if summary.CurrentUser.ID != admin.ID || summary.CurrentUser.Username != admin.Username {
		t.Fatalf("restore receipt must report the untouched current user, got %+v", summary.CurrentUser)
	}
	var sections []string
	for _, g := range summary.Groups {
		if g.Name == groupSettings {
			sections = g.Sections
		}
	}
	if len(sections) == 0 || !strings.Contains(strings.Join(sections, ","), "site") {
		t.Fatalf("restore summary sections = %v, want site among them", sections)
	}

	// ---- 5) 校验设置回到备份状态 ----
	site := h.loadSiteSetting()
	if site.DisplayName != siteName || site.LogoURL != "/images/logo.svg" {
		t.Fatalf("site after restore = %+v, want displayName %q with restored logo", site, siteName)
	}
	mail := h.loadMailSetting()
	if !mail.Enabled || mail.Host != "smtp.example.com" || mail.Port != 465 {
		t.Fatalf("mail after restore = %+v, want enabled smtp.example.com:465", mail)
	}
	// 库内必须是密文：明文备份恢复后不能把凭据以明文留在库里。
	if !strings.HasPrefix(mail.Password, "enc:v1:") {
		t.Fatalf("mail password after restore = %q, want ciphertext", mail.Password)
	}
	if got := secretpkg.Decrypt(mail.Password); got != mailPlain {
		t.Fatalf("mail password after restore = %q, want %q", got, mailPlain)
	}
	captcha := h.loadCaptchaSetting()
	if captcha.Provider != "turnstile" || captcha.TurnstileSiteKey != "site-key-1" || !captcha.RequiredForLogin {
		t.Fatalf("captcha after restore = %+v, want turnstile with site-key-1 required", captcha)
	}
	if got := secretpkg.Decrypt(captcha.TurnstileSecretKey); got != captchaPlain {
		t.Fatalf("captcha secret after restore = %q, want %q", got, captchaPlain)
	}
	// 运行时组件随恢复立即重建（否则要等下一次保存才生效）。
	if ts := h.turnstileCfg(); !ts.Enabled || ts.SiteKey != "site-key-1" {
		t.Fatalf("runtime turnstile = %+v, want enabled with site-key-1", ts)
	}

	// 提供商整体替换：快照里的还原、快照之后新增的被清掉。
	var provider models.OAuthProvider
	if err := h.db.NewSelect().Model(&provider).Where("id = ?", "custom_backup").Scan(ctx); err != nil {
		t.Fatalf("restored provider missing: %v", err)
	}
	if got := secretpkg.Decrypt(provider.ClientSecret); got != "provider-secret-1" {
		t.Fatalf("restored provider secret = %q, want plaintext restored and re-encrypted", got)
	}
	if n, err := h.db.NewSelect().Model((*models.OAuthProvider)(nil)).
		Where("id = ?", "custom_after_backup").Count(ctx); err != nil || n != 0 {
		t.Fatalf("provider added after the backup must be removed, count=%d err=%v", n, err)
	}

	// ---- 6) 当前用户与会话未被触碰 ----
	fresh := new(models.User)
	if err := h.db.NewSelect().Model(fresh).Where("id = ?", admin.ID).Scan(ctx); err != nil {
		t.Fatalf("current user must survive the restore: %v", err)
	}
	if fresh.Username != admin.Username || !fresh.IsAdmin {
		t.Fatalf("current user after restore = %+v, want unchanged admin", fresh)
	}
	session := httptest.NewRecorder()
	sessionReq := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	sessionReq.AddCookie(&http.Cookie{Name: h.cfg.SessionCookieName, Value: sessID})
	router.ServeHTTP(session, sessionReq)
	if session.Code != http.StatusOK {
		t.Fatalf("admin session must stay valid after restore, got %d (body=%s)", session.Code, session.Body.String())
	}
}

// TestAdminBackupDataGroupsRoundTrip 覆盖业务数据分组：
//   - 勾选后用户 / 会话 / 事件都会进 ZIP（含被 json:"-" 隐藏的字段）；
//   - 恢复是「合并」：备份里的行写入、库里多出来的行保留；
//   - 属于当前登录管理员的行被跳过，执行者不会被自己的旧备份覆盖。
func TestAdminBackupDataGroupsRoundTrip(t *testing.T) {
	h, router := newTestHandler(t)
	ctx := context.Background()
	if err := secretpkg.Init("", filepath.Join(h.cfg.DataDir, "encryption.key")); err != nil {
		t.Fatalf("init secret: %v", err)
	}
	admin := createTestUser(t, h.db, "dataadmin", "Str0ngPassw0rd!")
	sessID, csrf := newAdminSession(t, h, admin)

	// 被备份的普通用户 + 其事件；另有一条属于管理员自己的事件（恢复时应被跳过）。
	other := createTestUser(t, h.db, "otheruser", "Str0ngPassw0rd!")
	execMust := func(_ sql.Result, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
	}
	execMust(h.db.NewInsert().Model(&models.Event{
		UserID: other.ID, Type: "login.success", Summary: "普通用户登录",
	}).Exec(ctx))
	execMust(h.db.NewInsert().Model(&models.Event{
		UserID: admin.ID, Type: "login.success", Summary: "管理员登录",
	}).Exec(ctx))
	h.conf.invalidate()

	// ---- 1) 全量导出 ----
	allGroups := groupSettings + "," + groupUsers + "," + groupSessions + "," + groupEvents
	rec := doBackupExport(t, router, h, sessID, allGroups)
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	archive := rec.Body.Bytes()
	entries := unzipBackup(t, archive)

	var manifest backupManifest
	if err := json.Unmarshal(entries[backupManifestEntry], &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.Counts["users"] < 2 {
		t.Fatalf("manifest counts = %+v, want at least 2 users", manifest.Counts)
	}

	// 用户导出必须带上 password_hash —— 这正是「按列原样搬运」要解决的核心问题：
	// 模型序列化会因 json:"-" 静默丢掉它，恢复后没人能登录。
	usersEntry := entries[backupDataPrefix+"users.json"]
	if len(usersEntry) == 0 {
		t.Fatal("data/users.json is missing")
	}
	if !bytes.Contains(usersEntry, []byte("password_hash")) {
		t.Fatal("users entry must contain password_hash column")
	}
	eventsEntry := entries[backupDataPrefix+"events.json"]
	if len(eventsEntry) == 0 || !bytes.Contains(eventsEntry, []byte("普通用户登录")) {
		t.Fatalf("events entry = %s, want the exported security event", eventsEntry)
	}

	// ---- 2) 改坏数据：改名、删事件、新增一个备份里没有的用户 ----
	execMust(h.db.NewUpdate().Model((*models.User)(nil)).
		Set("display_name = ?", "被改坏的名字").Where("id = ?", other.ID).Exec(ctx))
	execMust(h.db.NewDelete().Model((*models.Event)(nil)).
		Where("user_id = ?", other.ID).Exec(ctx))
	extra := createTestUser(t, h.db, "extrauser", "Str0ngPassw0rd!")

	// ---- 3) 只恢复数据分组 ----
	dataGroups := groupUsers + "," + groupEvents
	summary := decodeRestoreSummary(t, doBackupRestore(t, router, h, sessID, csrf, dataGroups, archive))

	userTable := tableResultOf(t, summary, groupUsers, "users")
	if userTable.Updated == 0 && userTable.Inserted == 0 {
		t.Fatalf("users table result = %+v, want rows written back", userTable)
	}
	// 管理员自己的那行被跳过（users 表按主键 id 归属用户）。
	if userTable.Skipped == 0 {
		t.Fatalf("current admin row must be skipped, got %+v", userTable)
	}
	eventTable := tableResultOf(t, summary, groupEvents, "events")
	if eventTable.Inserted == 0 {
		t.Fatalf("events table result = %+v, want the deleted event restored", eventTable)
	}
	if eventTable.Skipped == 0 {
		t.Fatalf("current admin event must be skipped, got %+v", eventTable)
	}

	// ---- 4) 校验 ----
	reloaded := new(models.User)
	if err := h.db.NewSelect().Model(reloaded).Where("id = ?", other.ID).Scan(ctx); err != nil {
		t.Fatalf("reload other user: %v", err)
	}
	if reloaded.DisplayName != "otheruser" {
		t.Fatalf("other user displayName = %q, want the backed-up value", reloaded.DisplayName)
	}
	if reloaded.PasswordHash == "" {
		t.Fatal("password hash must survive the round trip")
	}
	if n, err := h.db.NewSelect().Model((*models.Event)(nil)).
		Where("user_id = ?", other.ID).Count(ctx); err != nil || n != 1 {
		t.Fatalf("other user's event must be restored, count=%d err=%v", n, err)
	}
	// 当前管理员不参与恢复：改名结果保持不变，事件也不会被覆盖。
	adminFresh := new(models.User)
	if err := h.db.NewSelect().Model(adminFresh).Where("id = ?", admin.ID).Scan(ctx); err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if adminFresh.DisplayName != admin.DisplayName {
		t.Fatalf("admin displayName = %q, want untouched %q", adminFresh.DisplayName, admin.DisplayName)
	}
	// 合并语义：备份之后新增的用户保留，不被这份备份抹掉。
	if n, err := h.db.NewSelect().Model((*models.User)(nil)).
		Where("id = ?", extra.ID).Count(ctx); err != nil || n != 1 {
		t.Fatalf("user created after the backup must survive, count=%d err=%v", n, err)
	}
}

// TestAdminBackupInspect 上传解析只回报归档里**实际存在**的分组与表：
// 恢复界面据此渲染勾选项，不能凭空多出文件里没有的内容。
func TestAdminBackupInspect(t *testing.T) {
	h, router := newTestHandler(t)
	admin := createTestUser(t, h.db, "inspectadmin", "Str0ngPassw0rd!")
	sessID, csrf := newAdminSession(t, h, admin)

	// 仅设置：解析结果只应包含 settings，不出现任何数据分组。
	rec := doBackupExport(t, router, h, sessID, groupSettings)
	if rec.Code != http.StatusOK {
		t.Fatalf("export settings = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	insp := doBackupInspect(t, router, h, sessID, csrf, rec.Body.Bytes())
	if insp.Code != http.StatusOK {
		t.Fatalf("inspect = %d, want 200 (body=%s)", insp.Code, insp.Body.String())
	}
	var envelope struct {
		Data backupInspectResult `json:"data"`
	}
	if err := json.Unmarshal(insp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode inspect result: %v", err)
	}
	if len(envelope.Data.Groups) != 1 || envelope.Data.Groups[0].Name != groupSettings {
		t.Fatalf("inspect groups = %+v, want only %s", envelope.Data.Groups, groupSettings)
	}
	if envelope.Data.ExportedBy != admin.Username {
		t.Fatalf("inspect exportedBy = %q, want %q", envelope.Data.ExportedBy, admin.Username)
	}

	// 含业务数据：分组按固定顺序返回，且列出各分组在文件里的表。
	rec = doBackupExport(t, router, h, sessID, groupUsers+","+groupEvents)
	if rec.Code != http.StatusOK {
		t.Fatalf("export data = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if insp = doBackupInspect(t, router, h, sessID, csrf, rec.Body.Bytes()); insp.Code != http.StatusOK {
		t.Fatalf("inspect data = %d, want 200 (body=%s)", insp.Code, insp.Body.String())
	}
	if err := json.Unmarshal(insp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode inspect result: %v", err)
	}
	if len(envelope.Data.Groups) != 2 ||
		envelope.Data.Groups[0].Name != groupUsers || envelope.Data.Groups[1].Name != groupEvents {
		t.Fatalf("inspect groups = %+v, want users then events", envelope.Data.Groups)
	}
	if names := envelope.Data.Groups[0].Tables; len(names) == 0 || !containsBackupGroup(names, "users") {
		t.Fatalf("inspect users tables = %v, want the users table listed", names)
	}

	// 解析同样只对管理员开放。
	if rec := doBackupInspect(t, router, h, "", "", rec.Body.Bytes()); rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous inspect = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestAdminBackupRestoreRejectsInvalidInput 备份文件与分组参数的校验。
func TestAdminBackupRestoreRejectsInvalidInput(t *testing.T) {
	h, router := newTestHandler(t)
	admin := createTestUser(t, h.db, "badbackup", "Str0ngPassw0rd!")
	sessID, csrf := newAdminSession(t, h, admin)

	// 未知分组：导出与恢复都直接拒绝，避免静默忽略拼错的分组名。
	if rec := doBackupExport(t, router, h, sessID, "settings,secret_stuff"); rec.Code != http.StatusBadRequest {
		t.Fatalf("export with unknown group = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// files（文件记录）已不再属于备份范围：请求它必须被拒绝，而不是静默返回空分组。
	if rec := doBackupExport(t, router, h, sessID, "files"); rec.Code != http.StatusBadRequest {
		t.Fatalf("export with files group = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := doBackupRestore(t, router, h, sessID, csrf, "secret_stuff", []byte("PK\x03\x04")); rec.Code != http.StatusBadRequest {
		t.Fatalf("restore with unknown group = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// 不是 ZIP。
	if rec := doBackupRestore(t, router, h, sessID, csrf, groupSettings, []byte("not a zip")); rec.Code != http.StatusBadRequest {
		t.Fatalf("restore with garbage body = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// 合法 ZIP 但不是备份（缺 manifest.json）。
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if _, err := zw.Create("readme.txt"); err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if rec := doBackupRestore(t, router, h, sessID, csrf, groupSettings, buf.Bytes()); rec.Code != http.StatusBadRequest {
		t.Fatalf("restore without manifest = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// 版本不支持。
	if rec := doBackupRestore(t, router, h, sessID, csrf, groupSettings,
		buildBackupZip(t, backupManifest{Format: backupFormat, Version: backupVersion + 1}, nil)); rec.Code != http.StatusBadRequest {
		t.Fatalf("restore with newer version = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// 格式标识不对。
	if rec := doBackupRestore(t, router, h, sessID, csrf, groupSettings,
		buildBackupZip(t, backupManifest{Format: "other.backup", Version: backupVersion}, nil)); rec.Code != http.StatusBadRequest {
		t.Fatalf("restore with wrong format = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// buildBackupZip 按给定 manifest（与可选附加条目）拼一个最小备份 ZIP。
func buildBackupZip(t *testing.T, manifest backupManifest, extra map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(backupManifestEntry)
	if err != nil {
		t.Fatalf("create manifest entry: %v", err)
	}
	if err := json.NewEncoder(w).Encode(manifest); err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	for name, v := range extra {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create entry %s: %v", name, err)
		}
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Fatalf("encode entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
