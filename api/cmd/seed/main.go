// seeddemo 向本地开发数据库写入「可重复执行」的演示数据，用于验证前端各页面。
//
// 用途与边界：
//   - 确保管理员账号存在（可用 -username / -password 指定，未指定则随机生成密码并打印）；
//     已存在同名账号时默认不改动其密码，需显式追加 -force 才会覆盖；
//   - 为该账号写入演示用的 OAuth 应用、授权、会话、设备、事件与站内通知，
//     让「我的授权 / 设备会话 / 安全事件 / 通知中心 / 管理后台」都有内容可看；
//   - **幂等**：演示数据一律带固定 ID 或 [示例] 前缀，重复执行只重建这些行，
//     不会触碰库里其它真实数据（不清空账号、不删除非演示记录）。
//
// 用法（在 api/ 目录下执行）：
//
//	go run ./cmd/seed            # 只列出当前库中的用户与数据概览
//	go run ./cmd/seed -apply     # 写入 / 刷新演示数据
//
// 环境变量与 cmd/server 一致（DATABASE_URL / DATA_DIR / OPENIDP_TIMEZONE）。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/config"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// demoPrefix 是演示事件 Summary / 通知标题的前缀：清理时据此精确删除，
// 避免按 user_id 整表清空误伤真实数据。
const demoPrefix = "[示例] "

const (
	demoUserUsername = "demo-user"
	demoUserEmail    = "demo@openidp.local"
	demoUserPassword = "demo-user-pass-2026"
)

// demoClient 描述一个演示 OAuth 应用及其授权/令牌的时间分布。
type demoClient struct {
	ID            string
	Name          string
	Description   string
	Homepage      string
	Logo          string
	Scopes        []string
	GrantDaysAgo  int // 授权时间（距今天数）
	TokenHoursAgo int // 最近一次令牌签发时间（距今小时数），0 表示不写入令牌
}

var demoClients = []demoClient{
	{
		ID: "demo-app-portal", Name: "OpenIdP 控制台", Description: "站点控制台自身的登录与资料读取。",
		Homepage: "https://openidp.example.com", Logo: "/images/logo.svg",
		Scopes: []string{"openid", "profile"}, GrantDaysAgo: 21, TokenHoursAgo: 3,
	},
	{
		ID: "demo-app-image", Name: "OpenIdP图床", Description: "图床服务的免密登录与邮箱读取。",
		Homepage: "https://img.example.com",
		Scopes:   []string{"openid", "profile", "email", "offline_access"}, GrantDaysAgo: 9, TokenHoursAgo: 30,
	},
	{
		ID: "demo-app-drive", Name: "OpenIdP网盘", Description: "网盘的长期授权（含离线刷新与联系方式读取）。",
		Homepage:     "https://drive.example.com",
		Scopes:       []string{"openid", "profile", "email", "phone", "offline_access"},
		GrantDaysAgo: 3, TokenHoursAgo: 90,
	},
}

// 演示会话：固定 ID 前缀 demo-sess-，覆盖「有效 / 历史」与会话页的四个页签。
type demoSession struct {
	ID         string
	DeviceID   string
	UserAgent  string
	IP         string
	Region     string
	HoursAgo   int // 最近活动时间
	TTLHours   int // 会话有效期（负值 = 已过期，用于历史会话）
	DeviceName string
}

var demoWindowsUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
var demoIPhoneUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
var demoMacUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

var demoSessions = []demoSession{
	{ID: "demo-sess-win", DeviceID: "demo-dev-win", UserAgent: demoWindowsUA, IP: "119.123.45.67", Region: "中国 · 广东省 · 深圳市 · 电信", HoursAgo: 0, TTLHours: 336, DeviceName: "Windows 设备"},
	{ID: "demo-sess-iphone", DeviceID: "demo-dev-iphone", UserAgent: demoIPhoneUA, IP: "223.104.38.21", Region: "中国 · 甘肃省 · 兰州市 · 移动", HoursAgo: 26, TTLHours: 336, DeviceName: "移动设备"},
	{ID: "demo-sess-mac", DeviceID: "demo-dev-mac", UserAgent: demoMacUA, IP: "61.178.12.90", Region: "中国 · 甘肃省 · 兰州市 · 联通", HoursAgo: 74, TTLHours: 336, DeviceName: "Mac"},
	{ID: "demo-sess-old", DeviceID: "demo-dev-win", UserAgent: demoWindowsUA, IP: "119.123.45.67", Region: "中国 · 广东省 · 深圳市 · 电信", HoursAgo: 22 * 24, TTLHours: -1, DeviceName: "Windows 设备"},
}

func main() {
	apply := flag.Bool("apply", false, "写入/刷新演示数据（缺省只输出概览，不做任何写操作）")
	force := flag.Bool("force", false, "允许覆盖已存在账号的密码（默认不动已存在账号的凭据）")
	username := flag.String("username", "h1s97x", "演示管理员用户名")
	password := flag.String("password", "", "演示管理员密码（留空则随机生成并打印）")
	email := flag.String("email", "admin@openidp.local", "演示管理员邮箱")
	flag.Parse()

	cfg := config.FromEnv()
	if _, err := timezone.Apply(cfg.Timezone); err != nil {
		log.Fatalf("❌ [Timezone] %v", err)
	}
	ctx := context.Background()
	opened, err := db.Open(cfg.DatabaseURL, cfg.DataDir, cfg.DBFallback)
	if err != nil {
		log.Fatalf("❌ [DB] %v", err)
	}
	defer opened.DB.Close()
	if err := db.Migrate(ctx, opened.DB); err != nil {
		log.Fatalf("❌ [DB] 建表失败: %v", err)
	}
	log.Printf("✅ [DB] 已连接 %s（%s）", opened.Kind, cfg.DataDir)

	s := &seeder{db: opened.DB, ctx: ctx}
	s.report()
	if !*apply {
		log.Printf("ℹ️  仅概览模式：写入演示数据请追加 -apply")
		return
	}
	pwd := strings.TrimSpace(*password)
	generated := false
	if pwd == "" {
		pwd = auth.RandomToken(16)
		generated = true
	}
	credApplied := s.apply(strings.TrimSpace(*username), pwd, strings.TrimSpace(*email), *force)
	if generated && credApplied {
		log.Printf("ℹ️  未指定 -password：本次随机生成的密码仅在上方「管理员」行输出，请自行保存")
	}
}

type seeder struct {
	db  *bun.DB
	ctx context.Context
}

func (s *seeder) report() {
	var users []models.User
	if err := s.db.NewSelect().Model(&users).Order("id ASC").Scan(s.ctx); err != nil {
		log.Printf("⚠️  读取用户失败: %v", err)
		return
	}
	log.Printf("👥 现有用户 %d 个：", len(users))
	for _, u := range users {
		role := "用户"
		if u.IsAdmin {
			role = "管理员"
		}
		log.Printf("   - #%d %s（%s）%s", u.ID, u.Username, u.Email, role)
	}
	for _, m := range []any{
		(*models.OAuthClient)(nil), (*models.Grant)(nil), (*models.Session)(nil),
		(*models.Device)(nil), (*models.Notification)(nil), (*models.Event)(nil),
	} {
		n, err := s.db.NewSelect().Model(m).Count(s.ctx)
		if err != nil {
			continue
		}
		log.Printf("   · %-16s %d 行", tableName(m), n)
	}
}

// apply 写入演示数据；返回值表示管理员密码是否在本次执行中被写入（新账号或 -force）。
func (s *seeder) apply(username, password, email string, force bool) bool {
	if username == "" || password == "" {
		log.Fatalf("❌ 用户名与密码不能为空")
	}
	now := db.Now()

	// 1) 管理员账号（已存在时默认保留其既有凭据，仅在 -force 下同步密码与管理员位）。
	admin, err := s.ensureUser(username, email, "OpenIdP", password, true, now, force)
	if err != nil {
		log.Fatalf("❌ 写入管理员账号失败: %v", err)
	}
	if admin.existing {
		if force {
			log.Printf("✅ 管理员已就绪：#%d %s（-force：密码已重置）", admin.user.ID, admin.user.Username)
		} else {
			log.Printf("✅ 管理员已存在：#%d %s（保留原密码，如需重置请追加 -force）", admin.user.ID, admin.user.Username)
		}
	} else {
		log.Printf("✅ 管理员已创建：#%d %s", admin.user.ID, admin.user.Username)
	}

	// 2) 一个普通示例用户：让「用户管理 / 审计日志」不是单行表格。
	// 示例用户是演示资源，可安全地随每次 -apply 重建其凭据。
	demoUserInfo, err := s.ensureUser(demoUserUsername, demoUserEmail, "示例用户", demoUserPassword, false, now.AddDate(0, 0, -12), true)
	if err != nil {
		log.Fatalf("❌ 写入示例用户失败: %v", err)
	}
	demoUser := demoUserInfo.user

	// 3) 清掉上一次的演示数据（只删带标记 / 固定 ID 的行）。
	s.purgeDemo(admin.user.ID)
	s.purgeDemo(demoUser.ID)
	// 示例用户的演示事件同样带前缀，单独清理。
	_, _ = s.db.NewDelete().Model((*models.Event)(nil)).
		Where("user_id = ? AND summary LIKE ?", demoUser.ID, demoPrefix+"%").Exec(s.ctx)

	// 4) OAuth 应用 + 授权 + 令牌。
	for _, c := range demoClients {
		if err := s.upsertClient(c, now); err != nil {
			log.Fatalf("❌ 写入应用 %s 失败: %v", c.ID, err)
		}
		grantAt := now.AddDate(0, 0, -c.GrantDaysAgo)
		if err := s.insert("grants", &models.Grant{
			ID: "demo-grant-" + c.ID, UserID: admin.user.ID, ClientID: c.ID, Scopes: c.Scopes, CreatedAt: grantAt,
		}); err != nil {
			log.Fatalf("❌ 写入授权失败: %v", err)
		}
		if c.TokenHoursAgo > 0 {
			issued := now.Add(-time.Duration(c.TokenHoursAgo) * time.Hour)
			if err := s.insert("tokens", &models.Token{
				ID: "demo-token-" + c.ID, UserID: admin.user.ID, ClientID: c.ID, Type: "access",
				Scope: strings.Join(c.Scopes, " "), ExpiresAt: issued.Add(2 * time.Hour), CreatedAt: issued,
			}); err != nil {
				log.Fatalf("❌ 写入令牌失败: %v", err)
			}
		}
	}
	log.Printf("✅ 演示应用 / 授权：%d 个（含高风险权限组合）", len(demoClients))

	// 5) 会话 + 设备 + 可信设备。
	for _, d := range demoSessions {
		lastSeen := now.Add(-time.Duration(d.HoursAgo) * time.Hour)
		created := lastSeen.Add(-2 * time.Hour)
		if err := s.insert("sessions", &models.Session{
			ID: d.ID, SessionHash: auth.SessionIDHash(d.ID), UserID: admin.user.ID, DeviceID: d.DeviceID,
			UserAgent: d.UserAgent, IPAddress: d.IP, IPRegion: d.Region,
			ExpiresAt: created.Add(time.Duration(d.TTLHours) * time.Hour), LastSeenAt: lastSeen, CreatedAt: created,
		}); err != nil {
			log.Fatalf("❌ 写入会话失败: %v", err)
		}
	}
	seenDevices := map[string]bool{}
	for _, d := range demoSessions {
		if seenDevices[d.DeviceID] {
			continue
		}
		seenDevices[d.DeviceID] = true
		first := now.Add(-time.Duration(d.HoursAgo+48) * time.Hour)
		if err := s.insert("devices", &models.Device{
			// 主键是独立随机值，设备标识另存 device_id：两者解耦后
			// 同一浏览器可分别属于多个账号，不会再因主键相同而冲突。
			ID: auth.NewID(), DeviceID: d.DeviceID, UserID: admin.user.ID, UserAgent: d.UserAgent,
			FirstIPAddress: d.IP, FirstIPRegion: d.Region, LastIPAddress: d.IP, LastIPRegion: d.Region,
			FirstSeenAt: first, LastSeenAt: now.Add(-time.Duration(d.HoursAgo) * time.Hour),
		}); err != nil {
			log.Fatalf("❌ 写入设备失败: %v", err)
		}
	}
	if err := s.insert("trusted_devices", &models.TrustedDevice{
		ID: "demo-trusted-win", UserID: admin.user.ID, DeviceID: "demo-dev-win", Name: "Windows 设备",
		UserAgent: demoWindowsUA, IPAddress: "119.123.45.67", IPRegion: "中国 · 广东省 · 深圳市 · 电信",
		ExpiresAt: now.AddDate(0, 0, 30), LastSeenAt: now, CreatedAt: now.AddDate(0, 0, -14),
	}); err != nil {
		log.Fatalf("❌ 写入可信设备失败: %v", err)
	}
	log.Printf("✅ 演示会话 %d 个 / 设备 %d 个 / 可信设备 1 个", len(demoSessions), len(seenDevices))

	// 6) 事件（近 7 天，覆盖登录/授权/会话/账号变更与失败记录）。
	if err := s.seedEvents(admin.user, now); err != nil {
		log.Fatalf("❌ 写入事件失败: %v", err)
	}

	// 7) 站内通知（含未读）。
	if err := s.seedNotifications(admin.user, now); err != nil {
		log.Fatalf("❌ 写入通知失败: %v", err)
	}

	log.Printf("--- 演示数据写入完成 ---")
	if force || !admin.existing {
		log.Printf("👉 管理员：%s / %s", username, password)
	} else {
		log.Printf("👉 管理员：%s（沿用原有密码）", username)
	}
	log.Printf("👉 示例用户：%s / %s（普通用户，用于管理端演示）", demoUserUsername, demoUserPassword)
	log.Printf("ℹ️  过期会话会被服务端定时清理（每小时 / 重启时），「历史会话」清空后重跑本命令即可恢复")
	return force || !admin.existing
}

// ensureUserResult 描述一次 ensureUser 的结果：existing 表示账号此前已存在。
type ensureUserResult struct {
	user     *models.User
	existing bool
}

// ensureUser 创建或更新一个用户。
//
// updatePassword 为 false 且账号已存在时，保留其原有密码与资料，仅确保账号可用
// （避免在预发 / 共享环境静默改写真实管理员凭据）；为 true 时同步密码与管理员位。
func (s *seeder) ensureUser(username, email, display, password string, isAdmin bool, createdAt time.Time, updatePassword bool) (*ensureUserResult, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	var u models.User
	err = s.db.NewSelect().Model(&u).Where("username = ?", username).Scan(s.ctx)
	if err == nil {
		if !updatePassword {
			return &ensureUserResult{user: &u, existing: true}, nil
		}
		_, err = s.db.NewUpdate().Model(&u).
			Set("password_hash = ?", hash).
			Set("password_set = ?", true).
			Set("is_admin = ?", isAdmin).
			Set("email_verified = ?", true).
			Set("updated_at = ?", db.Now()).
			Where("id = ?", u.ID).Exec(s.ctx)
		return &ensureUserResult{user: &u, existing: true}, err
	}
	u = models.User{
		Subject:       auth.RandomToken(16),
		Username:      username,
		DisplayName:   display,
		Email:         email,
		EmailVerified: true,
		PasswordHash:  hash,
		PasswordSet:   true,
		IsAdmin:       isAdmin,
		CreatedAt:     createdAt,
		UpdatedAt:     db.Now(),
	}
	if _, err := s.db.NewInsert().Model(&u).Exec(s.ctx); err != nil {
		return nil, err
	}
	return &ensureUserResult{user: &u, existing: false}, nil
}

func (s *seeder) upsertClient(c demoClient, now time.Time) error {
	_, _ = s.db.NewDelete().Model((*models.OAuthClient)(nil)).Where("id = ?", c.ID).Exec(s.ctx)
	// 每次运行生成随机密钥：演示客户端不应使用可预测的固定凭据。
	secret, err := auth.HashPassword(auth.RandomToken(24))
	if err != nil {
		return err
	}
	return s.insert("oauth_clients", &models.OAuthClient{
		ID: c.ID, SecretHash: secret, ClientType: "confidential",
		Name: c.Name, Description: c.Description, LogoURL: c.Logo, HomepageURL: c.Homepage,
		RedirectURIs: []string{c.Homepage + "/callback"}, Scopes: c.Scopes,
		CreatedAt: now.AddDate(0, 0, -c.GrantDaysAgo),
	})
}

// purgeDemo 只删除带演示标记的行：固定 ID 的资源 + [示例] 前缀的事件与通知。
func (s *seeder) purgeDemo(userID int64) {
	for _, model := range []any{
		(*models.Session)(nil), (*models.Device)(nil), (*models.TrustedDevice)(nil),
		(*models.Token)(nil), (*models.Grant)(nil),
	} {
		_, _ = s.db.NewDelete().Model(model).
			Where("user_id = ? AND id LIKE ?", userID, "demo-%").Exec(s.ctx)
	}
	_, _ = s.db.NewDelete().Model((*models.Event)(nil)).
		Where("user_id = ? AND summary LIKE ?", userID, demoPrefix+"%").Exec(s.ctx)
	_, _ = s.db.NewDelete().Model((*models.Notification)(nil)).
		Where("user_id = ? AND title LIKE ?", userID, demoPrefix+"%").Exec(s.ctx)
}

func (s *seeder) seedEvents(admin *models.User, now time.Time) error {
	type ev struct {
		hoursAgo int
		typ      string
		summary  string
		ip       string
		region   string
		ua       string
		method   string
	}
	list := []ev{
		{2, "login.success", "登录成功", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, "password"},
		{5, "oauth.authorized", "授权应用「OpenIdP图床」访问账号", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, ""},
		{9, "login.success", "登录成功", "223.104.38.21", "中国 · 甘肃省 · 兰州市 · 移动", demoIPhoneUA, "passkey"},
		{26, "login.success", "登录成功", "223.104.38.21", "中国 · 甘肃省 · 兰州市 · 移动", demoIPhoneUA, "emailCode"},
		{30, "session.revoked", "下线了一个历史会话", "223.104.38.21", "中国 · 甘肃省 · 兰州市 · 移动", demoIPhoneUA, ""},
		{34, "login.failed", "登录失败：密码错误", "45.83.12.201", "欧洲 · 荷兰 · 阿姆斯特丹 · 未知", "curl/8.4.0", "password"},
		{50, "login.failed", "登录失败：密码错误", "45.83.12.201", "欧洲 · 荷兰 · 阿姆斯特丹 · 未知", "curl/8.4.0", "password"},
		{52, "password.changed", "修改密码，其它会话已全部下线", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, ""},
		{58, "oauth.authorized", "授权应用「OpenIdP网盘」访问账号", "61.178.12.90", "中国 · 甘肃省 · 兰州市 · 联通", demoMacUA, ""},
		{74, "login.success", "登录成功", "61.178.12.90", "中国 · 甘肃省 · 兰州市 · 联通", demoMacUA, "thirdParty"},
		{80, "oauth.denied", "拒绝了应用「OpenIdP图床」的授权请求", "61.178.12.90", "中国 · 甘肃省 · 兰州市 · 联通", demoMacUA, ""},
		{96, "login.success", "登录成功", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, "password"},
		{120, "mfa.verify_failed", "双因素验证码校验失败", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, ""},
		{128, "login.success", "登录成功", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, "password"},
		{150, "passkey.added", "添加通行密钥", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, ""},
		{152, "login.success", "登录成功", "119.123.45.67", "中国 · 广东省 · 深圳市 · 电信", demoWindowsUA, "passkey"},
	}
	for _, e := range list {
		md := map[string]string{}
		if e.method != "" {
			md["method"] = e.method
		}
		// 授权类事件带上应用名，总览「最近活动」据此展示来源应用。
		if strings.HasPrefix(e.typ, "oauth.") {
			md["clientName"] = "OpenIdP图床"
			if strings.Contains(e.summary, "网盘") {
				md["clientName"] = "OpenIdP网盘"
			}
		}
		if err := s.insert("events", &models.Event{
			UserID: admin.ID, Type: e.typ, Summary: demoPrefix + e.summary,
			IPAddress: e.ip, IPRegion: e.region, UserAgent: e.ua, Metadata: md,
			CreatedAt: now.Add(-time.Duration(e.hoursAgo) * time.Hour),
		}); err != nil {
			return err
		}
	}
	log.Printf("✅ 演示事件 %d 条（近 7 天）", len(list))
	return nil
}

func (s *seeder) seedNotifications(admin *models.User, now time.Time) error {
	type nt struct {
		hoursAgo int
		typ      string
		title    string
		summary  string
		read     bool
	}
	list := []nt{
		{3, "new_device_login", demoPrefix + "新设备登录提醒", "检测到来自 Windows · 广东深圳（119.123.45.67）的新设备登录，若非本人操作请立即改密。", false},
		{26, "new_device_login", demoPrefix + "新设备登录提醒", "检测到来自 移动设备 · 甘肃兰州（223.104.38.21）的登录。", false},
		{48, "admin", demoPrefix + "站点维护公告", "本周日凌晨 02:00-03:00 将进行数据库维护，期间可能出现短暂无法登录。", true},
		{120, "system", demoPrefix + "授权变更提醒", "应用「OpenIdP网盘」的授权范围发生变化，请前往「我的授权」确认。", true},
	}
	for _, n := range list {
		if err := s.insert("notifications", &models.Notification{
			UserID: admin.ID, Type: n.typ, Title: n.title, Summary: n.summary,
			Read: n.read, CreatedAt: now.Add(-time.Duration(n.hoursAgo) * time.Hour),
		}); err != nil {
			return err
		}
	}
	log.Printf("✅ 演示通知 %d 条（2 条未读）", len(list))
	return nil
}

// insert 是统一的落库入口：只负责把错误信息带上表名，便于定位。
func (s *seeder) insert(table string, model any) error {
	if _, err := s.db.NewInsert().Model(model).Exec(s.ctx); err != nil {
		return fmt.Errorf("insert %s: %w", table, err)
	}
	return nil
}

func tableName(model any) string {
	switch model.(type) {
	case *models.OAuthClient:
		return "oauth_clients"
	case *models.Grant:
		return "grants"
	case *models.Session:
		return "sessions"
	case *models.Device:
		return "devices"
	case *models.Notification:
		return "notifications"
	default:
		return "events"
	}
}
