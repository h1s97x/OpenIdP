package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
	"github.com/uptrace/bun/dialect/mysqldialect"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/h1s97x/openidp/api/internal/auth"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// Kind 根据连接串判定数据库类型（sqlite / postgres / mysql）。
// 启动日志、初始化页等处共用这一个判定，避免同类逻辑散落多处各自演化。
func Kind(databaseURL string) string {
	if databaseURL == "" {
		return "sqlite"
	}
	if strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://") {
		return "postgres"
	}
	return "mysql"
}

// OpenResult 描述 Open 的最终结果。
// Kind 是实际生效的数据库类型，而非配置值：发生降级时两者不同，
// 启动日志必须依据它打印，否则会误导排障方向。
type OpenResult struct {
	DB       *bun.DB
	Kind     string
	Degraded bool
}

// Open chooses the driver based on DatabaseURL.
//   - ""       -> SQLite (dev default, modernc pure-Go driver, no CGO)
//   - postgres:// -> PostgreSQL
//   - mysql/mariadb DSN (user:pass@tcp(...)) -> MySQL / MariaDB
//
// fallback 控制外部数据库（PG/MySQL）不可连通时的行为：
//   - "sqlite"（显式允许降级）：连接失败时切到 SQLite 继续启动，仅限开发/测试。
//   - 其它值（默认 "fail-fast"）：外部数据库故障直接返回错误退出，避免静默切到空的
//     SQLite 导致用户数据"消失"与双库数据分裂。
//
// 返回实际生效的 Kind（降级后为 sqlite），调用方据此打印日志与运行状态。
func Open(databaseURL, dataDir string, fallback string) (*OpenResult, error) {
	if databaseURL == "" {
		db, err := openSQLite(dataDir)
		if err != nil {
			return nil, err
		}
		return &OpenResult{DB: db, Kind: "sqlite"}, nil
	}

	var (
		sqldb *sql.DB
		bdb   *bun.DB
		desc  string
	)
	switch {
	case strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://"):
		connector := pgdriver.NewConnector(pgdriver.WithDSN(databaseURL))
		sqldb = sql.OpenDB(connector)
		bdb = bun.NewDB(sqldb, pgdialect.New())
		desc = "PostgreSQL"
	default:
		// MySQL / MariaDB DSN
		cfg, err := mysql.ParseDSN(databaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid MySQL/MariaDB DSN: %w", err)
		}
		cfg.ParseTime = true
		// 字符集通过 Collation 指定，绝不能塞进 Params：
		// Params 里的每一项都会以 `SET <key> = <value>` 下发（见驱动 handleParams），
		// 而 `charset` 不是可 SET 的系统变量，写了会让每条新连接都直接报
		// ERROR 1193 Unknown system variable 'charset' —— MySQL / MariaDB
		// 部署根本连不上库（PingContext 失败 → 迁移与登录全不可用）。
		// 驱动的默认连接排序规则本就是 utf8mb4_general_ci（collation id 45），
		// 这里显式写出，避免默认值将来变动导致中文写入异常。
		cfg.Collation = "utf8mb4_general_ci"
		connector, err := mysql.NewConnector(cfg)
		if err != nil {
			return nil, fmt.Errorf("init mysql connector: %w", err)
		}
		sqldb = sql.OpenDB(connector)
		bdb = bun.NewDB(sqldb, mysqldialect.New())
		desc = "MySQL/MariaDB"
	}

	sqldb.SetMaxOpenConns(10)
	sqldb.SetMaxIdleConns(5)
	sqldb.SetConnMaxLifetime(time.Hour)

	// 探测外部数据库连通性；失败时按 fallback 决定是否降级。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		if strings.EqualFold(fallback, "sqlite") {
			log.Printf("⚠️ [DB] %s 连接失败（%v），已显式降级为 SQLite（DB_FALLBACK=sqlite）", desc, err)
			db, serr := openSQLite(dataDir)
			if serr != nil {
				return nil, serr
			}
			return &OpenResult{DB: db, Kind: "sqlite", Degraded: true}, nil
		}
		return nil, fmt.Errorf("%s 连接失败（%v）; 生产环境默认 fail-fast，如需降级 SQLite 请设置 DB_FALLBACK=sqlite", desc, err)
	}
	return &OpenResult{DB: bdb, Kind: Kind(databaseURL)}, nil
}

// openSQLite 打开 SQLite 数据库（自动降级目标）。
func openSQLite(dataDir string) (*bun.DB, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, "openidp.db")
	sqldb, err := sql.Open(sqliteshim.DriverName(), "file:"+path+"?cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqldb.SetMaxOpenConns(1)
	return bun.NewDB(sqldb, sqlitedialect.New()), nil
}

// Migrate creates tables if they do not exist (idempotent).
func Migrate(ctx context.Context, db *bun.DB) error {
	models := []any{
		(*models.User)(nil),
		(*models.Session)(nil),
		(*models.Device)(nil),
		(*models.TrustedDevice)(nil),
		(*models.Event)(nil),
		(*models.Grant)(nil),
		(*models.OAuthClient)(nil),
		(*models.AuthorizationCode)(nil),
		(*models.Token)(nil),
		(*models.NotificationPreference)(nil),
		(*models.Notification)(nil),
		(*models.SiteSetting)(nil),
		(*models.SecurityPolicy)(nil),
		(*models.OAuthProvider)(nil),
		(*models.Passkey)(nil),
		(*models.Identity)(nil),
		(*models.VerificationCode)(nil),
		(*models.MailSetting)(nil),
		(*models.CaptchaSetting)(nil),
		(*models.SmsSetting)(nil),
		(*models.MFA)(nil),
		(*models.MFAChallenge)(nil),
		(*models.AccountDeletionRequest)(nil),
		(*models.File)(nil),
		(*models.StorageSetting)(nil),
		(*models.LocationSetting)(nil),
		(*models.ProxySetting)(nil),
		(*models.AuditSetting)(nil),
		(*models.DataCleanupSetting)(nil),
		(*models.DeviceAuthorization)(nil),
		(*models.OAuthScope)(nil),
	}
	for _, m := range models {
		if _, err := db.NewCreateTable().Model(m).IfNotExists().Exec(ctx); err != nil {
			return fmt.Errorf("create table %T: %w", m, err)
		}
	}
	// 移除已废弃的内置登录提供商（华为/小米），保证升级后的库与内置列表一致。
	if err := removeDeprecatedProviders(ctx, db); err != nil {
		return err
	}
	// 移除已下线的门户登录策略表（功能已并入安全策略）。
	if err := dropPortalLoginPolicies(ctx, db); err != nil {
		return err
	}
	// 为升级前建的表补充新增列（旧库缺列）。可补的列与 DDL 全部登记在
	// columnMigrations 白名单里，这里按序遍历，不再逐条硬编码调用。
	for _, m := range columnMigrations {
		if err := addColumnIfMissing(ctx, db, m); err != nil {
			return err
		}
	}
	// 回填存量会话的 session_hash：老数据行的 id 即为 Cookie 中的明文值，
	// 这里补算摘要，迁移后统一按摘要校验。
	if err := backfillSessionHashes(ctx, db); err != nil {
		return err
	}
	// 把存量会话主键改写为不可逆摘要：历史上它等于 Cookie 里的原始会话 ID，
	// 不清理则库/备份泄露仍可直接接管账号。
	if err := scrubSessionIDs(ctx, db); err != nil {
		return err
	}
	// 回填 OAuth 客户端类型：按是否配置密钥推导（有密钥=confidential，否则 public）。
	if err := backfillClientTypes(ctx, db); err != nil {
		return err
	}
	// 用户名区分大小写：把 MySQL/MariaDB 的 username 列改为二进制排序规则。
	if err := ensureCaseSensitiveUsername(ctx, db); err != nil {
		return err
	}
	// 回填设备标识：旧库中 devices.id 就是设备 cookie 值，这里把它复制到新增的
	// device_id 列，随后才能安全地建立 (user_id, device_id) 唯一索引。
	if err := backfillDeviceIDs(ctx, db); err != nil {
		return err
	}
	// 为高频查询补建索引（幂等）。
	if err := createIndexes(ctx, db); err != nil {
		return err
	}
	return nil
}

// Now 返回系统时区下的当前时间，供业务写入 created_at / updated_at 等时间列。
//
// 统一入口保证日志、界面展示与统计日界使用同一时区口径。
func Now() time.Time {
	return timezone.Now()
}

// DefaultEventRetentionDays 是未配置时的默认事件保留天数。
//
// 保留天数取自管理后台的「审计保留策略」；此前那组配置只在界面上读写、
// 从未参与清理判定（归档与清理都硬编码 90 天），
// 后台把保留期从 90 天改成 7 天不会有任何效果。
const DefaultEventRetentionDays = 90

// CleanupExpired 删除各类过期/失效记录，避免数据无限膨胀。
// retentionDays 是审计事件的保留天数（<=0 表示永久保留，不清理事件）。
// 导出供任务调度器调用。
func CleanupExpired(ctx context.Context, db *bun.DB, retentionDays int) error {
	now := timezone.Now()

	dels := []*bun.DeleteQuery{
		db.NewDelete().Model((*models.Session)(nil)).Where("expires_at < ?", now),
		// Refresh token 墓碑（用于重用检测）多保留 30 天，与其轮换周期对齐；
		// 普通 access token 仍按到期即清。
		db.NewDelete().Model((*models.Token)(nil)).
			Where("expires_at < ? AND (replaced_by = '' OR replaced_by IS NULL OR expires_at < ?)", now, now.AddDate(0, 0, -30)),
		db.NewDelete().Model((*models.AuthorizationCode)(nil)).Where("expires_at < ?", now),
		db.NewDelete().Model((*models.VerificationCode)(nil)).Where("expires_at < ?", now),
		db.NewDelete().Model((*models.MFAChallenge)(nil)).Where("expires_at < ?", now),
	}
	if retentionDays > 0 {
		dels = append(dels, db.NewDelete().Model((*models.Event)(nil)).
			Where("created_at < ?", now.AddDate(0, 0, -retentionDays)))
	}
	for _, d := range dels {
		if _, err := d.Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ArchiveEvents 将超过保留期的历史事件归档为 JSON 行文件并删除原记录，
// 防止审计表无限膨胀的同时保留可追溯的历史。归档文件写入 DATA_DIR/audit/ 目录。
// retentionDays <= 0 时不做任何事（永久保留）。
func ArchiveEvents(ctx context.Context, db *bun.DB, dataDir string, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	cutoff := timezone.Now().AddDate(0, 0, -retentionDays)

	var events []models.Event
	err := db.NewSelect().Model(&events).Where("created_at < ?", cutoff).Limit(10000).Scan(ctx)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	dir := filepath.Join(dataDir, "audit")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "events.archive.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			return err
		}
	}
	// 归档成功后删除已归档记录。
	if _, err := db.NewDelete().Model((*models.Event)(nil)).Where("id IN (?)", bun.List(ids(events))).Exec(ctx); err != nil {
		return err
	}
	return nil
}

func ids(events []models.Event) []int64 {
	out := make([]int64, len(events))
	for i := range events {
		out[i] = events[i].ID
	}
	return out
}

// indexMigration 描述一条待补建的索引。
//
// table / columns / unique 全部是编译期字面量白名单：运行期只用它们拼接
// DDL 与参数（不做任何来自外部的输入拼接），并按方言分支生成语句。
//
// 之所以不能只用一条 `CREATE INDEX IF NOT EXISTS`：
//   - PostgreSQL / SQLite 支持 IF NOT EXISTS；
//   - MySQL / MariaDB 不支持该子句（ERROR 1064），必须先用
//     information_schema.statistics 查存在性再建，否则迁移第一步就会失败，
//     服务直接起不来。
type indexMigration struct {
	name    string
	table   string
	columns string
	unique  bool
}

// indexMigrations 是需要补建的索引白名单，覆盖所有热路径查询。
//
// 查询字段变更时必须同步维护这里，否则数据量上来后查询会退化成全表扫描
// （例如 sessions.session_hash 是每个请求都要查的会话校验入口）。
var indexMigrations = []indexMigration{
	// sessions：会话校验（每个请求一次）与过期清理。
	{"idx_sessions_session_hash", "sessions", "session_hash", false},
	{"idx_sessions_user_id", "sessions", "user_id", false},
	{"idx_sessions_expires_at", "sessions", "expires_at", false},
	// tokens：OIDC 令牌查询与过期清理。
	{"idx_tokens_user_id", "tokens", "user_id", false},
	{"idx_tokens_client_id", "tokens", "client_id", false},
	{"idx_tokens_expires_at", "tokens", "expires_at", false},
	// events：审计日志按用户与时间翻页。
	{"idx_events_user_created", "events", "user_id, created_at", false},
	// authorization_codes / verification_codes / mfa_challenges：过期清理。
	{"idx_auth_codes_expires", "authorization_codes", "expires_at", false},
	{"idx_verif_codes_expires", "verification_codes", "expires_at", false},
	// verification_codes：验证码校验与冷却判定（按邮箱 + 用途取最新一条）。
	{"idx_verif_codes_email_purpose", "verification_codes", "email, purpose", false},
	{"idx_mfa_challenges_expires", "mfa_challenges", "expires_at", false},
	// devices：设备列表与登录时的设备匹配（唯一索引同时防止同一用户重复建档）。
	{"idx_devices_user_device", "devices", "user_id, device_id", true},
	// trusted_devices：登录时按设备 Cookie 匹配可信设备。
	{"idx_trusted_devices_user_device", "trusted_devices", "user_id, device_id", false},
	// identities：第三方登录回调按 (provider, uid) 定位账号。
	{"idx_identities_provider_uid", "identities", "provider, provider_uid", false},
	// grants：授权列表与授权校验。
	{"idx_grants_user_client", "grants", "user_id, client_id", false},
	// account_deletion_requests：注销申请列表与到期执行。
	{"idx_deletion_req_user", "account_deletion_requests", "user_id", false},
	{"idx_deletion_req_status", "account_deletion_requests", "status, scheduled_at", false},
	// files：存储统计、孤儿回收与内容去重。
	{"idx_files_purpose_created", "files", "purpose, created_at", false},
	{"idx_files_owner", "files", "owner_user_id", false},
	{"idx_files_detached", "files", "detached_at", false},
	{"idx_files_content_hash", "files", "content_hash", false},
	// device_authorizations：设备码轮询与过期清理。
	{"idx_device_auth_user_code", "device_authorizations", "user_code", false},
	{"idx_device_auth_expires", "device_authorizations", "expires_at", false},
}

// createIndexes 为高频查询补建索引（幂等），防止数据量上来后查询退化。
func createIndexes(ctx context.Context, db *bun.DB) error {
	for _, m := range indexMigrations {
		if err := createIndexIfMissing(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

// createIndexIfMissing 按方言补建索引。
//
//   - SQLite / PostgreSQL：CREATE INDEX IF NOT EXISTS 原生幂等；
//   - MySQL / MariaDB：不支持 IF NOT EXISTS，先查 information_schema.statistics
//     （按 table_schema = DATABASE() 过滤，避免跨库同名表误判），不存在才建。
func createIndexIfMissing(ctx context.Context, db *bun.DB, m indexMigration) error {
	switch db.Dialect().Name() {
	case dialect.MySQL:
		// MySQL / MariaDB 没有 CREATE INDEX IF NOT EXISTS，先查后建。
		var n int
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?",
			m.table, m.name).Scan(&n); err != nil {
			return fmt.Errorf("inspect index %s: %w", m.name, err)
		}
		if n > 0 {
			return nil // 已存在
		}
	case dialect.PG, dialect.SQLite:
		// 原生幂等，无需先查。
	default:
		// 未知方言：跳过，避免执行语法不兼容的语句导致启动失败。
		return nil
	}
	if _, err := db.ExecContext(ctx, indexDDL(db.Dialect().Name(), m)); err != nil {
		return fmt.Errorf("create index %s: %w", m.name, err)
	}
	return nil
}

// indexDDL 按方言生成建索引语句。
//
// 关键是 IF NOT EXISTS：SQLite / PostgreSQL 支持该子句，MySQL / MariaDB 不支持
// （语法错误），对它必须在语句里去掉、改由调用方先查后建。
func indexDDL(dialectName dialect.Name, m indexMigration) string {
	kind := ""
	if m.unique {
		kind = "UNIQUE "
	}
	ifNotExists := ""
	if dialectName != dialect.MySQL {
		ifNotExists = "IF NOT EXISTS "
	}
	return fmt.Sprintf("CREATE %sINDEX %s%s ON %s (%s)", kind, ifNotExists, m.name, m.table, m.columns)
}

// columnMigration 描述一次「补列」迁移：目标表、列名与各自方言下的列类型。
//
// table / column / 类型全部是编译期字面量白名单，运行期只用它们组装语句，
// 不接受任何来自外部的输入。
//
// 为什么类型要分方言登记：MySQL / MariaDB 的 varchar 必须带长度，
// `ADD COLUMN x varchar` 在 MySQL 上是 ERROR 1064（语法错误），
// 而 SQLite / PostgreSQL 允许省略长度。用同一串 DDL 打三种库，
// 只会在 MySQL 上把「升级老库」变成「服务起不来」。
type columnMigration struct {
	table  string
	column string
	// typeSQLitePG 是 SQLite / PostgreSQL 的列类型。
	typeSQLitePG string
	// typeMySQL 是 MySQL / MariaDB 的列类型（varchar 必须带长度）。
	typeMySQL string
	// defaultTrue 让补列语句带上「真值默认」：存量行因此取 true 而不是 NULL。
	//
	// 为什么需要：ALTER TABLE ADD COLUMN 不带默认值时，存量行的新列是 NULL ——
	// 对布尔字段而言既可能让扫描失败，也会把「默认开启」的语义变成「默认关闭」。
	// 真值字面量在各方言下不同（PostgreSQL 只接受 true，SQLite / MySQL 用 1），
	// 所以在生成 DDL 时按方言展开，而不是让调用方自己拼片段。
	defaultTrue bool
}

// columnMigrations 是允许自动补列的白名单（旧库缺列时补齐）。
// 新增列就在这里追加一条；两种类型都必须给出，避免漏配导致某一种库迁移失败。
var columnMigrations = []columnMigration{
	// oauth_clients：客户端描述；客户端类型（confidential / public）；应用主页 URL。
	{table: "oauth_clients", column: "description", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	{table: "oauth_clients", column: "client_type", typeSQLitePG: "varchar", typeMySQL: "varchar(32)"},
	{table: "oauth_clients", column: "homepage_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	// verification_codes：验证码错误尝试计数（防爆破）。
	{table: "verification_codes", column: "attempts", typeSQLitePG: "integer", typeMySQL: "integer"},
	// mail_settings：邮件服务启用开关。
	{table: "mail_settings", column: "enabled", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	// captcha_settings：找回密码验证开关、极验绑定模式、Turnstile 自定义校验端点。
	{table: "captcha_settings", column: "required_for_password_reset", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "captcha_settings", column: "geetest_bind_mode", typeSQLitePG: "varchar", typeMySQL: "varchar(32)"},
	{table: "captcha_settings", column: "turnstile_verify_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	// sessions：只存 ID 摘要（sha256），防止数据库泄露即等价于会话劫持。
	{table: "sessions", column: "session_hash", typeSQLitePG: "varchar", typeMySQL: "varchar(64)"},
	// mfa_challenges：二次验证挑战的错误尝试计数（防 6 位 TOTP 爆破）。
	{table: "mfa_challenges", column: "attempts", typeSQLitePG: "integer", typeMySQL: "integer"},
	// site_settings：站点 URL、通行密钥开关、页脚与备案信息、通行密钥扩展配置。
	{table: "site_settings", column: "site_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	{table: "site_settings", column: "passkey_enabled", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "site_settings", column: "footer_text", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	{table: "site_settings", column: "icp_beian", typeSQLitePG: "varchar", typeMySQL: "varchar(255)"},
	{table: "site_settings", column: "public_security_beian", typeSQLitePG: "varchar", typeMySQL: "varchar(255)"},
	{table: "site_settings", column: "passkey_display_name", typeSQLitePG: "varchar", typeMySQL: "varchar(255)"},
	{table: "site_settings", column: "passkey_rpid", typeSQLitePG: "varchar", typeMySQL: "varchar(255)"},
	{table: "site_settings", column: "passkey_allow_insecure", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "site_settings", column: "passkey_origins", typeSQLitePG: "json", typeMySQL: "json"},
	// site_settings：站点默认语言（未登录页面使用；已登录以浏览器记忆优先）。
	{table: "site_settings", column: "default_language", typeSQLitePG: "varchar", typeMySQL: "varchar(32)"},
	// security_policies：密码登录开关、邮箱域名白名单、禁止别名邮箱、可信设备有效期、自助注销。
	{table: "security_policies", column: "password_login_enabled", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "security_policies", column: "email_domain_whitelist", typeSQLitePG: "varchar", typeMySQL: "varchar(1000)"},
	{table: "security_policies", column: "email_domain_whitelist_enabled", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "security_policies", column: "disable_alias_email", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "security_policies", column: "trusted_device_ttl_days", typeSQLitePG: "integer", typeMySQL: "integer"},
	{table: "security_policies", column: "account_deletion_enabled", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "security_policies", column: "account_deletion_cooldown_hours", typeSQLitePG: "integer", typeMySQL: "integer"},
	// oauth_providers：提供商级「使用代理」开关（配合 proxy_settings 使用）。
	{table: "oauth_providers", column: "use_proxy", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	// oauth_providers：端点与能力字段（内置与自定义提供商共用；内置值由初始化写入）。
	{table: "oauth_providers", column: "custom", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	{table: "oauth_providers", column: "authorize_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	{table: "oauth_providers", column: "token_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	{table: "oauth_providers", column: "user_info_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	{table: "oauth_providers", column: "scopes", typeSQLitePG: "json", typeMySQL: "json"},
	{table: "oauth_providers", column: "docs_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	// oauth_providers：换取 openid 的额外端点（仅部分平台需要，如 QQ）。
	{table: "oauth_providers", column: "open_id_url", typeSQLitePG: "varchar", typeMySQL: "varchar(500)"},
	// devices：设备标识与主键解耦（原主键即浏览器 device cookie，多账号登录会主键冲突）。
	{table: "devices", column: "device_id", typeSQLitePG: "varchar", typeMySQL: "varchar(64)"},
	// trusted_devices：按设备 Cookie 匹配（用于登录时跳过二次验证）。
	{table: "trusted_devices", column: "device_id", typeSQLitePG: "varchar", typeMySQL: "varchar(64)"},
	// tokens：Refresh token 轮换墓碑，记录旧 token 的后继 ID（用于重用检测）。
	{table: "tokens", column: "replaced_by", typeSQLitePG: "varchar", typeMySQL: "varchar(64)"},
	// users：手机号验证状态（手机号由用户自填，需短信验证后才可信）。
	{table: "users", column: "phone_verified", typeSQLitePG: "boolean", typeMySQL: "boolean"},
	// security_policies：是否允许用户自助添加手机号。
	// 默认 true 与存量行为一致（老库升级后手机号入口不会凭空消失），
	// 需要关闭时由管理员在「安全策略」里显式关掉。
	{table: "security_policies", column: "phone_add_enabled", typeSQLitePG: "boolean", typeMySQL: "boolean", defaultTrue: true},
}

// addColumnDDL 按方言组装补列语句。dialectName 取 bun 的 dialect.Name()。
func addColumnDDL(dialectName dialect.Name, m columnMigration) string {
	typ := m.typeSQLitePG
	if dialectName == dialect.MySQL {
		typ = m.typeMySQL
	}
	def := ""
	if m.defaultTrue {
		// 布尔真值：PostgreSQL 只接受 true；SQLite 支持 true 关键字；
		// MySQL / MariaDB 的 boolean 即 tinyint(1)，统一用 1 最稳妥。
		if dialectName == dialect.PG {
			def = " DEFAULT true"
		} else {
			def = " DEFAULT 1"
		}
	}
	return fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s%s", m.table, m.column, typ, def)
}

// addColumnIfMissing 在已有表中按需添加列（兼容升级前建的表），幂等。
// 按方言明确分支（不再靠「出错就换一种」），避免在 PostgreSQL 上误用 PRAGMA。
func addColumnIfMissing(ctx context.Context, db *bun.DB, m columnMigration) error {
	switch db.Dialect().Name() {
	case dialect.PG, dialect.MySQL:
		// table_schema 过滤必不可少：information_schema 跨库共享，多库实例上
		// 只按 table_name 判断会命中其它库的同名表，误判「列已存在」而漏补列，
		// 随后在运行期表现为 no such column。
		var def string
		err := db.QueryRowContext(ctx,
			"SELECT COALESCE((SELECT data_type FROM information_schema.columns WHERE table_schema = "+currentSchemaSQL(db)+" AND table_name = ? AND column_name = ?), '')",
			m.table, m.column).Scan(&def)
		if err != nil {
			return fmt.Errorf("inspect column %s.%s: %w", m.table, m.column, err)
		}
		if strings.TrimSpace(def) != "" {
			return nil // 已存在
		}
	case dialect.SQLite:
		cols, err := listColumns(ctx, db, m.table)
		if err != nil {
			return err
		}
		for _, c := range cols {
			if c == m.column {
				return nil // 已存在
			}
		}
	default:
		// 未知方言：跳过自动加列，避免破坏性误操作。
		return fmt.Errorf("unsupported dialect for addColumnIfMissing: %s", db.Dialect().Name())
	}
	if _, err := db.ExecContext(ctx, addColumnDDL(db.Dialect().Name(), m)); err != nil {
		return fmt.Errorf("add column %s.%s: %w", m.table, m.column, err)
	}
	return nil
}

// currentSchemaSQL 返回「当前库 / 当前 schema」的判定表达式，用于过滤
// information_schema.columns 的 table_schema 列：
//   - MySQL / MariaDB：DATABASE() 是当前连接的库名；
//   - PostgreSQL：current_schema() 是 search_path 中的首个 schema（默认 public）。
//
// 两者都是数据库内置表达式，不来自客户端输入。
func currentSchemaSQL(db *bun.DB) string {
	if db.Dialect().Name() == dialect.PG {
		return "current_schema()"
	}
	return "DATABASE()"
}

// sqliteTableColumns 是 SQLite 下"列出表列"的语句白名单：键为表名，值为完整 SQL 字面量。
//
// SQLite 的 PRAGMA 不接受绑定参数，表名只能出现在语句文本里。为了让这条语句
// 仍然是编译期常量，这里把允许内省的表逐一登记，listColumns 只做查表与执行。
// 新增需要补列的表时同步登记一项；未登记的表会直接报出明确错误，
// 而不是退化成把表名拼进 SQL。
var sqliteTableColumns = map[string]string{
	"captcha_settings":   `PRAGMA table_info(captcha_settings)`,
	"devices":            `PRAGMA table_info(devices)`,
	"mail_settings":      `PRAGMA table_info(mail_settings)`,
	"mfa_challenges":     `PRAGMA table_info(mfa_challenges)`,
	"oauth_clients":      `PRAGMA table_info(oauth_clients)`,
	"oauth_providers":    `PRAGMA table_info(oauth_providers)`,
	"security_policies":  `PRAGMA table_info(security_policies)`,
	"sessions":           `PRAGMA table_info(sessions)`,
	"site_settings":      `PRAGMA table_info(site_settings)`,
	"trusted_devices":    `PRAGMA table_info(trusted_devices)`,
	"tokens":             `PRAGMA table_info(tokens)`,
	"users":              `PRAGMA table_info(users)`,
	"verification_codes": `PRAGMA table_info(verification_codes)`,
}

// listColumns 返回某表的全部列名（仅 SQLite，使用 PRAGMA table_info）。
func listColumns(ctx context.Context, db *bun.DB, table string) ([]string, error) {
	stmt, ok := sqliteTableColumns[table]
	if !ok {
		return nil, fmt.Errorf("list columns: table %s is not registered in sqliteTableColumns", table)
	}
	rows, err := db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name string
		var ctype string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

// removeDeprecatedProviders 删除已不再内置的登录提供商（华为/小米/微信/GitLab）。
//
// 这是一次性数据迁移，而不是每次启动都要执行的清理语句：执行成功后会把标记写入
// schema_migrations 表，后续启动直接跳过，避免常驻 DELETE 带来的无谓写放大
// （也避免管理员手工插入的自定义提供商被反复删除）。
func removeDeprecatedProviders(ctx context.Context, db *bun.DB) error {
	done, err := migrationApplied(ctx, db, "remove_deprecated_providers")
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	if _, err := db.NewDelete().Model((*models.OAuthProvider)(nil)).
		Where("provider_type IN (?)", bun.List([]string{"xiaomi", "huawei", "wechat", "gitlab"})).Exec(ctx); err != nil {
		return fmt.Errorf("remove deprecated providers: %w", err)
	}
	return recordMigration(ctx, db, "remove_deprecated_providers")
}

// dropPortalLoginPolicies 删除已下线的门户登录策略表。
//
// 门户登录与安全策略功能重复，已整体移除；遗留表不再被任何代码读写，
// 这里做一次性 DROP（记录到 schema_migrations，后续启动直接跳过）。
func dropPortalLoginPolicies(ctx context.Context, db *bun.DB) error {
	done, err := migrationApplied(ctx, db, "drop_portal_login_policies")
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	// 用 IF EXISTS 兼容从未建过该表的全新库。
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS portal_login_policies"); err != nil {
		return fmt.Errorf("drop portal_login_policies: %w", err)
	}
	return recordMigration(ctx, db, "drop_portal_login_policies")
}

// schemaMigrations 记录已执行的一次性数据迁移，保证迁移只跑一遍。
type schemaMigrations struct {
	bun.BaseModel `bun:"table:schema_migrations,alias:sm"`

	ID        int64     `bun:"id,pk,autoincrement"`
	Name      string    `bun:"name,unique,notnull"`
	AppliedAt time.Time `bun:"applied_at"`
}

// migrationApplied 报告某个一次性迁移是否已执行过。
func migrationApplied(ctx context.Context, db *bun.DB, name string) (bool, error) {
	if err := ensureMigrationsTable(ctx, db); err != nil {
		return false, err
	}
	n, err := db.NewSelect().Model((*schemaMigrations)(nil)).Where("name = ?", name).Count(ctx)
	if err != nil {
		return false, fmt.Errorf("check migration %s: %w", name, err)
	}
	return n > 0, nil
}

// recordMigration 记录某个一次性迁移已执行（重复执行视为已记录）。
func recordMigration(ctx context.Context, db *bun.DB, name string) error {
	if err := ensureMigrationsTable(ctx, db); err != nil {
		return err
	}
	// 用 Ignore() 而非手写 ON CONFLICT：MySQL 会生成 INSERT IGNORE，
	// 且并发启动时重复记录也不会报错。
	_, err := db.NewInsert().Model(&schemaMigrations{Name: name, AppliedAt: timezone.Now()}).
		Ignore().Exec(ctx)
	if err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	return nil
}

// ensureMigrationsTable 确保迁移记录表存在（幂等）。
func ensureMigrationsTable(ctx context.Context, db *bun.DB) error {
	if _, err := db.NewCreateTable().Model((*schemaMigrations)(nil)).IfNotExists().Exec(ctx); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

// backfillSessionHashes 为存量会话补算 session_hash（老数据 id 即明文会话 ID）。
func backfillSessionHashes(ctx context.Context, db *bun.DB) error {
	var ids []string
	if err := db.NewSelect().Model((*models.Session)(nil)).
		Column("id").
		Where("session_hash IS NULL OR session_hash = ''").
		Scan(ctx, &ids); err != nil {
		// 列尚不存在等情况：忽略，交由下一次迁移处理。
		return nil
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, err := db.NewUpdate().Model((*models.Session)(nil)).
			Set("session_hash = ?", auth.SessionIDHash(id)).
			Where("id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("backfill session hash: %w", err)
		}
	}
	return nil
}

// scrubSessionIDs 把存量会话主键（原始会话 ID）改写为不可逆摘要。
//
// 历史实现里 sessions.id 就是 Cookie 携带的原始会话 ID，任何人都能用它
// 直接接管账号；即便这一列已不再序列化，库/备份泄露仍等价于会话泄露。
// 这里把 id 就地改写为 sha256(id)（与 session_hash 相同），使库里不再残留
// 可用的会话凭据；改写后按 session_hash 查库的逻辑完全不受影响。
//
// 一次性迁移：执行成功后写入 schema_migrations，后续启动直接跳过。
func scrubSessionIDs(ctx context.Context, db *bun.DB) error {
	done, err := migrationApplied(ctx, db, "scrub_session_ids")
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	var ids []string
	if err := db.NewSelect().Model((*models.Session)(nil)).
		Column("id").
		Scan(ctx, &ids); err != nil {
		// 表尚不存在等情况：忽略，交由下一次启动重试。
		return nil
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		hash := auth.SessionIDHash(id)
		if hash == id {
			continue // 已是摘要
		}
		if _, err := db.NewUpdate().Model((*models.Session)(nil)).
			Set("id = ?", hash).
			Set("session_hash = ?", hash).
			Where("id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("scrub session id: %w", err)
		}
	}
	return recordMigration(ctx, db, "scrub_session_ids")
}

// backfillDeviceIDs 把旧数据里「主键即设备标识」的历史形态补齐到 device_id 列。
//
// 旧版 devices.id 直接存放浏览器 device cookie 值，device_id 列则是后来新增的。
// 不补齐会让 (user_id, device_id) 唯一索引把多条历史设备压成同一个空值而建不起来，
// 也会让「我的设备」页面失去归属判定依据。
//
// 一次性迁移：执行成功后写入 schema_migrations，后续启动直接跳过。
func backfillDeviceIDs(ctx context.Context, db *bun.DB) error {
	done, err := migrationApplied(ctx, db, "backfill_device_ids")
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	if _, err := db.NewUpdate().Model((*models.Device)(nil)).
		Set("device_id = id").
		Where("device_id IS NULL OR device_id = ''").Exec(ctx); err != nil {
		// 表尚不存在等情况：忽略，交由下一次启动重试。
		return nil
	}
	return recordMigration(ctx, db, "backfill_device_ids")
}

// backfillClientTypes 按是否配置密钥推导存量 OAuth 客户端类型。
func backfillClientTypes(ctx context.Context, db *bun.DB) error {
	var clients []models.OAuthClient
	if err := db.NewSelect().Model(&clients).Scan(ctx); err != nil {
		return nil
	}
	for i := range clients {
		c := &clients[i]
		if strings.TrimSpace(c.ClientType) != "" {
			continue
		}
		typ := "public"
		if c.SecretHash != "" {
			typ = "confidential"
		}
		if _, err := db.NewUpdate().Model(c).
			Set("client_type = ?", typ).
			Where("id = ?", c.ID).Exec(ctx); err != nil {
			return fmt.Errorf("backfill client type: %w", err)
		}
	}
	return nil
}

// ensureCaseSensitiveUsername 保证用户名唯一索引区分大小写。
//
// MySQL/MariaDB 的默认排序规则是 *_ci（不区分大小写），此时 Admin 与 admin 在
// 唯一索引里算同一个值，与应用层的精确匹配规则冲突。这里把列显式改成二进制
// 排序规则，使三种数据库行为一致。PostgreSQL 与 SQLite 原生区分大小写，无需处理。
func ensureCaseSensitiveUsername(ctx context.Context, db *bun.DB) error {
	if db.Dialect().Name() != dialect.MySQL {
		return nil
	}
	done, err := migrationApplied(ctx, db, "username_case_sensitive")
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	if _, err := db.ExecContext(ctx,
		"ALTER TABLE users MODIFY username VARCHAR(255) COLLATE utf8mb4_bin NOT NULL"); err != nil {
		return fmt.Errorf("username case sensitive: %w", err)
	}
	return recordMigration(ctx, db, "username_case_sensitive")
}
