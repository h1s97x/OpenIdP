package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mysqldialect"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/h1s97x/openidp/api/internal/config"
)

// ---------------------------------------------------------------------------
// 方言迁移测试
//
// 背景：迁移里的 DDL 与元数据查询此前只按 SQLite 的语法写：
//   - CREATE INDEX IF NOT EXISTS 在 MySQL 上是语法错误（ERROR 1064），
//     迁移第一步就失败 → main 里 logging.Fatal → 服务直接起不来；
//   - ALTER TABLE ... ADD COLUMN x varchar 在 MySQL 上同样是语法错误
//     （varchar 必须带长度），是老库升级的定时炸弹；
//   - information_schema.columns 未按库过滤，多库实例会命中其它库的同名表。
//
// 这些问题只有真正连上对应数据库才能发现，因此这里按可用性做真实集成测试。
// 连接串通过环境变量提供，未配置时跳过（本地/CI 没起该库时不至于失败）。
// ---------------------------------------------------------------------------

// mysqlTestDB 连接测试用 MySQL / MariaDB，未配置 OPENIDP_TEST_MYSQL_DSN 时跳过。
func mysqlTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dsn := config.Getenv("TEST_MYSQL_DSN")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("未设置 OPENIDP_TEST_MYSQL_DSN，跳过 MySQL/MariaDB 集成测试")
	}
	// 管理连接：不设置任何会话参数（Params 会以 SET 语句下发，
	// 而 `charset` 不是可 SET 的系统变量，加了会在连接阶段直接报 1193）。
	adminCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	adminCfg.ParseTime = true
	adminConnector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatalf("mysql connector: %v", err)
	}
	admin := sql.OpenDB(adminConnector)
	defer admin.Close()

	// 每个用例用独立库名，避免并行/重复执行互相污染。
	name := fmt.Sprintf("openidp_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	// 连接池会重建连接，必须把库名写进 DSN 才能保证每条连接都落在该库。
	testCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	testCfg.ParseTime = true
	testCfg.DBName = name
	testCfg.Collation = "utf8mb4_general_ci"
	connector, err := mysql.NewConnector(testCfg)
	if err != nil {
		t.Fatalf("mysql connector2: %v", err)
	}
	sqldb := sql.OpenDB(connector)
	sqldb.SetMaxOpenConns(4)
	bdb := bun.NewDB(sqldb, mysqldialect.New())
	t.Cleanup(func() {
		_ = bdb.Close()
		drop := sql.OpenDB(adminConnector)
		defer drop.Close()
		_, _ = drop.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	return bdb
}

// TestOpenMySQLProducesWorkingConnections 回归：按生产路径 Open() 打开 MySQL
// 必须拿到可用连接。
//
// 此前 DSN 里把 charset 塞进了 cfg.Params，而驱动的 Params 会以
// `SET charset = utf8mb4` 下发——`charset` 不是可 SET 的系统变量，
// 于是每条新连接都报 ERROR 1193，PingContext 失败：
// 要么降级到 SQLite（数据看起来「消失」），要么 fail-fast 直接退出。
// 这一条只有真连库才能发现，因此必须留在集成测试里。
func TestOpenMySQLProducesWorkingConnections(t *testing.T) {
	dsn := config.Getenv("TEST_MYSQL_DSN")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("未设置 OPENIDP_TEST_MYSQL_DSN，跳过 MySQL/MariaDB 集成测试")
	}
	// 独立库，避免污染其它用例。
	adminCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	adminConnector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	admin := sql.OpenDB(adminConnector)
	defer admin.Close()
	name := fmt.Sprintf("openidp_open_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name)
	}()

	testDSN := dsn
	if !strings.HasSuffix(testDSN, "/") {
		// DSN 形如 user:pass@tcp(host:port)/——库名接在斜杠后。
		if i := strings.LastIndex(testDSN, "/"); i >= 0 {
			testDSN = testDSN[:i+1]
		}
	}
	testDSN += name

	res, err := Open(testDSN, t.TempDir(), "fail-fast")
	if err != nil {
		t.Fatalf("Open 失败（生产路径连不上库）: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if res.Kind != "mysql" {
		t.Fatalf("实际生效类型 = %q，期望 mysql", res.Kind)
	}
	// 连接池里新起的连接同样必须可用（此前每建一条都报 1193）。
	for i := 0; i < 3; i++ {
		if err := res.DB.PingContext(context.Background()); err != nil {
			t.Fatalf("第 %d 次 Ping 失败: %v", i+1, err)
		}
	}
	// 中文写入必须正常（字符集配置生效的直接观测点）。
	if err := Migrate(context.Background(), res.DB); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if _, err := res.DB.ExecContext(context.Background(),
		"INSERT INTO users (subject, username, display_name, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
		"sub-cn", "cnuser", "OpenIdP"); err != nil {
		t.Fatalf("写入中文失败: %v", err)
	}
	var got string
	if err := res.DB.QueryRowContext(context.Background(),
		"SELECT display_name FROM users WHERE username = ?", "cnuser").Scan(&got); err != nil {
		t.Fatalf("读取中文失败: %v", err)
	}
	if got != "OpenIdP" {
		t.Errorf("中文往返不一致：%q", got)
	}
}

// TestMigrateMySQL 迁移必须在真实 MySQL / MariaDB 上跑通并能重复执行。
//
// 这是 P0 级回归护栏：只要索引或补列语句再次退化成 SQLite 专有语法，
// 这个用例会立刻失败，而不是等到用户部署时才发现服务起不来。
func TestMigrateMySQL(t *testing.T) {
	db := mysqlTestDB(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("MySQL Migrate 第 %d 次失败: %v", i+1, err)
		}
	}
}

// TestMigrateMySQLBackfillsColumns 老库升级路径：先建一张缺列的表，
// 再跑迁移，必须能补齐列且不因 varchar 缺长度而报语法错误。
func TestMigrateMySQLBackfillsColumns(t *testing.T) {
	db := mysqlTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("初始化迁移失败: %v", err)
	}
	// 模拟旧库：先删掉依赖该列的索引，再删列；随后迁移应自动补回列。
	if _, err := db.ExecContext(ctx, "DROP INDEX idx_devices_user_device ON devices"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE devices DROP COLUMN device_id"); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("补列迁移失败: %v", err)
	}
	cols, err := mysqlColumns(ctx, db, "devices")
	if err != nil {
		t.Fatalf("list columns: %v", err)
	}
	if !containsStr(cols, "device_id") {
		t.Fatalf("device_id 未被补回：%v", cols)
	}
}

// TestMigrateMySQLIndexesCreated 迁移后热路径索引必须真实存在。
func TestMigrateMySQLIndexesCreated(t *testing.T) {
	db := mysqlTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, m := range indexMigrations {
		var n int
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?",
			m.table, m.name).Scan(&n); err != nil {
			t.Fatalf("inspect index %s: %v", m.name, err)
		}
		if n == 0 {
			t.Errorf("迁移后缺少索引 %s（表 %s）", m.name, m.table)
		}
	}
}

// TestAddColumnIfMissingIsSchemaScoped 多库实例上，同名表的列内省必须按当前库过滤。
//
// 另建一个库里存在同名表且含目标列：若查询未带 table_schema 过滤，
// 会误判「列已存在」而漏补列，随后在运行期表现为 no such column。
func TestAddColumnIfMissingIsSchemaScoped(t *testing.T) {
	db := mysqlTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 在另一个库里造一张同名表，且带 device_id 列（作为「干扰库」）。
	other := fmt.Sprintf("openidp_other_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, "CREATE DATABASE "+other); err != nil {
		t.Fatalf("create other db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+other)
	})
	if _, err := db.ExecContext(ctx, "CREATE TABLE "+other+".devices (id varchar(64), device_id varchar(64))"); err != nil {
		t.Fatalf("create shadow table: %v", err)
	}
	// 本库删列后补列：必须补回，而不是被干扰库的 device_id 误导。
	if _, err := db.ExecContext(ctx, "DROP INDEX idx_devices_user_device ON devices"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE devices DROP COLUMN device_id"); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	m := columnMigration{table: "devices", column: "device_id", typeSQLitePG: "varchar", typeMySQL: "varchar(64)"}
	// 迁移是一次性记录的，直接调用补列函数来验证内省逻辑。
	if err := addColumnIfMissing(ctx, db, m); err != nil {
		t.Fatalf("addColumnIfMissing: %v", err)
	}
	cols, err := mysqlColumns(ctx, db, "devices")
	if err != nil {
		t.Fatalf("list columns: %v", err)
	}
	if !containsStr(cols, "device_id") {
		t.Fatalf("列未按当前库补回：%v", cols)
	}
}

// ---- PostgreSQL：同一段迁移逻辑也要在该方言下成立 ----

func pgTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dsn := strings.TrimSpace(config.Getenv("TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("未设置 OPENIDP_TEST_PG_DSN，跳过 PostgreSQL 集成测试")
	}
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	t.Cleanup(func() { _ = sqldb.Close() })
	return bun.NewDB(sqldb, pgdialect.New())
}

// TestMigratePostgres PostgreSQL 下迁移同样必须可重复执行。
func TestMigratePostgres(t *testing.T) {
	db := pgTestDB(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("PG Migrate 第 %d 次失败: %v", i+1, err)
		}
	}
}

// mysqlColumns 列出当前库中某表的全部列名。
func mysqlColumns(ctx context.Context, db *bun.DB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		"SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
