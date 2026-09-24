package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/h1s97x/openidp/api/internal/auth"
)

// ---------------------------------------------------------------------------
// 数据库迁移测试
//
// 背景：迁移中的建索引、加列、列内省原先使用字符串拼接构造 SQL，存在注入面。
// 现已改为「编译期字面量 + 白名单查表」。本文件验证迁移本身的行为契约：
// 幂等、可重复执行、且在损坏/恶意输入下不会产生非法 SQL。
// ---------------------------------------------------------------------------

func newTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dir := t.TempDir()
	sqldb, err := openSQLiteForTest(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	bdb := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { _ = bdb.Close() })
	return bdb
}

func openSQLiteForTest(path string) (*sql.DB, error) {
	return sql.Open(sqliteshim.DriverName(), "file:"+path+"?cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
}

// TestMigrateIsIdempotent 迁移必须可重复执行：连续跑三次都不报错，
// 且表结构保持一致（升级与全新安装共用同一条代码路径）。
func TestMigrateIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("Migrate run #%d failed: %v", i+1, err)
		}
	}
}

// TestMigrateCreatesCoreTables 迁移后核心表必须存在。
func TestMigrateCreatesCoreTables(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	tables, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	_ = tables
	_ = err

	// 逐表校验存在性
	for _, tbl := range []string{"users", "sessions", "events", "grants", "oauth_clients", "passkeys"} {
		exists, err := tableExists(ctx, db, tbl)
		if err != nil {
			t.Fatalf("check table %s: %v", tbl, err)
		}
		if !exists {
			t.Errorf("expected table %s to exist after migrate", tbl)
		}
	}
}

func tableExists(ctx context.Context, db *bun.DB, name string) (bool, error) {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?", name).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// TestColumnMigrationDDLAreLiterals 所有补列语句必须是编译期字面量，
// 且结构与 `ALTER TABLE <表> ADD COLUMN <列> <类型>` 一致。
// 这保证 DDL 文本永不包含任何运行期拼接进来的值。
func TestColumnMigrationDDLAreLiterals(t *testing.T) {
	if len(columnMigrations) == 0 {
		t.Fatal("columnMigrations should not be empty")
	}
	for _, m := range columnMigrations {
		// 表名与列名必须是纯标识符（不含任何 SQL 元字符）
		if !isPlainIdent(m.table) {
			t.Errorf("columnMigrations table is not a plain identifier: %q", m.table)
		}
		if !isPlainIdent(m.column) {
			t.Errorf("columnMigrations column is not a plain identifier: %q", m.column)
		}
		// 方言类型必须登记完整，且不含注入特征字符。
		for name, typ := range map[string]string{"sqlite/pg": m.typeSQLitePG, "mysql": m.typeMySQL} {
			if typ == "" {
				t.Errorf("columnMigrations %s.%s 缺少 %s 类型", m.table, m.column, name)
				continue
			}
			for _, bad := range []string{";", "--", "/*", "'", "\""} {
				if strings.Contains(typ, bad) {
					t.Errorf("column type contains suspicious character %q: %s", bad, typ)
				}
			}
		}
		// MySQL 的 varchar 必须带长度，否则 ALTER 语句在 MySQL 上是语法错误。
		if m.typeMySQL == "varchar" {
			t.Errorf("columnMigrations %s.%s: MySQL 的 varchar 必须带长度", m.table, m.column)
		}
	}
}

// TestAddColumnDDLPerDialect 补列语句必须按方言生成：
//   - MySQL 不支持无长度的 varchar；
//   - 布尔真值的字面量三种库各不相同（PostgreSQL 只接受 true，SQLite / MySQL 用 1），
//     写错会让「升级老库」这一步直接失败。
func TestAddColumnDDLPerDialect(t *testing.T) {
	varchar := columnMigration{table: "t", column: "c", typeSQLitePG: "varchar", typeMySQL: "varchar(64)"}
	if got := addColumnDDL(dialect.SQLite, varchar); got != "ALTER TABLE t ADD COLUMN c varchar" {
		t.Errorf("sqlite ddl = %q", got)
	}
	if got := addColumnDDL(dialect.MySQL, varchar); got != "ALTER TABLE t ADD COLUMN c varchar(64)" {
		t.Errorf("mysql ddl = %q", got)
	}

	flag := columnMigration{table: "t", column: "flag", typeSQLitePG: "boolean", typeMySQL: "boolean", defaultTrue: true}
	if got := addColumnDDL(dialect.PG, flag); got != "ALTER TABLE t ADD COLUMN flag boolean DEFAULT true" {
		t.Errorf("pg ddl = %q", got)
	}
	if got := addColumnDDL(dialect.SQLite, flag); got != "ALTER TABLE t ADD COLUMN flag boolean DEFAULT 1" {
		t.Errorf("sqlite ddl = %q", got)
	}
	if got := addColumnDDL(dialect.MySQL, flag); got != "ALTER TABLE t ADD COLUMN flag boolean DEFAULT 1" {
		t.Errorf("mysql ddl = %q", got)
	}
}

// TestIndexDDLPerDialect 建索引语句必须按方言生成：
// MySQL / MariaDB 不支持 CREATE INDEX IF NOT EXISTS，混用会让迁移第一步就失败，
// 服务直接起不来（见 main 里的 log4x.Fatal 路径）。
func TestIndexDDLPerDialect(t *testing.T) {
	m := indexMigration{name: "idx_demo", table: "demo", columns: "a, b"}
	sqlite := indexDDL(dialect.SQLite, m)
	if sqlite != "CREATE INDEX IF NOT EXISTS idx_demo ON demo (a, b)" {
		t.Errorf("sqlite ddl = %q", sqlite)
	}
	pg := indexDDL(dialect.PG, m)
	if pg != "CREATE INDEX IF NOT EXISTS idx_demo ON demo (a, b)" {
		t.Errorf("pg ddl = %q", pg)
	}
	mysql := indexDDL(dialect.MySQL, m)
	if mysql != "CREATE INDEX idx_demo ON demo (a, b)" {
		t.Errorf("mysql ddl 不得包含 IF NOT EXISTS，实际 %q", mysql)
	}
	um := indexMigration{name: "idx_uniq", table: "demo", columns: "a", unique: true}
	if got := indexDDL(dialect.MySQL, um); got != "CREATE UNIQUE INDEX idx_uniq ON demo (a)" {
		t.Errorf("mysql unique ddl = %q", got)
	}
}

// TestIndexMigrationNamesAreLiterals 索引白名单必须是编译期字面量：
// 表名 / 列名都是纯标识符，避免任何来自外部的输入进入 DDL。
func TestIndexMigrationNamesAreLiterals(t *testing.T) {
	if len(indexMigrations) == 0 {
		t.Fatal("indexMigrations should not be empty")
	}
	seen := map[string]bool{}
	for _, m := range indexMigrations {
		if seen[m.name] {
			t.Errorf("duplicate index name %q", m.name)
		}
		seen[m.name] = true
		if !strings.HasPrefix(m.name, "idx_") {
			t.Errorf("index name should be prefixed with idx_: %q", m.name)
		}
		if !isPlainIdent(m.table) {
			t.Errorf("index %s table is not a plain identifier: %q", m.name, m.table)
		}
		for _, col := range strings.Split(m.columns, ",") {
			if !isPlainIdent(strings.TrimSpace(col)) {
				t.Errorf("index %s column is not a plain identifier: %q", m.name, col)
			}
		}
		for _, bad := range []string{";", "--", "/*", "'", "\""} {
			if strings.Contains(m.table+m.columns+m.name, bad) {
				t.Errorf("index %s contains suspicious characters", m.name)
			}
		}
	}
}

// 且语句本身是字面量 PRAGMA（PRAGMA 不接受绑定参数，故只能查表）。
func TestSqliteTableColumnsRegistry(t *testing.T) {
	if len(sqliteTableColumns) == 0 {
		t.Fatal("sqliteTableColumns should not be empty")
	}
	for tbl, stmt := range sqliteTableColumns {
		if !isPlainIdent(tbl) {
			t.Errorf("registry key is not a plain identifier: %q", tbl)
		}
		want := "PRAGMA table_info(" + tbl + ")"
		if stmt != want {
			t.Errorf("statement for %q = %q, want %q", tbl, stmt, want)
		}
	}
}

// TestListColumnsRejectsUnregisteredTable 未登记的表名必须报错，
// 而不是退化成把表名拼进 SQL。
func TestListColumnsRejectsUnregisteredTable(t *testing.T) {
	db := newTestDB(t)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := listColumns(context.Background(), db, "users; DROP TABLE users--"); err == nil {
		t.Error("listColumns should reject an unregistered/invalid table name")
	}
	// 未登记但合法的标识符同样应被拒绝（白名单语义）
	if _, err := listColumns(context.Background(), db, "some_unregistered_table"); err == nil {
		t.Error("listColumns should reject a table not in the registry")
	}
}

// TestListColumnsReturnsRegisteredTable 已登记的表应能正常返回列清单。
func TestListColumnsReturnsRegisteredTable(t *testing.T) {
	db := newTestDB(t)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cols, err := listColumns(context.Background(), db, "sessions")
	if err != nil {
		t.Fatalf("listColumns(sessions): %v", err)
	}
	if len(cols) == 0 {
		t.Fatal("expected sessions to have columns")
	}
	found := false
	for _, c := range cols {
		if c == "id" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an id column in sessions, got %v", cols)
	}
}

// TestAddColumnIfMissingRejectsUnregistered 未登记的补列目标必须报错。
func TestAddColumnIfMissingRejectsUnregistered(t *testing.T) {
	db := newTestDB(t)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	bad := columnMigration{table: "not_registered", column: "x", typeSQLitePG: "varchar", typeMySQL: "varchar(64)"}
	if err := addColumnIfMissing(context.Background(), db, bad); err == nil {
		t.Error("addColumnIfMissing should reject an unregistered table")
	}
}

// TestKindDetection 数据库类型判定：空 URL 为 sqlite，postgres/pgsql 前缀为 postgres，其余为 mysql。
func TestKindDetection(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "sqlite"},
		{"postgres://user:pw@h:5432/db", "postgres"},
		{"postgresql://user:pw@h:5432/db", "postgres"},
		{"user:pw@tcp(127.0.0.1:3306)/db", "mysql"},
	}
	for _, c := range cases {
		if got := Kind(c.in); got != c.want {
			t.Errorf("Kind(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// isPlainIdent 判断字符串是否为「纯」SQL 标识符：
// 仅含字母、数字、下划线，且不以数字开头。用于校验白名单登记项本身安全。
func isPlainIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		ok := r == '_' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(i > 0 && r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// TestScrubSessionIDsRewritesLegacyRawIDs 存量会话主键（历史实现为明文会话 ID）
// 必须在迁移时就地改写为不可逆摘要，避免库/备份泄露直接等同于会话劫持。
func TestScrubSessionIDsRewritesLegacyRawIDs(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 造一条「老库」形态：id 就是明文会话 ID，session_hash 为空。
	raw := "LEGACY_RAW_SESSION_ID_123"
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions (id, session_hash, user_id, expires_at, last_seen_at, created_at) VALUES (?, '', 1, '2099-01-01', '2026-01-01', '2026-01-01')`,
		raw); err != nil {
		t.Fatalf("insert legacy session: %v", err)
	}
	// 清除一次性迁移标记，模拟升级后首次执行。
	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE name = 'scrub_session_ids'`); err != nil {
		t.Fatalf("clear migration marker: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}

	var id, hash string
	if err := db.QueryRowContext(ctx, `SELECT id, session_hash FROM sessions`).Scan(&id, &hash); err != nil {
		t.Fatalf("load session: %v", err)
	}
	if id == raw {
		t.Fatal("legacy raw session id must be scrubbed from sessions.id")
	}
	if id != hash {
		t.Fatalf("sessions.id (%q) must equal session_hash (%q) after scrub", id, hash)
	}
	// 新值必须是原值的 sha256 摘要。
	if want := auth.SessionIDHash(raw); id != want {
		t.Fatalf("sessions.id = %q, want sha256(raw) = %q", id, want)
	}
}
