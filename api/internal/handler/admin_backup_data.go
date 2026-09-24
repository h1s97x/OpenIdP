package handler

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

// 数据表备份（ZIP 的 data/ 部分）。
//
// 与系统设置不同，数据表数量多、列多，且大量关键字段被模型用 `json:"-"` 隐藏
// （users.password_hash / mfas.secret / passkeys.public_key / sessions.id …）。
// 若沿模型序列化，这些字段会**静默丢失**：备份看起来成功，恢复后却登不上、
// 通行密钥失效。因此这里按列原样搬运，不做任何字段映射：
//   - 导出：SELECT * 取原始列值，按「列名 → 值」写成 JSON 对象；
//   - 恢复：按主键覆盖（先删后插、按块批量），且只增改不删除。
//
// 只有三类值需要编码，避免 JSON 往返丢类型：
//   - 时间   → {"$time": RFC3339Nano}
//   - 二进制 → {"$bytes": base64}
//   - 其余标量原样写入；整数用 json.Number 解析回 int64，避免大整数退化成 float64。

const (
	// backupDumpChunk 是导出时每批读取的行数：大表按主键翻页写入，不整表驻留内存。
	backupDumpChunk = 2000
	// backupLoadChunk 是恢复时每批写入的行数。
	// 上限受 SQL 参数个数约束（500 行 × 十余列 ≈ 数千个参数，远低于各方言上限）。
	backupLoadChunk = 500
)

// backupDataTable 描述一张参与备份的数据表。
type backupDataTable struct {
	// Group 所属分组（settings 走另一条有结构的路径，不在这里）。
	Group string
	// Name 表名，同时是 ZIP 条目名与回执里的键。
	Name string
	// PK 主键列名：导出按它翻页，恢复按它覆盖。
	PK string
	// UserColumn 非空表示该表按用户归属（users 表用主键本身）。
	// 恢复时跳过属于当前登录管理员的行：否则一次误恢复就会把执行者的
	// 账号密码、通行密钥或会话覆盖成备份里的旧值，等于把自己锁在门外。
	UserColumn string
}

// backupDataTables 是全部参与备份的数据表（顺序即导出顺序）。
//
// 覆盖除内部表（schema_migrations）之外的每一张业务表，包括常被忽略但
// 恢复后必须存在的关联数据：绑定关系、通行密钥、MFA 密钥、会话与令牌、
// 授权记录、文件元数据。
var backupDataTables = []backupDataTable{
	{Group: groupUsers, Name: "users", PK: "id", UserColumn: "id"},
	{Group: groupUsers, Name: "identities", PK: "id", UserColumn: "user_id"},
	{Group: groupUsers, Name: "passkeys", PK: "id", UserColumn: "user_id"},
	{Group: groupUsers, Name: "mfas", PK: "id", UserColumn: "user_id"},
	{Group: groupUsers, Name: "trusted_devices", PK: "id", UserColumn: "user_id"},
	{Group: groupUsers, Name: "devices", PK: "id", UserColumn: "user_id"},
	{Group: groupUsers, Name: "notification_preferences", PK: "user_id", UserColumn: "user_id"},
	{Group: groupUsers, Name: "account_deletion_requests", PK: "id", UserColumn: "user_id"},

	{Group: groupSessions, Name: "sessions", PK: "id", UserColumn: "user_id"},
	{Group: groupSessions, Name: "tokens", PK: "id", UserColumn: "user_id"},
	{Group: groupSessions, Name: "authorization_codes", PK: "code", UserColumn: "user_id"},
	{Group: groupSessions, Name: "device_authorizations", PK: "device_code", UserColumn: "user_id"},
	{Group: groupSessions, Name: "mfa_challenges", PK: "id", UserColumn: "user_id"},
	{Group: groupSessions, Name: "verification_codes", PK: "id"},

	{Group: groupEvents, Name: "events", PK: "id", UserColumn: "user_id"},
	{Group: groupEvents, Name: "notifications", PK: "id", UserColumn: "user_id"},

	{Group: groupOAuth, Name: "grants", PK: "id", UserColumn: "user_id"},
}

// backupTableResult 是单张表的恢复回执。
type backupTableResult struct {
	Table    string `json:"table"`
	Inserted int    `json:"inserted"`
	Updated  int    `json:"updated"`
	// Skipped 是「属于当前登录管理员而被跳过」的行数。
	Skipped int `json:"skipped"`
}

// dumpTableToZip 把整张表按主键翻页导出为 ZIP 条目 data/<table>.json（JSON 数组）。
func dumpTableToZip(ctx context.Context, db *bun.DB, zw *zip.Writer, t backupDataTable) (int, error) {
	w, err := zw.Create(backupDataPrefix + t.Name + ".json")
	if err != nil {
		return 0, err
	}
	d := db.Dialect().Name()
	table, pk := backupIdent(d, t.Name), backupIdent(d, t.PK)
	if _, err := io.WriteString(w, "["); err != nil {
		return 0, err
	}

	total := 0
	var last any
	for {
		query := "SELECT * FROM " + table
		var args []any
		if last != nil {
			query += " WHERE " + pk + " > " + backupPlaceholder(d, 1)
			args = append(args, last)
		}
		query += " ORDER BY " + pk + " LIMIT " + strconv.Itoa(backupDumpChunk)

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return total, err
		}
		cols, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			return total, err
		}
		batch, lastPK, err := scanBackupRows(rows, cols, t.PK)
		_ = rows.Close()
		if err != nil {
			return total, err
		}

		for _, row := range batch {
			encoded, err := json.Marshal(row)
			if err != nil {
				return total, err
			}
			if total > 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return total, err
				}
			}
			if _, err := w.Write(encoded); err != nil {
				return total, err
			}
			total++
		}
		if len(batch) < backupDumpChunk {
			break
		}
		last = lastPK
	}
	if _, err := io.WriteString(w, "]"); err != nil {
		return total, err
	}
	return total, nil
}

// scanBackupRows 读一页行，返回「列名 → 待 JSON 化的值」与最后一行的主键。
func scanBackupRows(rows *sql.Rows, cols []string, pk string) ([]map[string]any, any, error) {
	var out []map[string]any
	var lastPK any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = backupEncodeValue(vals[i])
			if c == pk {
				lastPK = vals[i]
			}
		}
		out = append(out, row)
	}
	return out, lastPK, rows.Err()
}

// loadTableFromZip 流式读取 data/<table>.json 并写库。
//
// 逐行解码 + 分块写入：数据表可能很大（events 动辄十万行），整体 Unmarshal
// 会把整张表读进内存。合并语义是「按主键覆盖」——备份里有的行写入，库里多出来的
// 行保留，因此用一份旧备份恢复不会删掉备份之后新增的数据。
func loadTableFromZip(ctx context.Context, tx bun.Tx, t backupDataTable, r io.Reader, currentUserID int64) (backupTableResult, error) {
	res := backupTableResult{Table: t.Name}
	known, err := tableColumns(ctx, tx, t.Name)
	if err != nil {
		return res, err
	}
	if len(known) == 0 {
		return res, fmt.Errorf("backup: table %s does not exist in the target database", t.Name)
	}

	dec := json.NewDecoder(r)
	// 整数用 Number 保留精度：默认的 float64 会把 int64 主键变成浮点，
	// 写回时在 PostgreSQL 上会因类型不匹配报错。
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return res, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return res, fmt.Errorf("backup: entry %s is not a JSON array", t.Name)
	}

	chunk := make([]map[string]any, 0, backupLoadChunk)
	for dec.More() {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			return res, err
		}
		row := decodeBackupRow(raw, known, t, currentUserID)
		if row == nil {
			res.Skipped++
			continue
		}
		chunk = append(chunk, row)
		if len(chunk) >= backupLoadChunk {
			if err := writeBackupRows(ctx, tx, t, chunk, &res); err != nil {
				return res, err
			}
			chunk = chunk[:0]
		}
	}
	if len(chunk) > 0 {
		if err := writeBackupRows(ctx, tx, t, chunk, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// decodeBackupRow 把备份里的一行转成可直接写库的值。
// 返回 nil 表示该行需要跳过（属于当前用户，或缺少主键）。
func decodeBackupRow(raw map[string]any, known []string, t backupDataTable, currentUserID int64) map[string]any {
	if t.UserColumn != "" {
		if owner, ok := backupOwnerID(raw[t.UserColumn]); ok && owner == currentUserID {
			return nil
		}
	}
	row := make(map[string]any, len(known))
	for _, c := range known {
		v, ok := raw[c]
		if !ok {
			// 备份里没有这一列（更早版本导出的文件）：留空，由目标表的默认值接管。
			continue
		}
		row[c] = backupDecodeValue(v)
	}
	if _, ok := row[t.PK]; !ok {
		return nil
	}
	return row
}

// writeBackupRows 按主键覆盖一块行：先统计已存在的行数（作为「更新」计数），
// 再删掉这些主键，然后整块插入。
func writeBackupRows(ctx context.Context, tx bun.Tx, t backupDataTable, chunk []map[string]any, res *backupTableResult) error {
	d := tx.Dialect().Name()
	table, pkIdent := backupIdent(d, t.Name), backupIdent(d, t.PK)

	ids := make([]any, 0, len(chunk))
	for _, row := range chunk {
		ids = append(ids, row[t.PK])
	}
	holders := make([]string, len(ids))
	for i := range ids {
		holders[i] = backupPlaceholder(d, i+1)
	}
	inClause := "(" + strings.Join(holders, ",") + ")"

	var existing int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM "+table+" WHERE "+pkIdent+" IN "+inClause, ids...).Scan(&existing); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM "+table+" WHERE "+pkIdent+" IN "+inClause, ids...); err != nil {
		return err
	}

	// 列集合取本块各行的并集：备份里缺失的列写 NULL（该行没有值），
	// 这样即使文件来自更早的版本、少了几列，恢复也能继续。
	var cols []string
	seen := make(map[string]bool, len(chunk))
	for _, row := range chunk {
		for c := range row {
			if !seen[c] {
				seen[c] = true
				cols = append(cols, c)
			}
		}
	}
	if !seen[t.PK] {
		return fmt.Errorf("backup: chunk of table %s has no primary key %s", t.Name, t.PK)
	}

	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = backupIdent(d, c)
	}
	args := make([]any, 0, len(cols)*len(chunk))
	tuples := make([]string, 0, len(chunk))
	n := 0
	for _, row := range chunk {
		ph := make([]string, len(cols))
		for i, c := range cols {
			n++
			ph[i] = backupPlaceholder(d, n)
			args = append(args, row[c])
		}
		tuples = append(tuples, "("+strings.Join(ph, ",")+")")
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO "+table+" ("+strings.Join(quoted, ",")+") VALUES "+strings.Join(tuples, ","), args...); err != nil {
		return err
	}

	res.Inserted += len(chunk) - existing
	res.Updated += existing
	return nil
}

// tableColumns 读取目标表的列清单。
// 用 `SELECT * … WHERE 1 = 0` 取元数据：三种方言都支持，也避免依赖
// information_schema 的方言差异（列名顺序与 SELECT * 一致）。
func tableColumns(ctx context.Context, tx bun.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT * FROM "+backupIdent(tx.Dialect().Name(), table)+" WHERE 1 = 0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return rows.Columns()
}

// backupEncodeValue 把数据库原始值转成可 JSON 往返的形式。
func backupEncodeValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case time.Time:
		return map[string]any{"$time": x.Format(time.RFC3339Nano)}
	case []byte:
		// 驱动对 TEXT 列也可能返回 []byte：能按 UTF-8 解析的按字符串写，
		// 其余（真正的 BLOB，如通行密钥公钥）用 base64 包裹，避免往返损坏。
		if utf8.Valid(x) {
			return string(x)
		}
		return map[string]any{"$bytes": base64.StdEncoding.EncodeToString(x)}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64,
		float32, float64, bool, string:
		return x
	default:
		// 兜底：其它驱动类型（如自定义 Decimal）转字符串，至少不丢内容。
		return fmt.Sprint(v)
	}
}

// backupDecodeValue 把备份里的 JSON 值还原成可写入数据库的 Go 值。
func backupDecodeValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if s, ok := x["$time"].(string); ok {
			if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
				return ts
			}
			return s
		}
		if s, ok := x["$bytes"].(string); ok {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return nil
			}
			return b
		}
		// 其余对象：按 JSON 文本写回（bun 的 type:json 列就是这样存的）。
		if encoded, err := json.Marshal(x); err == nil {
			return string(encoded)
		}
		return nil
	case []any:
		if encoded, err := json.Marshal(x); err == nil {
			return string(encoded)
		}
		return nil
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	default:
		return x
	}
}

// backupOwnerID 从 JSON 值里取用户 ID：整数、数字字符串都接受。
func backupOwnerID(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case float64:
		return int64(x), true
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, true
		}
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// backupIdent 按方言引用标识符。
// 输入只来自数据库自身的列清单或本文件的编译期字面量（不含外部输入），
// 这里按方言加引号，避免与保留字（key / read / type / session …）冲突。
func backupIdent(d dialect.Name, name string) string {
	if d == dialect.MySQL {
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// backupPlaceholder 生成第 i 个（从 1 开始）参数占位符：PostgreSQL 用 $N，其余用 ?。
func backupPlaceholder(d dialect.Name, i int) string {
	if d == dialect.PG {
		return "$" + strconv.Itoa(i)
	}
	return "?"
}
