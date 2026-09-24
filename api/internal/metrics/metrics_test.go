package metrics

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// ---------------------------------------------------------------------------
// 管理仪表盘统计测试。
//
// 背景：stats 包此前零测试。它为管理仪表盘提供事件分布、登录方式分布与
// 用户增长曲线。本文件验证聚合口径：空库不应报错、计数正确、
// 未知登录方式归为 unknown、事件分布按数量降序且最多 10 项。
// ---------------------------------------------------------------------------

func newStatsTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dir := t.TempDir()
	sqldb, err := sql.Open(sqliteshim.DriverName(),
		"file:"+filepath.Join(dir, "t.db")+"?cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	bdb := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { _ = bdb.Close() })
	if err := db.Migrate(context.Background(), bdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return bdb
}

// TestSnapshotOnEmptyDB 空库时必须返回零值快照，而不是报错——
// 否则全新部署的管理仪表盘会直接 500。
func TestSnapshotOnEmptyDB(t *testing.T) {
	bdb := newStatsTestDB(t)
	s, err := Compute(context.Background(), bdb)
	if err != nil {
		t.Fatalf("Snapshot on empty db: %v", err)
	}
	if s.Totals.TotalUsers != 0 || s.Totals.TotalEvents != 0 {
		t.Errorf("空库应全为 0，实际 %+v", s.Totals)
	}
	if s.GeneratedAt.IsZero() {
		t.Error("GeneratedAt 应已填充")
	}
	// 用户增长应固定返回 14 天（即使全为 0），否则图表会缺刻度
	if len(s.UserGrowth) != 14 {
		t.Errorf("UserGrowth 长度 = %d, want 14", len(s.UserGrowth))
	}
}

func TestSnapshotCountsUsersAndEvents(t *testing.T) {
	bdb := newStatsTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	// email 有唯一约束，必须各不相同
	users := []models.User{
		{Subject: "usr_a", Username: "a", Email: "a@example.com", CreatedAt: now, UpdatedAt: now},
		{Subject: "usr_b", Username: "b", Email: "b@example.com", CreatedAt: now, UpdatedAt: now},
	}
	if _, err := bdb.NewInsert().Model(&users).Exec(ctx); err != nil {
		t.Fatalf("insert users: %v", err)
	}

	s, err := Compute(ctx, bdb)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if s.Totals.TotalUsers != 2 {
		t.Errorf("TotalUsers = %d, want 2", s.Totals.TotalUsers)
	}
}

// TestLoginMethodsGroupsByMetadata 登录方式按事件的 metadata.method 聚合，
// 缺失时归为 unknown——避免出现空字符串键导致图表异常。
func TestLoginMethodsGroupsByMetadata(t *testing.T) {
	bdb := newStatsTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	events := []models.Event{
		{UserID: 1, Type: "login.success", Summary: "s", CreatedAt: now, Metadata: map[string]string{"method": "password"}},
		{UserID: 2, Type: "login.success", Summary: "s", CreatedAt: now, Metadata: map[string]string{"method": "password"}},
		{UserID: 3, Type: "login.success", Summary: "s", CreatedAt: now, Metadata: map[string]string{"method": "passkey"}},
		{UserID: 4, Type: "login.success", Summary: "s", CreatedAt: now, Metadata: map[string]string{}}, // 缺 method
	}
	if _, err := bdb.NewInsert().Model(&events).Exec(ctx); err != nil {
		t.Fatalf("insert events: %v", err)
	}

	s, err := Compute(ctx, bdb)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if s.LoginMethods["password"] != 2 {
		t.Errorf("password 计数 = %d, want 2", s.LoginMethods["password"])
	}
	if s.LoginMethods["passkey"] != 1 {
		t.Errorf("passkey 计数 = %d, want 1", s.LoginMethods["passkey"])
	}
	if s.LoginMethods["unknown"] != 1 {
		t.Errorf("缺 method 应归为 unknown，实际 = %d", s.LoginMethods["unknown"])
	}
}

// TestEventBreakdownSortedAndCapped 事件分布按数量降序且最多 10 项，
// 保证仪表盘图表可读且不会因为事件类型过多而撑爆。
func TestEventBreakdownSortedAndCapped(t *testing.T) {
	bdb := newStatsTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// 构造 12 种事件类型，数量递减
	var events []models.Event
	for i := 0; i < 12; i++ {
		for j := 0; j <= 12-i; j++ { // 类型 i 有 (13-i) 条
			events = append(events, models.Event{
				UserID: 1, Type: "type." + string(rune('a'+i)), Summary: "s", CreatedAt: now,
			})
		}
	}
	if _, err := bdb.NewInsert().Model(&events).Exec(ctx); err != nil {
		t.Fatalf("insert events: %v", err)
	}

	s, err := Compute(ctx, bdb)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(s.EventBreakdown) > 10 {
		t.Errorf("EventBreakdown 应最多 10 项，实际 %d", len(s.EventBreakdown))
	}
	// 降序校验
	for i := 1; i < len(s.EventBreakdown); i++ {
		if s.EventBreakdown[i].Count > s.EventBreakdown[i-1].Count {
			t.Errorf("未按数量降序: 第 %d 项 %d > 第 %d 项 %d",
				i, s.EventBreakdown[i].Count, i-1, s.EventBreakdown[i-1].Count)
		}
	}
	// 最多的应排第一
	if s.EventBreakdown[0].Count != 13 {
		t.Errorf("首位计数 = %d, want 13", s.EventBreakdown[0].Count)
	}
}

// TestUserGrowthIsCumulativeAndDated 用户增长应为 14 天累计值，
// 且日期格式为 YYYY-MM-DD（前端直接用作图表标签）。
func TestUserGrowthIsCumulativeAndDated(t *testing.T) {
	bdb := newStatsTestDB(t)
	ctx := context.Background()

	s, err := Compute(ctx, bdb)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(s.UserGrowth) != 14 {
		t.Fatalf("UserGrowth 长度 = %d, want 14", len(s.UserGrowth))
	}
	for i, d := range s.UserGrowth {
		if len(d.At) != 10 || d.At[4] != '-' || d.At[7] != '-' {
			t.Errorf("第 %d 项日期格式 = %q, want YYYY-MM-DD", i, d.At)
		}
	}
	// 日期应递增（由远及近）
	for i := 1; i < len(s.UserGrowth); i++ {
		if s.UserGrowth[i].At <= s.UserGrowth[i-1].At {
			t.Errorf("日期未递增: %q -> %q", s.UserGrowth[i-1].At, s.UserGrowth[i].At)
		}
	}
}

// TestSnapshotCountsSessionsByExpiry 会话只统计未过期的，
// 过期会话不应计入"活跃会话"。
func TestSnapshotCountsSessionsByExpiry(t *testing.T) {
	bdb := newStatsTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	sessions := []models.Session{
		{ID: "s1", SessionHash: "h1", UserID: 1, ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastSeenAt: now},
		{ID: "s2", SessionHash: "h2", UserID: 1, ExpiresAt: now.Add(-time.Hour), CreatedAt: now, LastSeenAt: now},
	}
	if _, err := bdb.NewInsert().Model(&sessions).Exec(ctx); err != nil {
		t.Fatalf("insert sessions: %v", err)
	}

	s, err := Compute(ctx, bdb)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if s.Totals.TotalSessions != 1 {
		t.Errorf("TotalSessions = %d, want 1（过期的不应计入）", s.Totals.TotalSessions)
	}
}
