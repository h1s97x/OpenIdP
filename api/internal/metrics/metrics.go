// Package stats computes user-activity and authentication analytics from the
// events and users tables. It powers the admin dashboard's richer
// visualizations (event breakdown, sign-in method distribution, user growth)
// without adding heavy charting dependencies.
package metrics

import (
	"context"
	"time"

	"github.com/uptrace/bun"

	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// Snapshot is a set of computed analytics at a point in time.
type Snapshot struct {
	GeneratedAt time.Time `json:"generatedAt"`
	// Totals are aggregate counters.
	Totals Totals `json:"totals"`
	// LoginMethods is the distribution of sign-in methods over the last 30 days.
	LoginMethods map[string]int64 `json:"loginMethods"`
	// UserGrowth is the cumulative user count per day over the last 14 days.
	UserGrowth []DayCount `json:"userGrowth"`
	// EventBreakdown is the top event types over the last 30 days.
	EventBreakdown []TypeCount `json:"eventBreakdown"`
}

// Totals holds aggregate counters.
type Totals struct {
	TotalUsers     int64 `json:"totalUsers"`
	ActiveUsers30d int64 `json:"activeUsers30d"`
	TotalEvents    int64 `json:"totalEvents"`
	TotalSessions  int64 `json:"totalSessions"`
	TotalGrants    int64 `json:"totalGrants"`
	TotalOAuthApps int64 `json:"totalOAuthApps"`
}

// DayCount is a per-day metric.
type DayCount struct {
	At    string `json:"at"`
	Count int64  `json:"count"`
}

// TypeCount is a per-type metric.
type TypeCount struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

// Compute gathers a full analytics snapshot.
func Compute(ctx context.Context, db *bun.DB) (Snapshot, error) {
	// 统计日界按系统时区切分，避免 UTC 日界让"今天"在本地时间 08:00 才重置。
	now := timezone.Now()
	thirtyDays := now.AddDate(0, 0, -30)

	var s Snapshot
	s.GeneratedAt = now

	totalUsers, err := db.NewSelect().Model((*models.User)(nil)).Count(ctx)
	if err != nil {
		return s, err
	}
	activeUsers, err := db.NewSelect().Model((*models.User)(nil)).
		Where("id IN (SELECT DISTINCT user_id FROM events WHERE created_at >= ?)", thirtyDays).
		Count(ctx)
	if err != nil {
		return s, err
	}
	totalEvents, err := db.NewSelect().Model((*models.Event)(nil)).Count(ctx)
	if err != nil {
		return s, err
	}
	totalSessions, err := db.NewSelect().Model((*models.Session)(nil)).Where("expires_at > ?", now).Count(ctx)
	if err != nil {
		return s, err
	}
	totalGrants, err := db.NewSelect().Model((*models.Grant)(nil)).Count(ctx)
	if err != nil {
		return s, err
	}
	totalApps, err := db.NewSelect().Model((*models.OAuthClient)(nil)).Count(ctx)
	if err != nil {
		return s, err
	}
	s.Totals = Totals{
		TotalUsers:     int64(totalUsers),
		ActiveUsers30d: int64(activeUsers),
		TotalEvents:    int64(totalEvents),
		TotalSessions:  int64(totalSessions),
		TotalGrants:    int64(totalGrants),
		TotalOAuthApps: int64(totalApps),
	}

	// login methods over last 30 days (login.success metadata contains method)
	s.LoginMethods = loginMethods(ctx, db, thirtyDays)

	// user growth over last 14 days
	s.UserGrowth = userGrowth(ctx, db, now)

	// event type breakdown over last 30 days
	s.EventBreakdown = eventBreakdown(ctx, db, thirtyDays)

	return s, nil
}

func loginMethods(ctx context.Context, db *bun.DB, since time.Time) map[string]int64 {
	var events []models.Event
	_ = db.NewSelect().Model(&events).Where("type = 'login.success' AND created_at >= ?", since).Scan(ctx, &events)
	out := map[string]int64{}
	for _, e := range events {
		m := e.Metadata["method"]
		if m == "" {
			m = "unknown"
		}
		out[m]++
	}
	return out
}

func userGrowth(ctx context.Context, db *bun.DB, now time.Time) []DayCount {
	out := make([]DayCount, 0, 14)
	for i := 13; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		start := timezone.StartOfDay(day)
		c, _ := db.NewSelect().Model((*models.User)(nil)).
			Where("created_at < ?", start.AddDate(0, 0, 1)).Count(ctx)
		out = append(out, DayCount{At: start.Format("2006-01-02"), Count: int64(c)})
	}
	return out
}

func eventBreakdown(ctx context.Context, db *bun.DB, since time.Time) []TypeCount {
	var events []models.Event
	_ = db.NewSelect().Model(&events).Where("created_at >= ?", since).Scan(ctx, &events)
	counts := map[string]int64{}
	for _, e := range events {
		counts[e.Type]++
	}
	out := make([]TypeCount, 0, len(counts))
	for t, c := range counts {
		out = append(out, TypeCount{Type: t, Count: c})
	}
	// sort descending by count
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Count > out[j-1].Count; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}
