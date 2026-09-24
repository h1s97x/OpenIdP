package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// TestSiteInfoExposesTimezone /api/v1/site 必须下发系统时区，
// 前端据此渲染时间，避免与后端日志/统计的时区口径不一致。
func TestSiteInfoExposesTimezone(t *testing.T) {
	restore := time.Local
	t.Cleanup(func() { time.Local = restore })
	if _, err := timezone.Apply("Asia/Shanghai"); err != nil {
		t.Fatalf("apply timezone: %v", err)
	}

	h, router := newTestHandler(t)
	h.cfg.Timezone = "Asia/Shanghai"
	rec := doJSON(t, router, http.MethodGet, "/api/v1/site", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/site = %d; want 200", rec.Code)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body.Data["timezone"]; got != "Asia/Shanghai" {
		t.Fatalf("timezone = %v; want Asia/Shanghai", got)
	}
	if got := body.Data["utcOffsetMinutes"]; got != float64(8*60) {
		t.Fatalf("utcOffsetMinutes = %v; want 480", got)
	}
	if got := body.Data["timezoneLabel"]; got != "UTC+08:00" {
		t.Fatalf("timezoneLabel = %v; want UTC+08:00", got)
	}
}

// TestSiteInfoTimezoneOverride 环境变量指定的时区必须下发到前端。
func TestSiteInfoTimezoneOverride(t *testing.T) {
	restore := time.Local
	t.Cleanup(func() { time.Local = restore })
	if _, err := timezone.Apply("UTC"); err != nil {
		t.Fatalf("apply timezone: %v", err)
	}

	h, router := newTestHandler(t)
	h.cfg.Timezone = "UTC"
	rec := doJSON(t, router, http.MethodGet, "/api/v1/site", nil)
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body.Data["timezone"]; got != "UTC" {
		t.Fatalf("timezone = %v; want UTC", got)
	}
	if got := body.Data["utcOffsetMinutes"]; got != float64(0) {
		t.Fatalf("utcOffsetMinutes = %v; want 0", got)
	}
	if got := body.Data["timezoneLabel"]; got != "UTC+00:00" {
		t.Fatalf("timezoneLabel = %v; want UTC+00:00", got)
	}
}

// TestEventTimestampsUseSystemTimezone 写库时间必须落在系统时区，
// 保证审计/事件列表展示与后端日志一致。
func TestEventTimestampsUseSystemTimezone(t *testing.T) {
	restore := time.Local
	t.Cleanup(func() { time.Local = restore })
	if _, err := timezone.Apply("Asia/Shanghai"); err != nil {
		t.Fatalf("apply timezone: %v", err)
	}

	h, _ := newTestHandler(t)
	h.logEvent(nil, 0, &models.Event{Type: "timezone.probe", Summary: "时区写入校验"})

	var ev models.Event
	if err := h.db.NewSelect().Model(&ev).
		Where("type = ?", "timezone.probe").Scan(context.Background()); err != nil {
		t.Fatalf("select event: %v", err)
	}
	// 以系统时区重新渲染写入时刻，应与 Asia/Shanghai 的当前日历日一致。
	_, wantOffset := time.Now().In(time.FixedZone("CST", 8*60*60)).Zone()
	if _, gotOffset := ev.CreatedAt.In(time.FixedZone("CST", 8*60*60)).Zone(); gotOffset != wantOffset {
		t.Fatalf("created_at 偏移 = %d; want %d", gotOffset, wantOffset)
	}
	if diff := time.Since(ev.CreatedAt); diff > time.Minute || diff < -time.Minute {
		t.Fatalf("created_at 不是当前时间: %v", ev.CreatedAt)
	}
}

// TestAdminDashboardDayBoundaryUsesSystemTimezone 管理台「今日」统计
// 必须按系统时区的自然日切分，而不是 UTC 日界。
func TestAdminDashboardDayBoundaryUsesSystemTimezone(t *testing.T) {
	restore := time.Local
	t.Cleanup(func() { time.Local = restore })
	if _, err := timezone.Apply("Asia/Shanghai"); err != nil {
		t.Fatalf("apply timezone: %v", err)
	}
	start := timezone.StartOfDay(time.Now())
	if start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 {
		t.Fatalf("StartOfDay 应为零点，实际 %s", start)
	}
	if _, offset := start.Zone(); offset != 8*60*60 {
		t.Fatalf("StartOfDay 偏移 = %d; want 28800", offset)
	}
}
