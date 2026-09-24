package timezone

import (
	"testing"
	"time"
)

func TestResolveDefault(t *testing.T) {
	z, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve(\"\") 失败: %v", err)
	}
	if z.Name != DefaultName {
		t.Fatalf("默认时区应为 %s，实际 %s", DefaultName, z.Name)
	}
	if z.OffsetMinutes != 8*60 {
		t.Fatalf("默认时区偏移应为 +480 分钟，实际 %d", z.OffsetMinutes)
	}
}

func TestResolveUTC(t *testing.T) {
	z, err := Resolve("UTC")
	if err != nil {
		t.Fatalf("Resolve(UTC) 失败: %v", err)
	}
	if z.OffsetMinutes != 0 {
		t.Fatalf("UTC 偏移应为 0，实际 %d", z.OffsetMinutes)
	}
}

func TestResolveInvalid(t *testing.T) {
	if _, err := Resolve("Not/AZone"); err == nil {
		t.Fatal("非法时区名应当返回错误")
	}
}

func TestApplyUpdatesLocal(t *testing.T) {
	orig := time.Local
	t.Cleanup(func() { time.Local = orig })

	z, err := Apply("Asia/Shanghai")
	if err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if !Loaded() {
		t.Fatal("Apply 之后 Loaded 应为 true")
	}
	if Name() != z.Name {
		t.Fatalf("Name 应为 %s，实际 %s", z.Name, Name())
	}
	if time.Local.String() != z.Location.String() {
		t.Fatalf("time.Local 未同步为系统时区: %s", time.Local)
	}
	if got := Now().Location().String(); got != z.Location.String() {
		t.Fatalf("Now 应返回系统时区时间，实际所在时区 %s", got)
	}
}

func TestApplyHourlyZone(t *testing.T) {
	// 半时区（UTC+09:30）用于验证非整点偏移也能正确计算。
	z, err := Resolve("Australia/Adelaide")
	if err != nil {
		t.Skipf("环境缺少 tzdata，跳过: %v", err)
	}
	if z.OffsetMinutes != 9*60+30 && z.OffsetMinutes != 10*60+30 {
		t.Fatalf("阿德莱德偏移异常: %d", z.OffsetMinutes)
	}
}

func TestOffsetLabel(t *testing.T) {
	orig := time.Local
	t.Cleanup(func() { time.Local = orig })
	if _, err := Apply("Asia/Shanghai"); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if got := OffsetLabel(); got != "UTC+08:00" {
		t.Fatalf("偏移标签应为 UTC+08:00，实际 %s", got)
	}
}

func TestDayBoundaries(t *testing.T) {
	orig := time.Local
	t.Cleanup(func() { time.Local = orig })
	if _, err := Apply("Asia/Shanghai"); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	// UTC 2026-01-01T17:00Z == 上海 2026-01-02T01:00
	tm := time.Date(2026, 1, 1, 17, 0, 0, 0, time.UTC)
	start := StartOfDay(tm)
	if start.Format("2006-01-02 15:04:05") != "2026-01-02 00:00:00" {
		t.Fatalf("日界应为上海 2026-01-02 00:00:00，实际 %s", start.Format("2006-01-02 15:04:05"))
	}
	if next := StartOfNextDay(tm); next.Sub(start) != 24*time.Hour {
		t.Fatalf("次日零点与当日零点应相差 24 小时，实际 %s", next.Sub(start))
	}
}
