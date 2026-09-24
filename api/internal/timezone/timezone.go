// Package timezone 统一管理系统时区。
//
// 系统所有对外呈现与按天切分的时间（后端日志、前端展示、统计日界）
// 都以系统时区为准，默认 Asia/Shanghai（UTC+8），可通过环境变量
// OPENIDP_TIMEZONE 指定任意 IANA 时区名（如 UTC、America/New_York）。
package timezone

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultName 是系统默认时区名（UTC+8）。
const DefaultName = "Asia/Shanghai"

// EnvKey 是配置系统时区的环境变量名。
const EnvKey = "TZ"

var (
	mu     sync.RWMutex
	name   = DefaultName
	loc    = time.FixedZone("CST", 8*60*60)
	loaded bool
)

// Zone 描述一个已解析的时区。
type Zone struct {
	// Name 是归属的规范时区名（IANA 名，如 Asia/Shanghai）。
	Name string
	// Location 是对应的时区对象，可直接用于 time.In / time.Local。
	Location *time.Location
	// OffsetMinutes 是当前时刻相对 UTC 的偏移分钟数。
	OffsetMinutes int
	// Label 是偏移的可读标签，如 UTC+08:00。
	Label string
}

// Resolve 解析时区名并返回时区信息。
//
// 空名称回落到默认时区；无法识别时返回错误，由调用方决定是否终止启动。
func Resolve(name string) (Zone, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = DefaultName
	}
	loc, err := load(name)
	if err != nil {
		return Zone{}, fmt.Errorf("无效的时区 %q（需为 IANA 时区名，如 %s / UTC）: %w", name, DefaultName, err)
	}
	_, offset := time.Now().In(loc).Zone()
	return Zone{Name: name, Location: loc, OffsetMinutes: offset / 60, Label: offsetLabel(offset)}, nil
}

// load 优先使用 Go 内置时区数据库，其次回退到系统时区数据库。
//
// 容器镜像通常不携带 tzdata，但只要 Go 标准库内置了该时区即可正常工作，
// 因此常见时区无需额外安装系统时区数据。
func load(name string) (*time.Location, error) {
	if loc, err := time.LoadLocation(name); err == nil {
		return loc, nil
	}
	// 兼容 UTC / GMT 这类简写
	if strings.EqualFold(name, "UTC") {
		return time.UTC, nil
	}
	// 部分环境缺少系统时区数据库，尝试从 TZDIR 显式读取时区文件后加载。
	if dir := strings.TrimSpace(os.Getenv("TZDIR")); dir != "" {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			if loc, err := time.LoadLocationFromTZData(name, data); err == nil {
				return loc, nil
			}
		}
	}
	return nil, fmt.Errorf("load location")
}

// Apply 把进程时区固定为 name，并同步 time.Local。
//
// 之后 time.Now() 返回的本地时间、标准库日志时间戳、
// 以及所有 time.In(time.Local) 的转换都会使用该系统时区。
func Apply(name string) (Zone, error) {
	z, err := Resolve(name)
	if err != nil {
		return Zone{}, err
	}
	// 设置 TZ 环境变量：子进程与依赖系统时区的库（如 libc 时间函数）同样生效。
	_ = os.Setenv(EnvKey, z.Name)
	time.Local = z.Location
	mu.Lock()
	name, loc, loaded = z.Name, z.Location, true
	mu.Unlock()
	return z, nil
}

// Name 返回当前系统时区名。
func Name() string {
	mu.RLock()
	defer mu.RUnlock()
	return name
}

// Location 返回当前系统时区对象。
func Location() *time.Location {
	mu.RLock()
	defer mu.RUnlock()
	return loc
}

// Loaded 表示是否已通过 Apply 显式初始化过。
func Loaded() bool {
	mu.RLock()
	defer mu.RUnlock()
	return loaded
}

// Now 返回系统时区下的当前时间。
//
// 业务时间统一通过它取"现在"，保证日志、展示与统计日界口径一致。
func Now() time.Time {
	return time.Now().In(Location())
}

// OffsetLabel 返回当前时区偏移的可读标签，如 UTC+08:00。
func OffsetLabel() string {
	_, offset := time.Now().In(Location()).Zone()
	return offsetLabel(offset)
}

// Format 按系统时区格式化时间，输出 RFC3339（带时区偏移）。
func Format(t time.Time) string {
	return t.In(Location()).Format(time.RFC3339)
}

// StartOfDay 返回 t 所在自然日在系统时区下的零点。
func StartOfDay(t time.Time) time.Time {
	t = t.In(Location())
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, Location())
}

// StartOfNextDay 返回 t 所在自然日的次日零点。
func StartOfNextDay(t time.Time) time.Time {
	return StartOfDay(t).AddDate(0, 0, 1)
}

// DefaultZone 返回默认时区（Asia/Shanghai）的信息，忽略任何自定义配置。
func DefaultZone() Zone {
	z, err := Resolve(DefaultName)
	if err != nil {
		// 默认时区必须可用；不可用时退回固定 +8 偏移，保证调用方无需处理错误。
		loc := time.FixedZone("CST", 8*60*60)
		return Zone{Name: DefaultName, Location: loc, OffsetMinutes: 8 * 60, Label: offsetLabel(8 * 60 * 60)}
	}
	return z
}

// ResolveOrDefault 解析时区名；无法识别时回退默认时区。
//
// 适用于「展示/下发」这类不应因配置错误中断的场景；
// 启动阶段仍应使用 Apply 以便把非法配置显式暴露出来。
func ResolveOrDefault(name string) Zone {
	z, err := Resolve(name)
	if err != nil {
		return DefaultZone()
	}
	return z
}

// offsetLabel 把 UTC 偏移秒数渲染为 UTC±hh:mm。
func offsetLabel(offset int) string {
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, offset/3600, (offset%3600)/60)
}
