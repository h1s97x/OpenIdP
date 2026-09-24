package logging

import (
	"log"

	"strings"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// 日志级别
//
// 用法与标准库 log 一致，只是多了一层级别判断：低于当前级别的调用会被丢弃。
// 级别可通过 OPENIDP_LOG_LEVEL 配置（debug / info / warn / error，默认 info）。
// ---------------------------------------------------------------------------

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	// LevelOff 关闭所有输出（仍保留 Fatalf，否则进程无法报告致命错误）
	LevelOff Level = 100
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "OFF"
	}
}

// ParseLevel 解析级别名，无法识别时返回 LevelInfo。
// 允许 debug/info/warn/error/off，大小写不敏感。
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info", "":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "off", "none":
		return LevelOff
	default:
		return LevelInfo
	}
}

// currentLevel 以原子方式保存，便于运行期调整（如管理后台热更新）。
var currentLevel atomic.Int32

func init() {
	currentLevel.Store(int32(LevelInfo))
}

// SetLevel 设置当前日志级别。
func SetLevel(l Level) { currentLevel.Store(int32(l)) }

// GetLevel 返回当前日志级别。
func GetLevel() Level { return Level(currentLevel.Load()) }

// enabled 判断给定级别是否应当输出。
func enabled(l Level) bool { return l >= GetLevel() }

// prefix 返回日志前缀（级别标签）。
func prefix(l Level) string { return "[" + l.String() + "] " }

// Debug 输出调试级日志（默认不输出，需 OPENIDP_LOG_LEVEL=debug）。
func Debug(format string, args ...any) {
	if !enabled(LevelDebug) {
		return
	}
	log.Printf(prefix(LevelDebug)+format, args...)
}

// Info 输出信息级日志（默认级别）。
func Info(format string, args ...any) {
	if !enabled(LevelInfo) {
		return
	}
	log.Printf(prefix(LevelInfo)+format, args...)
}

// Warn 输出告警级日志。
func Warn(format string, args ...any) {
	if !enabled(LevelWarn) {
		return
	}
	log.Printf(prefix(LevelWarn)+format, args...)
}

// Error 输出错误级日志。
func Error(format string, args ...any) {
	if !enabled(LevelError) {
		return
	}
	log.Printf(prefix(LevelError)+format, args...)
}

// Fatal 输出致命错误并退出进程。
// 不受级别限制：进程终止必须留下原因，否则排障无从下手。
func Fatal(format string, args ...any) {
	log.Fatalf(prefix(LevelError)+format, args...)
}

// Sensitive 输出不应写入日志文件的敏感信息（如邮箱验证码）。
// 同 logging.Sensitive，这里按级别过滤后转发。
func Sensitivef(format string, args ...any) {
	if !enabled(LevelInfo) {
		return
	}
	Sensitive(format, args...)
}
