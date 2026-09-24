// Package logx 提供运行日志的文件输出能力。
//
// 设计要点：
//  1. 保留 stderr 输出：容器化部署依赖 stdout/stderr 收集日志（docker logs、
//     kubectl logs），一旦只写文件就会让这些工具失效。因此文件日志是"附加"，
//     不是"替代"。
//  2. 日志失败绝不阻断启动：数据目录可能只读、磁盘可能满，此时应降级为
//     仅终端输出，而不是让服务起不来。
//  3. 敏感信息不落盘：验证码一类内容只输出终端（见 Sensitive）。
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Options 是文件日志的配置。
type Options struct {
	// Dir 是日志目录。为空表示不写文件。
	Dir string
	// Enabled 为 false 时只输出终端（用于排查日志本身引起的问题）。
	Enabled bool
	// RetentionDays 是日志保留天数，超期的文件在启动时清理。
	RetentionDays int
	// MaxSizeMB 是单个日志文件的大小上限，超出后切分为新文件。
	MaxSizeMB int
}

const (
	// 文件名前缀与日期格式：openidp-2006-01-02.log
	filePrefix = "openidp-"
	dateLayout = "2006-01-02"
)

// stderrOnly 是只写终端的 logger，用于不落盘的敏感信息。
// 沿用 log.LstdFlags 以保持与默认日志一致的时间戳格式。
var stderrOnly = log.New(os.Stderr, "", log.LstdFlags)

// Sensitive 输出不应当写入日志文件的敏感信息（如邮箱验证码）。
//
// 典型场景：未配置 SMTP 时，邮件正文（含验证码）会打到日志方便开发调试。
// 这类内容一旦落盘就等于把有效凭据留在磁盘上，因此只输出终端。
func Sensitive(format string, args ...any) {
	stderrOnly.Printf(format, args...)
}

// tee 把日志同时写给终端与文件。
// 文件写入失败时静默忽略——终端输出成功即可，绝不让日志问题影响主流程。
type tee struct {
	console  io.Writer
	logFile  *fileWriter
	fallback bool
}

func (t *tee) Write(p []byte) (int, error) {
	n, err := t.console.Write(p)
	if t.logFile != nil {
		if _, ferr := t.logFile.Write(p); ferr != nil && !t.fallback {
			// 仅提示一次，避免每条日志都重复报错
			t.fallback = true
			fmt.Fprintf(os.Stderr, "⚠️ [Log] 写入日志文件失败，后续日志仅输出到终端：%v\n", ferr)
		}
	}
	return n, err
}

// fileWriter 是按天 + 按大小切分的文件写入器，并发安全。
type fileWriter struct {
	mu        sync.Mutex
	dir       string
	retention int
	maxSize   int64

	curDay string // 当前打开的日期（dateLayout）
	seq    int    // 同一天内的切分序号
	file   *os.File
	size   int64
}

func (w *fileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.rotate(time.Now()); err != nil {
		return 0, err
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate 在日期变化或文件超限时切换到新文件。
func (w *fileWriter) rotate(now time.Time) error {
	day := now.Format(dateLayout)
	// 同一天且未超限：继续写当前文件
	if w.file != nil && w.curDay == day && w.size < w.maxSize {
		return nil
	}
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	if day != w.curDay {
		w.curDay = day
		w.seq = 0
	} else {
		// 同一天超限 → 递增序号
		w.seq++
	}

	name := filePrefix + day + ".log"
	if w.seq > 0 {
		name = fmt.Sprintf("%s%s.%d.log", filePrefix, day, w.seq)
	}
	path := filepath.Join(w.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.file = f
	// 追加模式下文件大小需从当前位置起算
	info, err := f.Stat()
	if err != nil {
		w.size = 0
	} else {
		w.size = info.Size()
	}
	return nil
}

// Close 关闭当前日志文件。
func (w *fileWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
}

// Init 初始化文件日志，把标准库 log 的输出改为「终端 + 文件」。
//
// 返回的关闭函数应在进程退出前调用，确保缓冲区内容落盘。
// 初始化失败时返回错误，调用方应记录提示后继续启动（不能因此阻断服务）。
func Init(opts Options) (func(), error) {
	if !opts.Enabled || strings.TrimSpace(opts.Dir) == "" {
		return func() {}, nil
	}
	if opts.RetentionDays <= 0 {
		opts.RetentionDays = 7
	}
	maxSize := int64(opts.MaxSizeMB) * 1024 * 1024
	if maxSize <= 0 {
		maxSize = 64 * 1024 * 1024
	}

	dir := opts.Dir
	// 0o750：属主可读写执行，同组可读——日志可能含内网 IP 等半敏感信息，
	// 不应让其他用户可读。
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return func() {}, fmt.Errorf("创建日志目录 %s: %w", dir, err)
	}
	// 目录存在但不可写时提前暴露，便于提示用户
	if err := isWritable(dir); err != nil {
		return func() {}, fmt.Errorf("日志目录 %s 不可写: %w", dir, err)
	}

	w := &fileWriter{
		dir:       dir,
		retention: opts.RetentionDays,
		maxSize:   maxSize,
	}
	// 先清理过期日志，再打开当天文件
	w.cleanup(time.Now())

	log.SetOutput(&tee{console: os.Stderr, logFile: w})
	// 日志前缀里已有时间戳，避免重复
	log.SetFlags(log.LstdFlags)

	return w.Close, nil
}

// isWritable 通过创建临时文件验证目录可写。
func isWritable(dir string) error {
	probe := filepath.Join(dir, ".write-probe")
	f, err := os.Create(probe)
	if err != nil {
		return err
	}
	_ = f.Close()
	return os.Remove(probe)
}

// cleanup 删除超过保留天数的日志文件。
// 只清理本项目命名格式的文件，避免误删同目录下的其他内容。
func (w *fileWriter) cleanup(now time.Time) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	cutoff := now.AddDate(0, 0, -w.retention).Format(dateLayout)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		// 从文件名中取出日期部分：openidp-2006-01-02[.N].log
		day := parseDay(name)
		if day == "" {
			continue
		}
		// 字符串比较即可判断日期先后（dateLayout 为定长字典序格式）
		if day < cutoff {
			_ = os.Remove(filepath.Join(w.dir, name))
		}
	}
}

// parseDay 从日志文件名中解析日期，无法识别时返回空串。
func parseDay(name string) string {
	core := strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), ".log")
	// 去掉可能的 .N 序号后缀
	if i := strings.LastIndex(core, "."); i > 0 {
		core = core[:i]
	}
	if _, err := time.Parse(dateLayout, core); err != nil {
		return ""
	}
	return core
}

// ListLogFiles 返回当前日志目录下的日志文件（按名称升序）。
// 供管理后台"系统状态"等面板展示使用。
func ListLogFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}
