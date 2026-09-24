package logging

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 文件日志测试。
//
// 覆盖：目录创建、日志落盘、按大小切分、过期清理、不可写目录降级、
// 敏感信息不落盘、文件名日期解析。
// ---------------------------------------------------------------------------

// captureStderr 在 fn 执行期间把 os.Stderr 替换为管道，返回期间写往终端的内容。
//
// 必须在 Init 之前替换：Init 内部会把当时的 os.Stderr 作为 tee 的终端输出目标，
// 之后替换无效。这样即可同时验证「终端仍输出」与「文件已落盘」。
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prev := os.Stderr
	prevOut := log.Writer()
	os.Stderr = w
	// 必须在替换 os.Stderr 之后重设：log 持有的是写入器引用，
	// 替换变量不会改变它已经保存的目标。
	log.SetOutput(w)

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	os.Stderr = prev
	log.SetOutput(prevOut)
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// resetLog 把标准库 log 恢复为默认输出（当前的 os.Stderr），
// 消除其它测试通过 Init 设置的 tee 残留影响。
func resetLog() { log.SetOutput(os.Stderr) }

func TestInitCreatesLogDirAndWritesFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	var closeFn func()
	var initErr error

	stderrOut := captureStderr(t, func() {
		closeFn, initErr = Init(Options{Dir: dir, Enabled: true, RetentionDays: 7, MaxSizeMB: 1})
		if initErr == nil {
			log.Printf("hello-from-test")
			closeFn()
		}
	})

	if initErr != nil {
		t.Fatalf("Init: %v", initErr)
	}

	// 终端仍有输出（保证 docker logs / kubectl logs 可用）
	if !strings.Contains(stderrOut, "hello-from-test") {
		t.Errorf("终端应保留日志输出，实际: %q", stderrOut)
	}

	// 文件应已创建并写入
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取日志目录: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("应有 1 个日志文件，实际 %d", len(entries))
	}
	content, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("读取日志: %v", err)
	}
	if !strings.Contains(string(content), "hello-from-test") {
		t.Errorf("日志文件未包含写入内容: %q", content)
	}
}

func TestInitDisabledWritesNoFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	resetLog() // Init(Enabled:false) 不改动输出目标，需先恢复默认才能捕获

	stderrOut := captureStderr(t, func() {
		cf, err := Init(Options{Dir: dir, Enabled: false})
		if err != nil {
			t.Errorf("Init: %v", err)
			return
		}
		_ = cf
		log.Printf("should-not-persist")
		cf()
	})

	if !strings.Contains(stderrOut, "should-not-persist") {
		t.Error("关闭文件日志后，终端输出仍应正常")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("关闭文件日志时不应创建日志目录")
	}
}

// TestInitUnwritableDirDegradesGracefully 日志目录不可写时必须返回错误，
// 且调用方据此降级——绝不能让服务因日志起不来。
func TestInitUnwritableDirDegradesGracefully(t *testing.T) {
	resetLog() // 初始化失败时不改动输出目标，需先恢复默认才能捕获
	// 用一个文件路径充当"目录"，MkdirAll 必定失败
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("准备阻塞文件: %v", err)
	}
	badDir := filepath.Join(blocker, "log")

	closeFn, err := Init(Options{Dir: badDir, Enabled: true})
	if err == nil {
		t.Fatal("目录不可写时应返回错误")
	}
	// 出错时 closeFn 应可安全调用
	closeFn()

	stderrOut := captureStderr(t, func() { log.Printf("still-works") })
	if !strings.Contains(stderrOut, "still-works") {
		t.Error("日志初始化失败后，终端输出仍应正常")
	}
	// 还原标准输出，避免影响其他测试
	log.SetOutput(os.Stderr)
}

func TestSensitiveDoesNotWriteFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	var closeFn func()
	captureStderr(t, func() {
		cf, err := Init(Options{Dir: dir, Enabled: true, RetentionDays: 7, MaxSizeMB: 1})
		if err != nil {
			t.Errorf("Init: %v", err)
			return
		}
		closeFn = cf
		// 普通日志落盘，敏感日志只出终端
		log.Printf("normal-line")
		Sensitive("sensitive-line-123456")
		closeFn()
	})
	log.SetOutput(os.Stderr)

	entries, _ := os.ReadDir(dir)
	var all []byte
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		all = append(all, b...)
	}
	if !strings.Contains(string(all), "normal-line") {
		t.Error("普通日志应写入文件")
	}
	if strings.Contains(string(all), "sensitive-line-123456") {
		t.Error("敏感信息不应写入日志文件")
	}
}

// TestRotateBySize 单文件超过上限时应切分出新文件。
func TestRotateBySize(t *testing.T) {
	dir := t.TempDir()
	w := &fileWriter{dir: dir, maxSize: 512, retention: 1} // 512B 便于触发
	defer w.Close()

	payload := strings.Repeat("x", 200)
	for i := 0; i < 6; i++ {
		if _, err := w.Write([]byte(payload + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	w.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("超出大小上限后应切分多个文件，实际 %d", len(entries))
	}
}

func TestCleanupRemovesExpiredFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	fresh := filePrefix + now.Format(dateLayout) + ".log"
	old := filePrefix + now.AddDate(0, 0, -30).Format(dateLayout) + ".log"
	for _, n := range []string{fresh, old, "unrelated.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}

	w := &fileWriter{dir: dir, maxSize: 1 << 20, retention: 7}
	w.cleanup(now)

	if _, err := os.Stat(filepath.Join(dir, fresh)); err != nil {
		t.Error("当天的日志不应被清理")
	}
	if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Error("超过保留天数的日志应被清理")
	}
	if _, err := os.Stat(filepath.Join(dir, "unrelated.txt")); err != nil {
		t.Error("不应删除非本项目命名的文件")
	}
}

func TestParseDay(t *testing.T) {
	cases := map[string]string{
		"openidp-2026-09-05.log":    "2026-09-05",
		"openidp-2026-09-05.1.log":  "2026-09-05",
		"openidp-2026-09-05.12.log": "2026-09-05",
		"openidp-bad-name.log":      "",
		"other-2026-09-05.log":      "",
	}
	for name, want := range cases {
		if got := parseDay(name); got != want {
			t.Errorf("parseDay(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestLogFilePermissions 日志文件应仅限属主读写，避免同机其他用户读取。
func TestLogFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	var initErr error
	captureStderr(t, func() {
		cf, err := Init(Options{Dir: dir, Enabled: true, RetentionDays: 7, MaxSizeMB: 1})
		initErr = err
		if err == nil {
			log.Printf("perm-check")
			cf()
		}
	})
	log.SetOutput(os.Stderr)
	if initErr != nil {
		t.Fatalf("Init: %v", initErr)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Fatal("未生成日志文件")
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("日志文件权限 = %o, want 600", perm)
	}
}

func TestListLogFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.log"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ListLogFiles(dir)
	if err != nil {
		t.Fatalf("ListLogFiles: %v", err)
	}
	if len(got) != 1 || got[0] != "a.log" {
		t.Errorf("ListLogFiles = %v, want [a.log]", got)
	}
	// 目录不存在时应返回空而非报错
	missing, err := ListLogFiles(filepath.Join(dir, "nope"))
	if err != nil || len(missing) != 0 {
		t.Errorf("目录不存在时应返回 (nil, nil)，实际 (%v, %v)", missing, err)
	}
}
