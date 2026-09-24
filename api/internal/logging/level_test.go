package logging

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 日志级别与分类日志测试。
// ---------------------------------------------------------------------------

// capture 在 fn 执行期间接管 log 输出，返回期间产生的日志文本。
func capture(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(w)
	log.SetFlags(0) // 去掉时间戳，便于精确断言

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	log.SetOutput(prevOut)
	log.SetFlags(prevFlags)
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug":   LevelDebug,
		"DEBUG":   LevelDebug,
		"info":    LevelInfo,
		"":        LevelInfo,
		"warn":    LevelWarn,
		"warning": LevelWarn,
		"error":   LevelError,
		"off":     LevelOff,
		"none":    LevelOff,
		"bogus":   LevelInfo, // 无法识别时回落到 info
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestLevelFiltering 低于当前级别的日志必须被丢弃。
func TestLevelFiltering(t *testing.T) {
	defer SetLevel(LevelInfo)

	SetLevel(LevelWarn)
	out := capture(t, func() {
		Debug("dbg")
		Info("inf")
		Warn("wrn")
		Error("err")
	})
	if strings.Contains(out, "dbg") || strings.Contains(out, "inf") {
		t.Errorf("warn 级别下不应输出 debug/info，实际: %q", out)
	}
	if !strings.Contains(out, "wrn") || !strings.Contains(out, "err") {
		t.Errorf("warn 级别下应输出 warn/error，实际: %q", out)
	}

	SetLevel(LevelError)
	out = capture(t, func() {
		Warn("wrn2")
		Error("err2")
	})
	if strings.Contains(out, "wrn2") {
		t.Errorf("error 级别下不应输出 warn，实际: %q", out)
	}
	if !strings.Contains(out, "err2") {
		t.Errorf("error 级别下应输出 error，实际: %q", out)
	}
}

// TestOffLevelSilencesAll off 级别应静音所有分级日志。
func TestOffLevelSilencesAll(t *testing.T) {
	defer SetLevel(LevelInfo)
	SetLevel(LevelOff)
	out := capture(t, func() {
		Debug("d")
		Info("i")
		Warn("w")
		Error("e")
	})
	if strings.TrimSpace(out) != "" {
		t.Errorf("off 级别下不应有任何输出，实际: %q", out)
	}
}

func TestLevelLabelPrefix(t *testing.T) {
	defer SetLevel(LevelInfo)
	SetLevel(LevelDebug)
	out := capture(t, func() { Info("hello") })
	if !strings.Contains(out, "[INFO]") {
		t.Errorf("日志应带级别标签，实际: %q", out)
	}
}

func TestGetSetLevel(t *testing.T) {
	defer SetLevel(LevelInfo)
	SetLevel(LevelWarn)
	if GetLevel() != LevelWarn {
		t.Errorf("GetLevel() = %v, want %v", GetLevel(), LevelWarn)
	}
}

// TestAccessLog 访问日志应包含方法、路径、状态码与耗时。
func TestAccessLog(t *testing.T) {
	defer SetLevel(LevelInfo)
	SetLevel(LevelInfo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/profile", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	req.Header.Set("User-Agent", "Mozilla/5.0 TestAgent")

	out := capture(t, func() {
		Access(req, 200, 1234, 15*time.Millisecond)
	})
	for _, want := range []string{"[ACCESS]", "GET", "/api/v1/me/profile", "200", "1234B", "203.0.113.7"} {
		if !strings.Contains(out, want) {
			t.Errorf("访问日志缺少 %q，实际: %q", want, out)
		}
	}
}

// TestAccessLogExcludesQueryValues 访问日志不得记录查询串中的值
// （可能含 token、邮箱等敏感信息）。
func TestAccessLogExcludesQueryValues(t *testing.T) {
	defer SetLevel(LevelInfo)
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token=SUPERSECRETTOKEN", nil)
	out := capture(t, func() {
		Access(req, 200, 10, time.Millisecond)
	})
	if strings.Contains(out, "SUPERSECRETTOKEN") {
		t.Errorf("访问日志不应包含查询串中的敏感值，实际: %q", out)
	}
}

// TestAuditLog 审计日志应包含结果、分类、动作、用户与 IP。
func TestAuditLog(t *testing.T) {
	defer SetLevel(LevelInfo)
	out := capture(t, func() {
		Audit("success", "auth", "password_login", 42, "203.0.113.9", "用户名=alice")
	})
	for _, want := range []string{"[AUDIT]", "result=success", "category=auth", "action=password_login", "userID=42", "203.0.113.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("审计日志缺少 %q，实际: %q", want, out)
		}
	}
}

// TestConfigChangeLog 配置变更日志应记录范围与字段名。
func TestConfigChangeLog(t *testing.T) {
	defer SetLevel(LevelInfo)
	out := capture(t, func() {
		ConfigChange("security-policy", "update", 7, "203.0.113.1", []string{"signupEnabled", "minPasswordLength"})
	})
	for _, want := range []string{"[CONFIG]", "scope=security-policy", "action=update", "userID=7", "signupEnabled", "minPasswordLength"} {
		if !strings.Contains(out, want) {
			t.Errorf("配置变更日志缺少 %q，实际: %q", want, out)
		}
	}
}

// TestAccessLogRespectsLevel 访问/审计/配置日志同样受级别控制。
func TestAccessLogRespectsLevel(t *testing.T) {
	defer SetLevel(LevelInfo)
	SetLevel(LevelError)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	out := capture(t, func() {
		Access(req, 200, 1, time.Millisecond)
		Audit("success", "auth", "x", 1, "1.2.3.4", "")
		ConfigChange("site", "update", 1, "1.2.3.4", []string{"a"})
	})
	if strings.TrimSpace(out) != "" {
		t.Errorf("error 级别下分类日志不应输出，实际: %q", out)
	}
}

// TestSensitivefRespectsLevel 敏感日志也应按级别过滤。
func TestSensitivefRespectsLevel(t *testing.T) {
	defer SetLevel(LevelInfo)
	SetLevel(LevelError)
	out := capture(t, func() {
		Sensitivef("code=%s", "123456")
	})
	if strings.Contains(out, "123456") {
		t.Errorf("error 级别下敏感日志不应输出，实际: %q", out)
	}
}

// TestAccessLogTruncatesUA 超长 UA 必须截断，避免单条日志过大。
func TestAccessLogTruncatesUA(t *testing.T) {
	defer SetLevel(LevelInfo)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("User-Agent", strings.Repeat("A", 500))
	out := capture(t, func() {
		Access(req, 200, 1, time.Millisecond)
	})
	if strings.Count(out, "A") > 130 {
		t.Errorf("UA 应被截断，实际长度过大: %d", strings.Count(out, "A"))
	}
}
