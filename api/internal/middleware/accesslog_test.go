package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// 访问日志中间件测试。
//
// 重点：
//   - 启用时记录请求；禁用时不包裹 writer（零开销）
//   - 健康检查默认跳过
//   - 状态码与字节数统计正确
//   - 必须保持 http.Flusher 能力，否则 SSE / 流式下载会被缓冲
// ---------------------------------------------------------------------------

func TestAccessLogEnabledRecordsRequest(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	})

	h := AccessLog(AccessLogConfig{Enabled: true})(next)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tickets", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next 未被调用")
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("状态码 = %d, want 201", rec.Code)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("响应体 = %q, want %q", rec.Body.String(), "hello")
	}
}

func TestAccessLogDisabledPassesThrough(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := AccessLog(AccessLogConfig{Enabled: false})(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("禁用时响应应原样透传，实际 code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAccessLogSkipsHealth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := AccessLog(AccessLogConfig{Enabled: true, SkipHealth: true})(next)

	// 健康检查应正常透传（只是不记录日志）
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("健康检查状态码 = %d, want 200", rec.Code)
	}
}

func TestAccessLogSkipHealthDisabled(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// SkipHealth 关闭时健康检查也应正常处理
	h := AccessLog(AccessLogConfig{Enabled: true, SkipHealth: false})(next)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("状态码 = %d, want 200", rec.Code)
	}
}

// TestStatusRecorderTracksWrite 未显式调用 WriteHeader 时应按 200 统计。
func TestStatusRecorderTracksWrite(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	n, err := rec.Write([]byte("abcde"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("写入字节数 = %d, want 5", n)
	}
	if rec.written != 5 {
		t.Errorf("记录字节数 = %d, want 5", rec.written)
	}
	if rec.status != http.StatusOK {
		t.Errorf("默认状态码 = %d, want 200", rec.status)
	}
}

// TestStatusRecorderPreservesFlusher 必须保留流式响应能力。
func TestStatusRecorderPreservesFlusher(t *testing.T) {
	base := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: base, status: http.StatusOK}
	if _, ok := interface{}(rec).(http.Flusher); !ok {
		t.Fatal("statusRecorder 必须实现 http.Flusher，否则 SSE / 流式下载会被缓冲")
	}
	// 调用不应 panic
	rec.Flush()
	if !base.Flushed {
		t.Error("Flush 应转发到底层 ResponseWriter")
	}
}
