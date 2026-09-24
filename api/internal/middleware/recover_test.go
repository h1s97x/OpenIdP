package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRecoverConvertsPanicTo500 验证 handler panic 被转换为可解析的 500 响应。
//
// 此前没有任何兜底 recover：panic 冒泡到 net/http，标准库直接断开连接，
// 客户端拿到 broken pipe 而不是错误结构，前端无法给出任何提示。
func TestRecoverConvertsPanicTo500(t *testing.T) {
	h := Recover(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/panic", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("状态码 = %d; want 500", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v（body=%q）", err, rec.Body.String())
	}
	if body["code"] != "server.internal_error" {
		t.Fatalf("code = %v; want server.internal_error", body["code"])
	}
}

// TestRecoverPassesThroughNormalResponses 验证正常请求不受影响。
func TestRecoverPassesThroughNormalResponses(t *testing.T) {
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ok", nil))
	if rec.Code != http.StatusTeapot || rec.Body.String() != "ok" {
		t.Fatalf("正常响应被改写: %d %q", rec.Code, rec.Body.String())
	}
}

// TestRecoverDoesNotCorruptStartedResponses 验证「响应已开始写出」时
// 不再追加错误 JSON，避免产生损坏的响应体。
func TestRecoverDoesNotCorruptStartedResponses(t *testing.T) {
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic("after write")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/partial", nil))

	if got := rec.Body.String(); got != "partial" {
		t.Fatalf("响应体被污染: %q", got)
	}
	if strings.Contains(rec.Body.String(), "server.internal_error") {
		t.Fatal("已在写出的响应后追加了错误 JSON")
	}
}

// TestRecoverRethrowsAbortHandler ErrAbortHandler 是标准库约定的静默中断，
// 不应被记成 500，必须原样向上抛出。
func TestRecoverRethrowsAbortHandler(t *testing.T) {
	h := Recover(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Fatalf("panic 未被原样重抛: %v", r)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/abort", nil))
	t.Fatal("ErrAbortHandler 未被重抛")
}
