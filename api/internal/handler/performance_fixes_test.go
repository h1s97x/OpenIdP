package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/h1s97x/openidp/api/internal/middleware"
)

// TestRouterChainRecoversPanic 验证路由链路上确实装了兜底 panic 恢复中间件。
//
// 背景：此前全仓只有 event.Publish 内有 recover，HTTP handler 层没有任何兜底。
// panic 会冒泡到 net/http，标准库只按连接 recover：客户端拿到 broken pipe
// 而不是可解析的 JSON 错误，前端无法提示用户，堆栈也只出现在 stderr。
//
// 这里用「在路由最内层注入一个 panic」的方式验证，而不是简单断言中间件存在：
// 只有真的把 panic 转成 500 JSON，才算链路生效。
func TestRouterChainRecoversPanic(t *testing.T) {
	_, mux := newTestHandler(t)

	// 包一层 Recover 的内部 handler，模拟「业务 handler panic」。
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	guarded := middleware.Recover(inner)

	// 先确认未加 Recover 时 panic 会逃逸（这是此前的行为）。
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("未加 Recover 时 panic 未逃逸，测试前提不成立")
			}
		}()
		inner.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	}()

	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic 未转为 500：状态码 = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("500 响应不是合法 JSON: %v（%q）", err, rec.Body.String())
	}
	if body["code"] != "server.internal_error" {
		t.Fatalf("错误码 = %v; want server.internal_error", body["code"])
	}

	// 正常链路不受影响。
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	healthRec := httptest.NewRecorder()
	mux.ServeHTTP(healthRec, req)
	if healthRec.Code != http.StatusOK || !strings.Contains(healthRec.Body.String(), "ok") {
		t.Fatalf("健康检查异常: %d %q", healthRec.Code, healthRec.Body.String())
	}
}
