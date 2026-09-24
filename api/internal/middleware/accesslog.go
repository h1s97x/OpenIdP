package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/h1s97x/openidp/api/internal/logging"
)

// ---------------------------------------------------------------------------
// HTTP 访问日志中间件
//
// 记录每个请求的 方法 / 路径 / 状态码 / 字节数 / 耗时 / 客户端 IP / UA，
// 用于排障与访问审计。刻意不记录：
//   - 请求体：可能含密码、验证码等凭据
//   - 查询串的值：可能含 token、邮箱等（仅路径本身参与记录）
// ---------------------------------------------------------------------------

// AccessLogConfig 是访问日志的配置。
type AccessLogConfig struct {
	// Enabled 为 false 时完全不记录（中间件退化为直接透传）。
	Enabled bool
	// SkipHealth 为 true 时跳过健康检查端点。容器/编排会高频调用健康检查，
	// 记录它价值很低却会显著放大日志量。
	SkipHealth bool
}

// AccessLog returns middleware that records one line per HTTP request.
func AccessLog(cfg AccessLogConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// 未启用时不包裹 ResponseWriter，避免任何额外开销
		if !cfg.Enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.SkipHealth && isHealthEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			logging.Access(r, rec.status, rec.written, time.Since(start))
		})
	}
}

// isHealthEndpoint 判断是否为健康检查端点。
func isHealthEndpoint(p string) bool {
	return strings.HasSuffix(p, "/api/health")
}

// statusRecorder 捕获响应状态码与写入字节数。
//
// 必须实现 http.Flusher：SSE、大文件流式下载等依赖它，
// 不实现会导致响应被缓冲、实时性丧失。
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	// 首次写入时状态码可能尚未显式设置，此时按 200 计
	n, err := r.ResponseWriter.Write(b)
	r.written += n
	return n, err
}

// Flush 转发到底层 ResponseWriter，保持流式响应可用。
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
