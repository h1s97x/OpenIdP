package middleware

import (
	"log"
	"net/http"
	"runtime/debug"

	"github.com/h1s97x/openidp/api/internal/logging"
)

// Recover 兜底捕获 handler 链路上的 panic，转换为 500 响应并记录堆栈。
//
// 必要性：Go 的 net/http 只会在连接级别 recover（打印堆栈后直接断开连接），
// 客户端拿到的是 broken pipe 而不是可解析的错误响应，前端无法给用户任何提示；
// 同时 panic 细节只出现在 stderr，落盘日志里一无所有，排障时缺少可用线索。
//
// 放在中间件链最外层：这样 panic 无论来自限流、CSRF、鉴权还是业务 handler
// 都能被捕获。已开始写响应的请求（响应头已发出）无法再改成 500，
// 此时只记录日志，避免写坏响应体。
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &recoverWriter{ResponseWriter: w}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// http.ErrAbortHandler 是 net/http 约定的「静默中断」信号，
			// 按标准库语义重新抛出，不应记成 500（它由调用方主动触发）。
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			logging.Error("❌ [Panic] %s %s 处理时发生 panic: %v\n%s",
				r.Method, r.URL.Path, rec, debug.Stack())
			log.Printf("❌ [Panic] %s %s: %v", r.Method, r.URL.Path, rec)

			// 响应头一旦发出就无法再改成 500：此时只记录日志，
			// 否则会把错误 JSON 追加到已有响应体后面，产生损坏的响应。
			if rw.wrote {
				return
			}
			writeJSONError(rw, r, http.StatusInternalServerError, "server.internal_error", "服务器内部错误")
		}()
		next.ServeHTTP(rw, r)
	})
}

// recoverWriter 记录响应是否已经开始写出，供 Recover 判断能否安全地改写为 500。
type recoverWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *recoverWriter) WriteHeader(status int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *recoverWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// Flush 透传，保持流式响应的可用性（标准库的 Flusher 语义）。
func (w *recoverWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
