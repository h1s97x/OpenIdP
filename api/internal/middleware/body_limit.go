package middleware

import (
	"context"
	"net/http"
	"strings"
)

// maxJSONBodyBytes 是 JSON / 表单请求体的大小上限（1MB）。
// 所有 handler 都用 json.NewDecoder(r.Body) 直接解码，缺少统一上限时
// 恶意客户端可以发送数 GB 请求体打爆内存。
const maxJSONBodyBytes = 1 << 20

// maxMultipartBodyBytes 是 multipart（文件上传）请求体的总上限。
//
// 之所以不能豁免 multipart：ParseMultipartForm(maxMemory) 的 maxMemory 只是
// **内存阈值**，超出部分会落到临时文件，请求体本身并没有任何上限。
// 上传端点虽然校验 header.Size，但那次校验发生在整个请求体已经被读完并落盘之后：
// 攻击者发一个远超限额的 multipart，服务端会先完整读完、写满临时目录，
// 最后才回一个 file.too_large。配合限流仍可在一天内写满数 TB 临时文件。
//
// 取值 = 通用附件上限（10MB）+ 表单开销余量：multipart 除文件本身还包含
// 边界、各字段头与其它小字段，余量过小会误伤合法上传。
const maxMultipartBodyBytes = (10 << 20) + (1 << 20)

// multipartMemoryBytes 是 multipart 解析时保留在内存中的上限。
// 刻意小于 maxMultipartBodyBytes：超出部分由 ParseMultipartForm 落临时文件，
// 由外层 MaxBytesReader 兜底总量，二者共同限制磁盘占用。
const multipartMemoryBytes = 1 << 20

// maxBackupBodyBytes 是数据备份（application/zip）请求体的上限。
//
// 为什么单独给一档：备份恢复要上传整份归档，含事件表时可达数十至数百 MB，
// 远超 JSON 的 1MB 上限；卡在 1MB 会让这个功能「导得出来、恢复不回去」。
// 上限不能省：请求体虽然被 handler 流式落到临时文件（不驻留内存），
// 但落盘同样消耗磁盘。这里给足空间并依赖两点兜底：端点仅管理员可用，
// 且挂在 adminLimiter 限流之下（见 router.go 的 admin 分组）。
const maxBackupBodyBytes = 512 << 20

// BodyLimit caps the request body size for the wrapped handler.
//
// multipart（文件上传）同样受限，只是上限更宽（见 maxMultipartBodyBytes）：
// 任何请求体都必须有一个绝对上限，否则「校验在读完请求体之后」的写法
// 等于没有限制。
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		limit := int64(maxJSONBodyBytes)
		switch contentType := r.Header.Get("Content-Type"); {
		case strings.HasPrefix(contentType, "multipart/"):
			limit = int64(maxMultipartBodyBytes)
		case strings.HasPrefix(contentType, "application/zip"):
			limit = int64(maxBackupBodyBytes)
		}
		// MaxBytesReader 在超限时让后续读取返回错误，并在响应中回 413，
		// 从而把「读完再判断」变成「读不动就停」。
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// MultipartMemoryLimit 返回 multipart 解析应传给 ParseMultipartForm 的内存上限，
// 供上传 handler 使用：超出部分落临时文件，但总量仍受 BodyLimit 约束。
func MultipartMemoryLimit() int64 { return multipartMemoryBytes }

// ctxBackground 返回限流器使用的固定上下文（限流不随请求取消而中断）。
func ctxBackground() context.Context { return context.Background() }
