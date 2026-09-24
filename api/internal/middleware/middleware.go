package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/h1s97x/openidp/api/internal/auth"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	csrfTokenKey
)

// WithRequestID injects an X-Request-ID (32-hex) into every response and context.
func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := auth.RandomHex(16)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestID returns the request ID from context (or "").
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// writeJSONError 输出与 handler 包 fail() 结构一致的 JSON 错误响应，
// 并带上正确的 Content-Type 与当前 requestId。
//
// 此前中间件用 http.Error 输出 JSON 字符串：http.Error 会强制把 Content-Type
// 覆盖为 text/plain，前端按 JSON 解析会失败；requestId 也恒为空字符串，
// 排障时无法把这次拒绝关联到访问日志。
func writeJSONError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	body, err := json.Marshal(map[string]any{
		"status":    0,
		"code":      code,
		"message":   message,
		"requestId": RequestID(r.Context()),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// SecurityHeaders 输出加固的安全响应头。
// hsts 控制是否输出 Strict-Transport-Security（仅在站点以 HTTPS 对外服务时启用）。
// cdnBaseURL 是前端静态资源（字体等）的 CDN 基址，会加入 CSP 白名单；
// 为空或 "-" 表示不使用外部 CDN（私有化/离线部署），此时不下发该域。
//
// 注意：CSP 白名单必须与前端实际引用的外部域保持一致（见 web/index.html）。
// 字体 CSS 与字体文件来自 CDN，若此处遗漏该域，浏览器会按 CSP 阻断样式与字体，
// 导致「内置字体」功能整体失效。
// SecurityOptions 控制安全响应头的可选项（目前仅开发模式需要放开的部分）。
type SecurityOptions struct {
	// AllowInlineScripts 允许内联 <script>。
	// Vite dev server 会向 index.html 注入 react-refresh 引导脚本（无 src 的内联模块），
	// 生产内嵌产物不含内联脚本，因此仅在开发模式放开，避免削弱生产 CSP。
	AllowInlineScripts bool
}

func SecurityHeaders(hsts bool, cdnBaseURL string, opts ...SecurityOptions) func(http.Handler) http.Handler {
	var o SecurityOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	// CSP 只需在启动时计算一次：它只依赖配置，不随请求变化。
	// 原先每请求都拼一次长字符串，属于无谓开销。
	csp := buildCSP(cdnBaseURL, o.AllowInlineScripts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
			h.Set("Content-Security-Policy", csp)
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// buildCSP 生成 Content-Security-Policy 值。
//
// cdnBaseURL 为空或 "-" 时不引入外部 CDN 域，供私有化/离线部署使用；
// 其余情况把它加入 style-src 与 font-src（前端字体与样式来自该域）。
// allowInlineScripts 仅开发模式为 true：Vite 注入的 react-refresh 引导脚本是内联的，
// 被拦掉会导致页面白屏（模块脚本依赖它注入的全局钩子）。
func buildCSP(cdnBaseURL string, allowInlineScripts bool) string {
	cdn := ""
	if v := strings.TrimSpace(cdnBaseURL); v != "" && v != "-" {
		cdn = " " + v
	}
	scriptInline := ""
	if allowInlineScripts {
		scriptInline = " 'unsafe-inline'"
	}
	// 极验 v4 前端 SDK 会按网络状况在多个域名间切换（geetest.com /
	// geevisit.com / gsensebot.com），且部分资源走 http://，逐域白名单
	// 会被 CSP 拦截导致验证窗口弹不出来——这里放开相关域并允许 http 升级。
	return "default-src 'self'" +
		// JSONP load 接口走 http://，script-src 必须放行 http 的极验域。
		"; script-src 'self'" + scriptInline + " https://static.geetest.com https://static.geevisit.com http://*.geetest.com https://*.geetest.com http://*.geevisit.com https://*.geevisit.com http://*.gsensebot.com https://*.gsensebot.com https://challenges.cloudflare.com" +
		"; style-src 'self' 'unsafe-inline' https://static.geetest.com https://static.geevisit.com http://static.geetest.com http://static.geevisit.com https://challenges.cloudflare.com" + cdn +
		"; img-src 'self' data: blob: https: http://*.geetest.com http://*.geevisit.com" +
		"; font-src 'self' data: https://static.geetest.com https://static.geevisit.com" + cdn +
		"; connect-src 'self' https://*.geetest.com http://*.geetest.com https://*.geevisit.com http://*.geevisit.com https://*.gsensebot.com https://challenges.cloudflare.com" +
		"; frame-src https://*.geetest.com https://*.geevisit.com https://*.gsensebot.com https://challenges.cloudflare.com" +
		"; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
}
