package middleware

import (
	"net/http"
)

// 跨域允许的方法必须覆盖前端实际使用的全部动词。
// 曾经漏掉 PUT，导致「前后端分离部署」下 5 个管理端 PUT 接口
// （storage / location / audit-settings / data-cleanup / oauth-scopes）
// 的预检请求被浏览器拦截，功能整片不可用。
const corsAllowMethods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"

const corsAllowHeaders = "Content-Type, Accept, X-OpenIdP-CSRF, X-OpenIdP-Reauth, X-Request-ID, Authorization"

// CORS enables cross-origin API access for frontend/backend separated
// deployments. It only emits headers when the request Origin is in the
// allowed list (from CORS_ALLOWED_ORIGINS). Same-origin deployments pass
// through untouched.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, o := range allowedOrigins {
		allowed[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Vary", "Origin")
				// 跨源请求需要携带会话 Cookie，因此必须同时允许凭据；
				// 前端侧对应 credentials: 'include'。
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Methods", corsAllowMethods)
				h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
				h.Set("Access-Control-Max-Age", "86400")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
