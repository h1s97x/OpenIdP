package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/h1s97x/openidp/api/internal/cache"
)

// RateLimiter is a fixed-window rate limiter keyed by an arbitrary string
// (client IP, account, user ID…), backed by a shared cache (Redis when
// available, in-memory otherwise). It protects login / verification-code
// endpoints against brute-force and enumeration. Using a shared backend keeps
// limits consistent across multiple instances.
//
// 计数与窗口过期的设置是原子的（Redis 走 Lua 脚本，内存后端走同一把锁）：
// 若拆成 Incr + 条件 Expire，多实例并发下多个实例都可能观察到 count==1，
// 从而反复把窗口 TTL 重置为 1，限流形同虚设。
type RateLimiter struct {
	// name 是限流器的作用域标识，参与计数键构造（rl:<name>:<key>）。
	//
	// 作用域不能省：此前所有限流器共用 rl:<IP> 一个计数器，
	// 登录(10/min)、验证码(20/min)、上传(20/min)、文件读取(600/min) 互相顶配额——
	// 同一分钟加载 20 张图片就会耗尽上传配额，任意端点数次请求即可连锁封住登录。
	// 带上作用域后各限流器独立计数，互不影响。
	name   string
	window time.Duration
	max    int
	cache  cache.Cache
}

// NewRateLimiter creates a limiter allowing `max` requests per `window` per key.
// name 是该限流器的作用域（如 login / code / upload），同名限流器共享同一组计数。
func NewRateLimiter(c cache.Cache, name string, window time.Duration, max int) *RateLimiter {
	return &RateLimiter{cache: c, name: name, window: window, max: max}
}

func rateKey(name, key string) string { return "rl:" + name + ":" + key }

// allow 判定计数是否放行，并处理计数取不到的情况。
//
// 计数失败（两个后端都不可用）时按 fail-closed 拒绝：限流器的职责就是挡住爆破，
// 取不到计数时放行等于主动解除防护。正常情况下不会出现——failover 会在 Redis
// 故障时改用内存后端计数，这里只是兜底。
func (l *RateLimiter) allow(count int64, err error) bool {
	if err != nil {
		log.Printf("❌ [RateLimit] 计数失败，按 fail-closed 拒绝请求：%v", err)
		return false
	}
	return count <= int64(l.max)
}

// AllowKey reports whether a request under the given key is within the limit.
// 与 Allow 相同，但使用显式键（可叠加维度，如 IP、账号、用户）。
func (l *RateLimiter) AllowKey(key string) bool {
	if l == nil || key == "" {
		return true
	}
	count, err := l.cache.IncrWithTTL(ctxBackground(), rateKey(l.name, key), l.window)
	return l.allow(count, err)
}

// Allow reports whether a request from the given IP is within the limit.
func (l *RateLimiter) Allow(ip string) bool {
	if l == nil {
		return true
	}
	if ip == "" {
		// 无法解析 IP 时放行，避免阻断内部/无 IP 场景
		return true
	}
	count, err := l.cache.IncrWithTTL(ctxBackground(), rateKey(l.name, ip), l.window)
	return l.allow(count, err)
}

// RateLimit returns middleware that applies a rate limiter to a handler,
// returning 429 when exceeded. ipFunc extracts the client IP from the request.
func RateLimit(l *RateLimiter, ipFunc func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l != nil && !l.Allow(ipFunc(r)) {
				w.Header().Set("Retry-After", "60")
				writeJSONError(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
