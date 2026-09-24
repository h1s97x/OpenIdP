package middleware

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/cache"
)

// TestMemoryBackendFixedWindow 验证内存后端与 Redis 后端窗口语义一致，
// 回归此前的缺陷：每次自增都重设 TTL 会让窗口永不滑动，限流形同虚设。
func TestMemoryBackendFixedWindow(t *testing.T) {
	c := cache.NewMemory()
	defer c.Close()
	ctx := context.Background()

	// 窗口 600ms，每 200ms 一次：窗口内持续累加（1,2,3），
	// 到第 4 次（已过 600ms）窗口到期，计数重置为 1。
	want := []int64{1, 2, 3, 1, 2, 3}
	got := make([]int64, 0, len(want))
	for i := 0; i < len(want); i++ {
		n, err := c.IncrWithTTL(ctx, "rl:probe", 600*time.Millisecond)
		if err != nil {
			t.Fatalf("IncrWithTTL #%d 返回错误: %v", i, err)
		}
		got = append(got, n)
		time.Sleep(200 * time.Millisecond)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("counts = %v; want %v (window must reset, not extend)", got, want)
		}
	}
}

// errCache 是一个计数恒定失败的后端，用于验证限流器不会 fail-open。
type errCache struct{ cache.Cache }

func (errCache) IncrWithTTL(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("计数后端不可用")
}
func (errCache) Incr(context.Context, string) (int64, error) {
	return 0, errors.New("计数后端不可用")
}

// TestRateLimiterFailsClosed 验证计数取不到时限流器拒绝放行而非放行。
// 这是 Redis 宕机导致限流失效（fail-open）的回归测试：
// 旧实现里 Incr 出错返回 1，1 <= max 恒真，防爆破被静默解除。
func TestRateLimiterFailsClosed(t *testing.T) {
	l := NewRateLimiter(errCache{cache.NewMemory()}, "login", time.Minute, 10)
	for i := 0; i < 10; i++ {
		if l.Allow("10.0.0.9") {
			t.Fatalf("第 %d 次请求被放行；计数失败时必须 fail-closed", i+1)
		}
	}
	if l.AllowKey("acct:someone") {
		t.Fatal("AllowKey 在计数失败时被放行；必须 fail-closed")
	}
}

// TestRateLimiterResetsEachWindow 校验限流器在窗口到期后重新放行。
func TestRateLimiterResetsEachWindow(t *testing.T) {
	l := NewRateLimiter(cache.NewMemory(), "login", 600*time.Millisecond, 3)
	// 配额 3 / 600ms，共 6 次请求（每 200ms 一次）：
	// 前 3 次放行，第 4~6 次进入新窗口后继续放行，即 6 次全部通过。
	allowed := 0
	for i := 0; i < 6; i++ {
		if l.Allow("10.0.0.1") {
			allowed++
		}
		time.Sleep(200 * time.Millisecond)
	}
	if allowed != 6 {
		t.Fatalf("allowed = %d; want 6 (3 per window x 2 windows)", allowed)
	}

	// 同一窗口内连续请求超出配额时必须被拒。
	l2 := NewRateLimiter(cache.NewMemory(), "login", time.Minute, 3)
	passed := 0
	for i := 0; i < 5; i++ {
		if l2.Allow("10.0.0.2") {
			passed++
		}
	}
	if passed != 3 {
		t.Fatalf("passed = %d; want 3 (limit 3 per window)", passed)
	}
}

// TestRateLimiterScopesAreIsolated 验证不同 scope 的限流器互不影响。
//
// 回归此前的缺陷：所有限流器共用 rl:<IP> 一个计数键，
// 于是「加载 20 张图片」就能把上传配额顶爆（file 与 upload 同池），
// 任意端点数次请求也会连锁封住登录。scope 化后各自独立计数。
func TestRateLimiterScopesAreIsolated(t *testing.T) {
	c := cache.NewMemory()
	defer c.Close()

	// file 作用域配额 5，先打满。
	fileLimiter := NewRateLimiter(c, "file", time.Minute, 5)
	for i := 0; i < 5; i++ {
		if !fileLimiter.Allow("10.0.0.5") {
			t.Fatalf("file 第 %d 次请求被拒；配额为 5", i+1)
		}
	}
	if fileLimiter.Allow("10.0.0.5") {
		t.Fatal("file 作用域超出配额仍被放行")
	}

	// 同一 IP、同一 cache：upload 作用域必须不受影响。
	uploadLimiter := NewRateLimiter(c, "upload", time.Minute, 5)
	if !uploadLimiter.Allow("10.0.0.5") {
		t.Fatal("file 作用域打满后 upload 被误伤；不同 scope 必须独立计数")
	}

	// AllowKey 同样按 scope 隔离：acct:/sms: 用途前缀保留，且不串到 IP 计数。
	accountLimiter := NewRateLimiter(c, "account", time.Minute, 2)
	if !accountLimiter.AllowKey("acct:alice") || !accountLimiter.AllowKey("acct:alice") {
		t.Fatal("account 作用域前两次请求应放行")
	}
	if accountLimiter.AllowKey("acct:alice") {
		t.Fatal("account 作用域超出配额仍被放行")
	}
	if !accountLimiter.AllowKey("sms:alice") {
		t.Fatal("acct:/sms: 是不同用途前缀，应各自独立计数")
	}
	if !accountLimiter.Allow("10.0.0.5") {
		t.Fatal("account 的显式键计数不应影响同 scope 下的 IP 计数")
	}
}
