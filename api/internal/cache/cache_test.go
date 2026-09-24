package cache

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestMemoryBackend(t *testing.T) {
	c := newMemory()
	ctx := context.Background()

	// Set/Get
	c.Set(ctx, "k", "v", time.Minute)
	if v, ok := c.Get(ctx, "k"); !ok || v != "v" {
		t.Fatalf("Get = %q, %v; want %q, true", v, ok, "v")
	}

	// Get after Set returns the stored value
	if v, _ := c.Get(ctx, "k"); v != "v" {
		t.Fatalf("value changed unexpectedly: %q", v)
	}

	// GetDel atomically returns and removes
	if v, ok := c.GetDel(ctx, "k"); !ok || v != "v" {
		t.Fatalf("GetDel = %q, %v; want v, true", v, ok)
	}
	if _, ok := c.GetDel(ctx, "k"); ok {
		t.Fatal("second GetDel should miss")
	}

	// Del
	c.Del(ctx, "k")
	if _, ok := c.Get(ctx, "k"); ok {
		t.Fatal("Get after Del should miss")
	}

	// Expiry
	c.Set(ctx, "exp", "1", 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get(ctx, "exp"); ok {
		t.Fatal("Get of expired key should miss")
	}

	// IncrWithTTL: 新建键返回 1，并在窗口内继续累加
	if n := mustIncrWithTTL(t, c, ctx, "counter", time.Minute); n != 1 {
		t.Fatalf("IncrWithTTL new key = %d; want 1", n)
	}
	if n := mustIncr(t, c, ctx, "counter"); n != 2 {
		t.Fatalf("Incr = %d; want 2", n)
	}
	// 过期后计数重新开始（窗口重置）
	c.Del(ctx, "counter")
	if n := mustIncrWithTTL(t, c, ctx, "counter", time.Minute); n != 1 {
		t.Fatalf("IncrWithTTL after reset = %d; want 1", n)
	}
}

// mustIncr / mustIncrWithTTL 断言计数不返回错误（内存后端不应失败）。
func mustIncr(t *testing.T, c Cache, ctx context.Context, key string) int64 {
	t.Helper()
	n, err := c.Incr(ctx, key)
	if err != nil {
		t.Fatalf("Incr(%q) 返回错误: %v", key, err)
	}
	return n
}

func mustIncrWithTTL(t *testing.T, c Cache, ctx context.Context, key string, ttl time.Duration) int64 {
	t.Helper()
	n, err := c.IncrWithTTL(ctx, key, ttl)
	if err != nil {
		t.Fatalf("IncrWithTTL(%q) 返回错误: %v", key, err)
	}
	return n
}

func TestMemoryIncr(t *testing.T) {
	c := newMemory()
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		if got := mustIncr(t, c, ctx, "n"); got != int64(i) {
			t.Fatalf("Incr #%d = %d; want %d", i, got, i)
		}
	}
	c.Expire(ctx, "n", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if got := mustIncr(t, c, ctx, "n"); got != 1 {
		t.Fatalf("Incr after expire = %d; want 1", got)
	}
}

func TestNewFallsBackToMemoryWhenNoAddr(t *testing.T) {
	c, msg := New(Options{})
	if c.Kind() != "memory" {
		t.Fatalf("Kind = %q; want memory", c.Kind())
	}
	if msg == "" {
		t.Fatal("expected a diagnostic message")
	}
	_ = c.Close()
}

// TestNewFallsBackToMemoryWhenRedisUnreachable verifies that an unreachable
// Redis address degrades to the in-memory backend instead of failing.
func TestNewFallsBackToMemoryWhenRedisUnreachable(t *testing.T) {
	c, msg := New(Options{
		Addr:        "127.0.0.1:1", // closed port -> connection refused
		PingTimeout: 300 * time.Millisecond,
		DialTimeout: 300 * time.Millisecond,
	})
	if c.Kind() != "memory" {
		t.Fatalf("Kind = %q; want memory (auto-degrade)", c.Kind())
	}
	if msg == "" {
		t.Fatal("expected a diagnostic degradation message")
	}
	_ = c.Close()
}

// startRedis 启动一个临时 Redis（无持久化），返回端口。无 redis-server 则跳过。
func startRedis(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("redis-server"); err != nil {
		t.Skip("未安装 redis-server，跳过")
	}
	port := "6399"
	if out, err := exec.Command("redis-server", "--daemonize", "yes",
		"--save", "", "--appendonly", "no", "--port", port).CombinedOutput(); err != nil {
		t.Skipf("无法启动 redis-server: %v (%s)", err, out)
	}
	time.Sleep(700 * time.Millisecond)
	t.Cleanup(func() { _ = exec.Command("redis-cli", "-p", port, "shutdown", "nosave").Run() })
	return "127.0.0.1:" + port
}

// TestFailoverSwitchesToMemoryWhenRedisDies 是 Redis 运行期宕机的回归测试。
//
// 修复前：New() 只在启动时探测一次，之后 Redis 是唯一后端。运行中 Redis 死掉后
// IncrWithTTL 失败 → 旧实现返回 1 → 限流器判 1<=max 恒放行，防爆破完全失效；
// 同时 TokenStore 读不到令牌，全部写操作返回 403。
func TestFailoverSwitchesToMemoryWhenRedisDies(t *testing.T) {
	addr := startRedis(t)
	ctx := context.Background()

	c, msg := New(Options{
		Addr:             addr,
		PingTimeout:      500 * time.Millisecond,
		DialTimeout:      500 * time.Millisecond,
		FailureThreshold: 2,
		ProbeInterval:    300 * time.Millisecond,
	})
	defer c.Close()
	if c.Kind() != "redis" {
		t.Fatalf("启动时应使用 Redis，实际 Kind=%q（%s）", c.Kind(), msg)
	}

	// Redis 健康：计数应连续递增。
	for i := 1; i <= 3; i++ {
		n, err := c.IncrWithTTL(ctx, "fo", time.Minute)
		if err != nil {
			t.Fatalf("Redis 健康时 IncrWithTTL #%d 出错: %v", i, err)
		}
		if n != int64(i) {
			t.Fatalf("Redis 健康时 IncrWithTTL #%d = %d; want %d", i, n, i)
		}
	}

	// 运行中切断 Redis。
	if out, err := exec.Command("redis-cli", "-p", "6399", "shutdown", "nosave").CombinedOutput(); err != nil {
		t.Logf("shutdown: %v %s", err, out)
	}
	time.Sleep(400 * time.Millisecond)

	// 关键断言 1：故障期间必须能继续计数（走内存后端），且计数真实递增——
	// 绝不能每次都返回 1（那会让限流放行一切）。
	var got []int64
	for i := 0; i < 3; i++ {
		n, err := c.IncrWithTTL(ctx, "fo", time.Minute)
		if err != nil {
			t.Fatalf("Redis 故障期间 IncrWithTTL 出错: %v", err)
		}
		got = append(got, n)
	}
	if got[0] == 1 && got[1] == 1 && got[2] == 1 {
		t.Errorf("fail-open 回归：Redis 故障期间计数恒为 1（%v），限流将形同虚设", got)
	}

	// 关键断言 2：熔断后 Kind 必须反映真实后端，便于运维判断。
	if c.Kind() != "memory(degraded)" {
		t.Errorf("熔断后 Kind = %q; want memory(degraded)", c.Kind())
	}

	// 关键断言 3：TokenStore 依赖的读写在故障期间必须恢复正常，
	// 不能出现「写成功但读不到」导致 CSRF 校验全挂。
	c.Set(ctx, "tok:csrf", "abc", time.Minute)
	if v, ok := c.Get(ctx, "tok:csrf"); !ok || v != "abc" {
		t.Errorf("故障期间 Set/Get 不一致：got %q,%v; want abc,true", v, ok)
	}
}

// TestFailoverSetSurvivesBeforeTrip 覆盖「熔断生效前」的写入：
// 此时后端仍是 Redis，写入会失败，必须回落到内存，否则数据凭空消失。
// 表现为：Redis 宕机后新签发的 CSRF 令牌写不进去，全站写操作持续 403。
func TestFailoverSetSurvivesBeforeTrip(t *testing.T) {
	addr := startRedis(t)
	ctx := context.Background()

	// 阈值调大，确保整个测试期间都不会熔断，全程停留在「以为 Redis 还活着」的阶段。
	c, _ := New(Options{
		Addr:             addr,
		PingTimeout:      500 * time.Millisecond,
		DialTimeout:      500 * time.Millisecond,
		FailureThreshold: 1000,
		ProbeInterval:    time.Hour,
	})
	defer c.Close()

	_ = exec.Command("redis-cli", "-p", "6399", "shutdown", "nosave").Run()
	time.Sleep(300 * time.Millisecond)

	c.Set(ctx, "tok:before-trip", "v", time.Minute)
	if v, ok := c.Get(ctx, "tok:before-trip"); !ok || v != "v" {
		t.Errorf("熔断前写入丢失：Get = %q,%v; want v,true", v, ok)
	}
}

// TestFailoverRecoversWhenRedisReturns 验证 Redis 恢复后自动切回。
func TestFailoverRecoversWhenRedisReturns(t *testing.T) {
	addr := startRedis(t)
	c, _ := New(Options{
		Addr:             addr,
		PingTimeout:      500 * time.Millisecond,
		DialTimeout:      500 * time.Millisecond,
		FailureThreshold: 1,
		ProbeInterval:    300 * time.Millisecond,
	})
	defer c.Close()

	// 切断后等待熔断生效。
	_ = exec.Command("redis-cli", "-p", "6399", "shutdown", "nosave").Run()
	time.Sleep(300 * time.Millisecond)
	if _, err := c.Incr(context.Background(), "rec"); err != nil {
		t.Fatalf("故障期间计数出错: %v", err)
	}
	if c.Kind() != "memory(degraded)" {
		t.Fatalf("熔断未生效，Kind=%q", c.Kind())
	}

	// 重启 Redis，等待后台探测把它切回。
	if out, err := exec.Command("redis-server", "--daemonize", "yes",
		"--save", "", "--appendonly", "no", "--port", "6399").CombinedOutput(); err != nil {
		t.Fatalf("重启 redis 失败: %v (%s)", err, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.Kind() == "redis" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Errorf("Redis 恢复后未自动切回，Kind=%q", c.Kind())
}

// TestMemoryIncrWithTTLFixedWindow 校验内存后端与 Redis 后端窗口语义一致：
// 窗口内的后续自增不会延长窗口，窗口到期后计数重新从 1 开始。
func TestMemoryIncrWithTTLFixedWindow(t *testing.T) {
	c := newMemory()
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		if n := mustIncrWithTTL(t, c, ctx, "win", 400*time.Millisecond); n != int64(i) {
			t.Fatalf("IncrWithTTL #%d = %d; want %d", i, n, i)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// 窗口到期后应重置为 1，而不是继续累加。
	time.Sleep(350 * time.Millisecond)
	if n := mustIncrWithTTL(t, c, ctx, "win", 400*time.Millisecond); n != 1 {
		t.Fatalf("IncrWithTTL after window = %d; want 1 (fixed window)", n)
	}
}
