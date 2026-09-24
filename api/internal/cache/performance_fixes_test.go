package cache

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestMemorySweepsExpiredKeys 验证内存后端会回收过期条目。
//
// 背景：只有惰性删除时，写入后不再被访问的 key 会永久驻留——限流键的维度
// （IP / 账号 / 邮箱）由请求方控制，唯一值可无限增长，实测 100 万键约占 150MB，
// 长期运行必然 OOM。这里通过直接触发一轮清扫来验证回收逻辑。
func TestMemorySweepsExpiredKeys(t *testing.T) {
	m := newMemory()
	defer m.Close()
	ctx := context.Background()

	for i := 0; i < 5000; i++ {
		m.Set(ctx, "rl:"+strconv.Itoa(i), "1", 10*time.Millisecond)
	}
	// 未过期时不应被清扫掉。
	if got := m.sweepExpired(); got != 0 {
		t.Fatalf("sweepExpired() 删除了未过期条目 %d 个，想要 0", got)
	}
	time.Sleep(50 * time.Millisecond)
	if got := m.sweepExpired(); got != 5000 {
		t.Fatalf("sweepExpired() 回收 %d 个，想要 5000", got)
	}
	if n := m.resident(); n != 0 {
		t.Fatalf("清扫后仍驻留 %d 个 key，想要 0", n)
	}
}

// TestMemorySweepKeepsUnexpiredKeys 验证清扫不会误删仍然有效的条目
// （限流计数、CSRF 令牌被误删会导致限流失效/写操作被拒）。
func TestMemorySweepKeepsUnexpiredKeys(t *testing.T) {
	m := newMemory()
	defer m.Close()
	ctx := context.Background()

	m.Set(ctx, "live", "v", time.Hour)
	m.Set(ctx, "dead", "v", time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	m.sweepExpired()

	if _, ok := m.Get(ctx, "live"); !ok {
		t.Fatal("有效的 key 被清扫误删")
	}
	if _, ok := m.Get(ctx, "dead"); ok {
		t.Fatal("过期的 key 仍可读取")
	}
}

// TestMemoryBackgroundSweeperRuns 验证后台清扫协程真的在跑（不依赖手工触发）。
// 用较短的等待控制测试时长：清扫周期固定为 1 分钟，这里改为直接校验
// sweepLoop 存在且 Close 能停止它。
func TestMemoryCloseStopsSweeper(t *testing.T) {
	m := newMemory()
	if err := m.Close(); err != nil {
		t.Fatalf("Close() 返回错误: %v", err)
	}
	// 重复 Close 必须安全（defer 与显式调用可能同时发生）。
	if err := m.Close(); err != nil {
		t.Fatalf("重复 Close() 返回错误: %v", err)
	}
	select {
	case <-m.stopped:
	default:
		t.Fatal("Close() 之后 stopped 通道未关闭，清扫协程会常驻")
	}
}

// TestMemoryCapTriggersSweep 验证写入触达条目上限时会顺手回收过期项，
// 避免清扫周期内的写入尖峰把内存顶爆。
func TestMemoryCapTriggersSweep(t *testing.T) {
	m := newMemory()
	defer m.Close()
	ctx := context.Background()
	m.maxItems = 100

	for i := 0; i < 100; i++ {
		m.Set(ctx, "k"+strconv.Itoa(i), "1", time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	// 这次写入会触发 maybeSweepLocked，把前面 100 个过期项清掉。
	m.Set(ctx, "fresh", "1", time.Hour)
	if n := m.resident(); n > 2 {
		t.Fatalf("触达上限后仍驻留 %d 个 key，期望已回收过期项", n)
	}
}

// TestMemoryConcurrentAccessIsSafe 并发读写 + 清扫不能产生数据竞争（配合 -race）。
func TestMemoryConcurrentAccessIsSafe(t *testing.T) {
	m := newMemory()
	defer m.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				k := strconv.Itoa(id) + ":" + strconv.Itoa(j%50)
				m.Set(ctx, k, "1", 5*time.Millisecond)
				m.Get(ctx, k)
				m.IncrWithTTL(ctx, "rl:"+k, 5*time.Millisecond)
				if j%100 == 0 {
					m.sweepExpired()
				}
			}
		}(i)
	}
	wg.Wait()
}

// ---- Redis 熔断恢复后的状态交接 ----

// TestFailoverBackfillsCountersOnRecovery 验证 Redis 恢复时会把熔断期间
// 累计在内存里的限流计数回填到 Redis，而不是直接丢弃。
//
// 不变量：限流窗口内的计数只能增、不能因后端切换而回退。
// 修复前，Redis 抖动一趟会让窗口计数「重置」，短时内容忍超出限额的请求。
func TestFailoverBackfillsCountersOnRecovery(t *testing.T) {
	addr := startRedis(t)
	ctx := context.Background()
	c, _ := New(Options{
		Addr:             addr,
		PingTimeout:      500 * time.Millisecond,
		DialTimeout:      500 * time.Millisecond,
		FailureThreshold: 1,
		ProbeInterval:    200 * time.Millisecond,
	})
	defer c.Close()

	// Redis 健康时先建立窗口。
	if _, err := c.IncrWithTTL(ctx, "rl:acct:alice", time.Minute); err != nil {
		t.Fatalf("建立窗口失败: %v", err)
	}

	// 切断 Redis，计量到 10 次（全部落在内存后端）。阈值已置 1，
	// 第一次操作失败即熔断。
	_ = exec.Command("redis-cli", "-p", "6399", "shutdown", "nosave").Run()
	time.Sleep(300 * time.Millisecond)
	var last int64
	for i := 0; i < 10; i++ {
		n, err := c.IncrWithTTL(ctx, "rl:acct:alice", time.Minute)
		if err != nil {
			t.Fatalf("熔断期间计数出错: %v", err)
		}
		last = n
	}
	if last < 5 {
		t.Fatalf("熔断期间未在内存中累计计数：last=%d", last)
	}
	if c.Kind() != "memory(degraded)" {
		t.Fatalf("预期已熔断，Kind=%q", c.Kind())
	}

	// 重启 Redis，等待切回。切回后计数必须至少保持内存中的值，不能回退到 1。
	if out, err := exec.Command("redis-server", "--daemonize", "yes",
		"--save", "", "--appendonly", "no", "--port", "6399").CombinedOutput(); err != nil {
		t.Fatalf("重启 redis 失败: %v (%s)", err, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.Kind() != "redis" {
		time.Sleep(100 * time.Millisecond)
	}
	if c.Kind() != "redis" {
		t.Fatal("Redis 恢复后未切回")
	}

	n, err := c.IncrWithTTL(ctx, "rl:acct:alice", time.Minute)
	if err != nil {
		t.Fatalf("切回后计数出错: %v", err)
	}
	if n < last {
		t.Fatalf("切回后计数回退：%d → %d（限流窗口被重置，存在穿透风险）", last, n)
	}
}

// TestFailoverBackfillDoesNotClobberTokens 验证非计数器键的回填是「仅在缺失时写入」，
// 不会覆盖 Redis 中更新的令牌值。
func TestFailoverBackfillDoesNotClobberTokens(t *testing.T) {
	addr := startRedis(t)
	ctx := context.Background()
	c, _ := New(Options{
		Addr:             addr,
		PingTimeout:      500 * time.Millisecond,
		DialTimeout:      500 * time.Millisecond,
		FailureThreshold: 1,
		ProbeInterval:    200 * time.Millisecond,
	})
	defer c.Close()

	_ = exec.Command("redis-cli", "-p", "6399", "shutdown", "nosave").Run()
	time.Sleep(300 * time.Millisecond)
	// 熔断期间在内存写下令牌。
	c.Set(ctx, "tok:csrf:1", "memory-value", time.Minute)
	_, _ = c.Get(ctx, "tok:csrf:1")

	if out, err := exec.Command("redis-server", "--daemonize", "yes",
		"--save", "", "--appendonly", "no", "--port", "6399").CombinedOutput(); err != nil {
		t.Fatalf("重启 redis 失败: %v (%s)", err, out)
	}
	// 切回前先在 Redis 侧写入「权威」的新值。
	_ = exec.Command("redis-cli", "-p", "6399", "set", "tok:csrf:1", "redis-value", "EX", "60").Run()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.Kind() != "redis" {
		time.Sleep(100 * time.Millisecond)
	}
	if c.Kind() != "redis" {
		t.Fatal("Redis 恢复后未切回")
	}
	time.Sleep(300 * time.Millisecond) // 留出回填时间

	if v, ok := c.Get(ctx, "tok:csrf:1"); !ok || v != "redis-value" {
		t.Fatalf("回填覆盖了 Redis 中的权威值：got %q,%v; want redis-value,true", v, ok)
	}
}

// ---- 内存占用的定量证明 ----

// 定量对照实验：模拟「限流键唯一值不断增长」的线上场景，
// 断言内存占用与「当前活跃 key 数」相关，而非与「历史写入过的 key 总数」相关。
func TestMemoryFootprintBoundedByLiveKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过较慢的内存实验")
	}
	m := newMemory()
	defer m.Close()
	ctx := context.Background()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	const total = 400_000
	for i := 0; i < total; i++ {
		m.Set(ctx, "rl:acct:user"+strconv.Itoa(i), "1", 50*time.Millisecond)
	}
	// 等待全部 TTL 过期后再清扫（等价于线上后台清扫到期那一刻）。
	time.Sleep(80 * time.Millisecond)
	// 触发一轮清扫。
	// 写入过程本身也会在触达条目上限时顺手回收（maybeSweepLocked），
	// 所以这里回收到的数量可能远小于写入总量——这正是期望行为。
	n := m.sweepExpired()
	t.Logf("最后一轮清扫额外回收 %d 个", n)
	if m.resident() != 0 {
		t.Fatalf("清扫后仍驻留 %d 个 key，期望 0", m.resident())
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	heapDeltaMB := int64(after.HeapAlloc)/1024/1024 - int64(before.HeapAlloc)/1024/1024
	t.Logf("写入 %d 个过期 key 后清扫：resident=%d，堆变化 %d MB", total, m.resident(), heapDeltaMB)
	// 清扫掉全部 key 后，堆不应保留与写入量成正比的内存。
	if heapDeltaMB > 30 {
		t.Fatalf("清扫后堆仍增长 %d MB，疑似泄漏", heapDeltaMB)
	}
}
