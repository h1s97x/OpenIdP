package cache

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

// failover 同时持有 Redis 与内存两个后端，在 Redis 运行期故障时自动切换。
//
// 必要性：New 只在启动时探测一次 Redis，之后 Redis 是唯一后端。一旦它在运行中
// 宕机，所有读写都会失败——限流取不到计数而恒放行、TokenStore 读不到 CSRF
// 令牌而拒绝全部写操作、每个请求还要重复拨号等待超时。这里用连续失败计数做
// 熔断，熔断期间整体走内存后端，并由后台协程探测恢复。
//
// 关键设计：熔断是按失败次数触发的，达到阈值前仍会先尝试 Redis。因此每个操作
// 在 Redis 返回错误后必须立刻回落到内存后端，否则「熔断生效前的那几次写入」
// 会被静默丢弃（既没进 Redis 也没进内存）。
type failover struct {
	redis     *redisCache
	mem       *memory
	threshold int
	probe     time.Duration

	mu      sync.RWMutex
	healthy bool
	fails   int

	stopOnce sync.Once
	stopped  chan struct{}
}

// newFailover 包装一个已连通的 Redis 后端。返回的 Cache 在 Redis 故障期间
// 自动使用内存后端，并在 Redis 恢复后切回。
func newFailover(rc *redisCache, o Options) *failover {
	f := &failover{
		redis:     rc,
		mem:       newMemory(),
		threshold: o.FailureThreshold,
		probe:     o.ProbeInterval,
		healthy:   true,
		stopped:   make(chan struct{}),
	}
	if f.threshold <= 0 {
		f.threshold = 3
	}
	if f.probe <= 0 {
		f.probe = 10 * time.Second
	}
	go f.probeLoop()
	return f
}

// useRedis 报告本次操作是否应先尝试 Redis。
func (f *failover) useRedis() bool {
	f.mu.RLock()
	ok := f.healthy
	f.mu.RUnlock()
	return ok
}

// recordFailure 累计一次 Redis 失败，达到阈值则熔断切内存。
func (f *failover) recordFailure(err error) {
	f.mu.Lock()
	f.fails++
	if !f.healthy || f.fails < f.threshold {
		f.mu.Unlock()
		return
	}
	f.healthy = false
	n := f.fails
	f.mu.Unlock()
	log.Printf("⚠️ [Cache] Redis 连续失败 %d 次（%v），已熔断并切换到内存缓存", n, err)
}

// recordSuccess 一次 Redis 操作成功后清零失败计数。
func (f *failover) recordSuccess() {
	f.mu.Lock()
	f.fails = 0
	f.mu.Unlock()
}

// probeLoop 熔断期间周期性探测 Redis，恢复后切回。
//
// 恢复时会把熔断期间写进内存的条目回填到 Redis，而不是直接把内存副本丢掉。
// 此前不做回填，Redis 抖动前后的限流窗口会「重置」：熔断期间累计的计数只存在
// 内存里，切回 Redis 后从 0 开始，短时间内容忍超出限额的请求（限流穿透）。
// 回填完成后才把内存副本清空，两块状态的交接是完整的。
func (f *failover) probeLoop() {
	ticker := time.NewTicker(f.probe)
	defer ticker.Stop()
	for {
		select {
		case <-f.stopped:
			return
		case <-ticker.C:
			if f.useRedis() {
				continue
			}
			if err := f.redis.ping(); err != nil {
				continue
			}
			// 先回填再标记健康，避免回填过程中新请求又落到 Redis 的空 key 上。
			f.backfillMemoryToRedis()
			f.mu.Lock()
			f.healthy = true
			f.fails = 0
			f.mu.Unlock()
			log.Printf("✅ [Cache] Redis 已恢复，缓存后端已切回 Redis")
		}
	}
}

// backfillMemoryToRedis 把内存后端中仍然有效的条目合并写入 Redis。
//
// 合并策略按数据类型区分，避免「后写覆盖」把 Redis 里更新的值抹掉：
//   - 纯计数器（rl:*，十进制整数）：取两者最大值。限流计数只增不减，
//     取大值保证熔断期间累计的请求量不会被丢弃，也不会因覆盖而回退窗口；
//   - 其余键（CSRF/step-up/consent 令牌、一次性设备码等）：仅当 Redis 侧
//     不存在时才写入，绝不覆盖 Redis 中可能更新的值。
//
// 回填失败（Redis 又抖了）时保留内存副本，等待下一轮探测重试。
func (f *failover) backfillMemoryToRedis() {
	entries := f.mem.snapshot()
	if len(entries) == 0 {
		return
	}
	failed := false
	for _, it := range entries {
		ttl := time.Until(it.expires)
		if !it.expires.IsZero() && ttl <= 0 {
			continue // 已过期，无需回填
		}
		var err error
		if isCounterKey(it.key) {
			err = f.redis.mergeMaxCounter(it.key, it.value, ttl)
		} else {
			err = f.redis.setIfAbsent(it.key, it.value, ttl)
		}
		if err != nil {
			failed = true
			break
		}
	}
	if failed {
		// 保留内存副本，下一轮探测再试（此时状态未切换，读写仍走内存）。
		return
	}
	f.mem.clear()
	log.Printf("🔄 [Cache] 已将熔断期间的 %d 条内存缓存条目回填到 Redis", len(entries))
}

// isCounterKey 报告 key 是否是纯计数器（限流计数）。
// 限流键统一由 middleware.rateKey 加 "rl:" 前缀。
func isCounterKey(key string) bool {
	return strings.HasPrefix(key, "rl:")
}

func (f *failover) Get(ctx context.Context, key string) (string, bool) {
	if !f.useRedis() {
		return f.mem.Get(ctx, key)
	}
	v, ok, err := f.redis.get(ctx, key)
	if err != nil {
		f.recordFailure(err)
		return f.mem.Get(ctx, key)
	}
	f.recordSuccess()
	return v, ok
}

func (f *failover) Set(ctx context.Context, key string, value string, ttl time.Duration) {
	if !f.useRedis() {
		f.mem.Set(ctx, key, value, ttl)
		return
	}
	if err := f.redis.set(ctx, key, value, ttl); err != nil {
		// 写失败必须落到内存，否则这条数据会凭空消失
		// （熔断生效前写入 Redis 的尝试全部丢失）。
		f.recordFailure(err)
		f.mem.Set(ctx, key, value, ttl)
		return
	}
	f.recordSuccess()
}

func (f *failover) GetDel(ctx context.Context, key string) (string, bool) {
	if !f.useRedis() {
		return f.mem.GetDel(ctx, key)
	}
	v, ok, err := f.redis.getDel(ctx, key)
	if err != nil {
		f.recordFailure(err)
		return f.mem.GetDel(ctx, key)
	}
	f.recordSuccess()
	return v, ok
}

func (f *failover) Del(ctx context.Context, key string) {
	if !f.useRedis() {
		f.mem.Del(ctx, key)
		return
	}
	if err := f.redis.del(ctx, key); err != nil {
		f.recordFailure(err)
		f.mem.Del(ctx, key)
		return
	}
	f.recordSuccess()
}

// Incr 优先走 Redis；Redis 出错时先记一次失败，再用内存后端兜底，
// 保证调用方始终拿到真实计数而不是恒为 1（恒 1 会让限流放行一切）。
func (f *failover) Incr(ctx context.Context, key string) (int64, error) {
	if !f.useRedis() {
		return f.mem.Incr(ctx, key)
	}
	n, err := f.redis.incr(ctx, key)
	if err != nil {
		f.recordFailure(err)
		return f.mem.Incr(ctx, key)
	}
	f.recordSuccess()
	return n, nil
}

// IncrWithTTL 同 Incr：Redis 失败时回落到内存后端计数。
func (f *failover) IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if !f.useRedis() {
		return f.mem.IncrWithTTL(ctx, key, ttl)
	}
	n, err := f.redis.incrWithTTL(ctx, key, ttl)
	if err != nil {
		f.recordFailure(err)
		return f.mem.IncrWithTTL(ctx, key, ttl)
	}
	f.recordSuccess()
	return n, nil
}

func (f *failover) Expire(ctx context.Context, key string, ttl time.Duration) bool {
	if !f.useRedis() {
		return f.mem.Expire(ctx, key, ttl)
	}
	ok, err := f.redis.expire(ctx, key, ttl)
	if err != nil {
		f.recordFailure(err)
		return f.mem.Expire(ctx, key, ttl)
	}
	f.recordSuccess()
	return ok
}

// Stats 上报当前生效后端的规模，口径与 Kind 一致：熔断期间报内存后端，
// 否则报 Redis —— 与 Kind 说的必须是同一个后端，否则展示会自相矛盾。
func (f *failover) Stats() Stats {
	if !f.useRedis() {
		return f.mem.Stats()
	}
	return f.redis.Stats()
}

// Kind 反映当前实际生效的后端，便于运维从运行状态接口判断真实情况。
func (f *failover) Kind() string {
	if !f.useRedis() {
		return "memory(degraded)"
	}
	return "redis"
}

func (f *failover) Close() error {
	f.stopOnce.Do(func() { close(f.stopped) })
	// 内存兜底后端也持有后台清扫协程，必须一并停掉，否则 Close 后仍有 goroutine 常驻。
	_ = f.mem.Close()
	return f.redis.Close()
}
