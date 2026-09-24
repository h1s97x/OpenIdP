// Package cache provides a uniform caching abstraction with automatic
// degradation: it uses Redis when reachable and transparently falls back to a
// process-local in-memory store otherwise. It backs the token store, rate
// limiters, OAuth consent tickets and GeoIP API results.
//
// Choosing a backend:
//
//	New(addr, password, db) tries to connect to Redis at addr. When addr is
//	empty or the connection/ping fails it returns a memory-backed cache and
//	records the reason in the returned log message (only for diagnostics).
//
// 运行期降级：New 成功连上 Redis 后返回 failover 包装，它同时持有 Redis 与
// 内存两个后端。当 Redis 在运行中宕机（而非仅启动时不通）时，连续失败达到阈值
// 即熔断并切到内存后端，后台协程周期性探测 Redis，恢复后自动切回。
// 没有这一层，Redis 死后限流计数会取不到值而使防爆破形同虚设。
package cache

import (
	"context"
	"time"
)

// Cache is the minimal set of operations shared by the in-memory and Redis
// backends. All methods are safe for concurrent use.
type Cache interface {
	// Get returns the value stored under key and whether it was present and
	// not expired.
	Get(ctx context.Context, key string) (string, bool)
	// Set stores value under key with the given TTL. A zero TTL never expires.
	Set(ctx context.Context, key string, value string, ttl time.Duration)
	// GetDel atomically returns and removes the value stored under key.
	// 用于一次性 token / consent ticket 的原子消费，避免并发重放。
	GetDel(ctx context.Context, key string) (string, bool)
	// Del removes a key if present.
	Del(ctx context.Context, key string)
	// Incr atomically increments the integer stored under key and returns the
	// new value. A missing key starts at 1.
	// 返回错误而非静默返回 1：调用方（限流器）据此决定 fail-closed，
	// 否则计数取不到值会让限流恒为放行。
	Incr(ctx context.Context, key string) (int64, error)
	// IncrWithTTL atomically increments the counter under key and, when the
	// counter is created (or its TTL already gone), sets ttl in the same
	// operation. 限流必须用它而非 Incr+Expire：后者在多实例并发下会把窗口
	// 反复重置为 1，导致限流形同虚设。
	IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// Expire sets a TTL on an existing key. It reports whether the key existed.
	Expire(ctx context.Context, key string, ttl time.Duration) bool
	// Kind returns "redis" or "memory", used for logging.
	Kind() string
	// Close releases any background resources held by the backend.
	Close() error
}

// Stats 描述缓存后端的当前规模（管理端「数据与运维 → 数据清理」展示缓存占用）。
//
// Bytes 只在能如实归因时才给：内存后端是键与值的字节长度之和（近似堆占用）；
// Redis 无法按 DB 归因内存（INFO memory 是整个实例的 used_memory），故留 0，
// 由调用方只展示键数 —— 在共享实例上报一个"看起来是缓存占用、实际是整实例"的
// 数字比不报更容易误导。
type Stats struct {
	Entries int   `json:"entries"`
	Bytes   int64 `json:"bytes"`
}

// StatsReporter 是可选的规模上报能力，不并入 Cache 接口：规模上报只服务于运维
// 展示，为它强制所有后端（含测试替身）实现一个方法并不划算。
// 调用方用类型断言取用，取不到就只展示后端类型。
type StatsReporter interface {
	Stats() Stats
}

// Options describes how to reach the shared (Redis) store.
type Options struct {
	Addr     string
	Password string
	DB       int
	// PingTimeout bounds how long we wait while probing Redis availability.
	PingTimeout time.Duration
	// DialTimeout bounds the initial TCP connection attempt.
	DialTimeout time.Duration
	// FailureThreshold 连续失败达到该次数即熔断并切到内存后端。
	FailureThreshold int
	// ProbeInterval 熔断后探测 Redis 是否恢复的间隔。
	ProbeInterval time.Duration
}

// effectivePingTimeout 返回探测 Redis 用的超时（未配置时用内置默认值）。
func (o Options) effectivePingTimeout() time.Duration {
	if o.PingTimeout > 0 {
		return o.PingTimeout
	}
	return 2 * time.Second
}

// New builds a Cache. It probes Redis when Addr is non-empty; on any failure it
// degrades to the in-memory backend. The returned Cache is always non-nil and
// safe to use even if Redis is down (the backend is memory).
//
// Redis 可用时返回带熔断的 failover 包装：运行中 Redis 宕机会自动切内存，
// 恢复后自动切回，调用方无需感知。
func New(o Options) (Cache, string) {
	if o.Addr == "" {
		return newMemory(), "Redis 未配置（REDIS_ADDR 为空）→ 使用内存缓存"
	}
	rc, err := newRedis(o)
	if err != nil {
		return newMemory(), "Redis 连接失败：" + err.Error() + " → 降级为内存缓存"
	}
	return newFailover(rc, o), "Redis 已启用（运行中中断将自动切换内存缓存）"
}

// NewMemory returns a process-local cache. 它用于 Redis 不可用时兜底
// （例如 passkey 仪式状态），而不是让调用方各自实现一个 map。
func NewMemory() Cache { return newMemory() }
