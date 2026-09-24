package cache

import (
	"context"
	"sync"
	"time"
)

// memory is a process-local cache with per-key TTL. It is the fallback backend
// used whenever Redis is unconfigured or unreachable.
//
// 回收策略有两层，缺一不可：
//  1. 惰性删除：Get/GetDel/Incr 命中过期条目时顺手删掉；
//  2. 后台清扫：newMemory 启动一个定时器定期遍历删除过期条目。
//
// 只有惰性删除时，写入后不再被同一个 key 访问的条目会永久驻留：限流键
// （rl:<name>:<ip> / rl:acct:<login>）的维度由请求方控制，唯一值可以无限增长，
// 实测 100 万个限流键即占用约 150MB，长期运行必然 OOM。
// 后台清扫让内存占用与「活跃 key 数」相关，而不是与「历史写入过的 key 数」相关。
type memory struct {
	mu    sync.RWMutex
	items map[string]*memItem

	// 一旦达到条目上限就立即触发一轮清扫，避免清扫周期内的写入尖峰把内存打满。
	maxItems int

	stopOnce sync.Once
	stopped  chan struct{}
}

type memItem struct {
	value   string
	expires time.Time // zero => never expires
}

const (
	// memorySweepInterval 是后台清扫周期。取值权衡：太短会空转消耗 CPU，
	// 太长则过期条目在内存里多留一会儿。限流窗口通常在分钟级，1 分钟足够。
	memorySweepInterval = time.Minute
	// memoryMaxItems 是内存后端的软上限。达到后立即清扫一次；
	// 清扫仍无法压到上限以下（大量未过期 key）时不再强行淘汰，
	// 避免误删仍在有效期的限流计数/CSRF 令牌。
	memoryMaxItems = 200_000
)

// newMemory creates an empty in-memory cache with a background expiry sweeper.
func newMemory() *memory {
	m := &memory{
		items:    make(map[string]*memItem),
		maxItems: memoryMaxItems,
		stopped:  make(chan struct{}),
	}
	go m.sweepLoop()
	return m
}

// sweepLoop 周期性删除已过期条目，直到 Close 被调用。
func (m *memory) sweepLoop() {
	ticker := time.NewTicker(memorySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopped:
			return
		case <-ticker.C:
			m.sweepExpired()
		}
	}
}

// sweepExpired 删除所有已过期条目，返回删除数量。
func (m *memory) sweepExpired() int {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, it := range m.items {
		if !it.expires.IsZero() && now.After(it.expires) {
			delete(m.items, k)
			n++
		}
	}
	return n
}

// maybeSweepLocked 在条目数触达上限时同步清扫一轮，抑制写入尖峰。
// 必须在持有写锁时调用（由 Set/Incr 内部触发）。
func (m *memory) maybeSweepLocked() {
	if m.maxItems <= 0 || len(m.items) < m.maxItems {
		return
	}
	now := time.Now()
	for k, it := range m.items {
		if !it.expires.IsZero() && now.After(it.expires) {
			delete(m.items, k)
		}
	}
}

func (m *memory) Get(_ context.Context, key string) (string, bool) {
	m.mu.RLock()
	it, ok := m.items[key]
	m.mu.RUnlock()
	if !ok {
		return "", false
	}
	if !it.expires.IsZero() && time.Now().After(it.expires) {
		m.mu.Lock()
		delete(m.items, key)
		m.mu.Unlock()
		return "", false
	}
	return it.value, true
}

func (m *memory) Set(_ context.Context, key, value string, ttl time.Duration) {
	it := &memItem{value: value}
	if ttl > 0 {
		it.expires = time.Now().Add(ttl)
	}
	m.mu.Lock()
	m.items[key] = it
	m.maybeSweepLocked()
	m.mu.Unlock()
}

// GetDel 原子地读取并删除（同一把锁内完成，避免并发下重复消费）。
func (m *memory) GetDel(_ context.Context, key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[key]
	if !ok {
		return "", false
	}
	if !it.expires.IsZero() && time.Now().After(it.expires) {
		delete(m.items, key)
		return "", false
	}
	delete(m.items, key)
	return it.value, true
}

func (m *memory) Del(_ context.Context, key string) {
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
}

func (m *memory) Incr(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.incrLocked(key, 0), nil
}

// IncrWithTTL 在同一把锁内完成自增与 TTL 设置，等价于 Redis 侧的单命令原子实现。
func (m *memory) IncrWithTTL(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.incrLocked(key, ttl), nil
}

// incrLocked 自增计数。ttl > 0 时仅在计数器新建或窗口已过期时设置过期时间，
// 与 Redis 后端的固定窗口语义保持一致：窗口内继续自增不会延长窗口，
// 否则限流窗口会被每次请求不断往后推，永远失效。
func (m *memory) incrLocked(key string, ttl time.Duration) int64 {
	it, ok := m.items[key]
	expired := ok && !it.expires.IsZero() && time.Now().After(it.expires)
	if !ok || expired {
		n := &memItem{value: "1"}
		if ttl > 0 {
			n.expires = time.Now().Add(ttl)
		}
		m.items[key] = n
		m.maybeSweepLocked()
		return 1
	}
	var n int64
	for _, r := range it.value {
		if r < '0' || r > '9' {
			n = 0
			break
		}
		if n < (1<<62)/10 {
			n = n*10 + int64(r-'0')
		}
	}
	n++
	it.value = itrconv(n)
	return n
}

func (m *memory) Expire(_ context.Context, key string, ttl time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[key]
	if !ok {
		return false
	}
	if ttl > 0 {
		it.expires = time.Now().Add(ttl)
	} else {
		it.expires = time.Time{}
	}
	return true
}

// snapshot 返回当前仍然有效的条目副本（过滤掉已过期项），
// 供 failover 在 Redis 恢复后回填。返回的 expires 是绝对时间，调用方自行换算 TTL。
func (m *memory) snapshot() []memSnapshot {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]memSnapshot, 0, len(m.items))
	for k, it := range m.items {
		if !it.expires.IsZero() && now.After(it.expires) {
			continue
		}
		out = append(out, memSnapshot{key: k, value: it.value, expires: it.expires})
	}
	return out
}

// memSnapshot 是回填用的一条内存条目。
type memSnapshot struct {
	key     string
	value   string
	expires time.Time
}

// clear 清空所有条目（回填成功后交接状态）。
func (m *memory) clear() {
	m.mu.Lock()
	m.items = make(map[string]*memItem)
	m.mu.Unlock()
}

// Stats 上报条目数与近似占用：只累加键与值的字节长度，不含 map 桶、
// 结构体头与指针开销，因此是偏小的下限值（展示时标注"≈"）。
// 这里不做过期过滤：清扫周期内最多残留一分钟的过期条目，量级可忽略。
func (m *memory) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Stats{Entries: len(m.items)}
	for k, it := range m.items {
		st.Bytes += int64(len(k) + len(it.value))
	}
	return st
}

func (m *memory) Kind() string { return "memory" }

// Close 停掉后台清扫协程。可重复调用。
func (m *memory) Close() error {
	m.stopOnce.Do(func() { close(m.stopped) })
	return nil
}

// resident 返回当前驻留的条目数（测试用）。
func (m *memory) resident() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// itrconv converts a non-negative int64 to its decimal string.
func itrconv(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
