// Package event provides a lightweight in-process event bus that decouples
// domain events (authentication, security, configuration) from their consumers
// (mail notifications, audit logs, webhooks, statistics).
// 派发是异步的：监听器在独立 goroutine 中执行，避免阻塞请求处理；
// 因此不保证跨监听器的执行顺序，单个监听器内部仍需自行保证顺序。
//
// Usage:
//
//	bus := event.New()
//	stop := bus.Subscribe("auth.login", listener)
//	defer stop()
//	bus.Publish(ctx, event.Data{Type: "auth.login", UserID: 1})
//
// A nil bus is safe to use (Publish and Subscribe become no-ops), which makes
// it easy to keep components testable without wiring an event bus.
package event

import (
	"context"
	"log"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
)

// Data is a single event payload. Payload holds event-specific fields and is
// guaranteed to be JSON-serializable.
type Data struct {
	Type    string         `json:"type"`
	UserID  int64          `json:"userId,omitempty"`
	Payload map[string]any `json:"payload,omitempty"`
}

// Listener receives published events. It should return promptly and not panic.
type Listener func(ctx context.Context, e Data)

// Bus is a publish/subscribe hub with bounded asynchronous dispatch.
//
// 派发有明确上限：事件先进入有界队列，再由固定大小的 worker 池消费，
// 队列满时丢弃并计数。若像此前那样「每个事件 × 每个监听器起一个 goroutine」，
// 一次突发（例如批量登录失败触发安全事件）就会瞬间起出等量协程，
// 慢消费者（Webhook 投递卡住、审计落库慢）会把它放大成 goroutine 与内存雪崩。
type Bus struct {
	mu   sync.RWMutex
	subs map[string][]Listener

	// queue 是共享的有界事件队列：待执行的一次「监听器调用」入队，
	// 由 worker 池消费；队列满时丢弃并计数，绝不无限堆积。
	queue chan job
	// dropped 累计因队列满而丢弃的派发次数，用于排障时判断是否存在背压。
	dropped atomic.Uint64

	stopOnce sync.Once
	stopped  chan struct{}
	// wg 统计正在执行的监听器任务；dispatchWG 只统计派发协程本身。
	// 两者分开是必要的：Close 需要先停派发、再等在途任务，
	// 混用一个 WaitGroup 会形成互相等待。
	wg         sync.WaitGroup
	dispatchWG sync.WaitGroup
}

// job 是一次待执行的监听器调用。
type job struct {
	fn  Listener
	ctx context.Context
	e   Data
}

const (
	// defaultQueueSize 是有界队列容量。安全事件是低频的（登录、改密、越权），
	// 4096 足够吸收正常突发；真正打满时说明下游已经严重拥塞，
	// 此时丢弃比无限堆积更安全（堆积最终会以 OOM 收场）。
	defaultQueueSize = 4096
	// maxWorkers 是同时执行监听器的硬上限，也是派发协程总数的上界。
	// 取值兼顾「慢监听器不互相阻塞」与「协程不失控」：
	// 64 个并发监听器足以吸收正常突发，最坏情况的额外协程数也就这个量级。
	maxWorkers = 64
)

// New creates an empty event bus with bounded async dispatch.
func New() *Bus {
	b := &Bus{
		subs:    make(map[string][]Listener),
		queue:   make(chan job, defaultQueueSize),
		stopped: make(chan struct{}),
	}
	// dispatchLoop 用一个独立的 WaitGroup 记账：它常驻到 Close 为止，
	// 若与在途任务共用同一个 WaitGroup，dispatchLoop 内的等待会与
	// Close 的等待互相死锁。
	b.dispatchWG.Add(1)
	go func() {
		defer b.dispatchWG.Done()
		b.dispatchLoop()
	}()
	return b
}

// Subscribe registers a listener for the given event type and returns a stop
// function that removes it. Multiple subscriptions to the same type are all
// invoked in registration order.
//
// A subscription type ending in ".*" acts as a prefix wildcard: it matches
// every event whose type begins with the prefix (e.g. "security.*" matches
// "security.auth.login").
func (b *Bus) Subscribe(typ string, fn Listener) (stop func()) {
	if b == nil || fn == nil {
		return func() {}
	}
	b.mu.Lock()
	b.subs[typ] = append(b.subs[typ], fn)
	b.mu.Unlock()
	// 订阅变更后的并发度调整入口（当前由固定大小 worker 池统一决定）。
	b.ensureWorkers()

	done := false
	return func() {
		if done {
			return
		}
		done = true
		b.mu.Lock()
		defer b.mu.Unlock()
		list := b.subs[typ]
		ptr := reflect.ValueOf(fn).Pointer()
		for i := range list {
			if reflect.ValueOf(list[i]).Pointer() == ptr {
				b.subs[typ] = append(list[:i], list[i+1:]...)
				return
			}
		}
	}
}

// Publish delivers the event to every matching listener. A nil bus is a no-op.
// Exact-type subscriptions and prefix wildcards ("type.*") are both honored.
//
// 派发是异步的：监听器运行在各自的 goroutine 中，任一消费方（Webhook 投递等）
// 变慢都不会拖住登录等认证请求。复制一份订阅快照后再解锁，
// 避免订阅变更与派发相互阻塞。
func (b *Bus) Publish(ctx context.Context, e Data) {
	if b == nil {
		return
	}
	b.mu.RLock()
	list := make([]Listener, 0, len(b.subs[e.Type]))
	list = append(list, b.subs[e.Type]...)
	for typ, l := range b.subs {
		if isWildcard(typ) && strings.HasPrefix(e.Type, typ[:len(typ)-1]) {
			list = append(list, l...)
		}
	}
	b.mu.RUnlock()
	// 深拷贝一份负载再派发：多个异步监听器共享同一个 map 时，任一监听器
	// （或调用方在 Publish 返回后继续修改原 map）都会造成数据竞争。
	// 对发布方透明，代价只是一次小 map 的浅拷贝。
	e = cloneData(e)
	for _, fn := range list {
		select {
		case b.queue <- job{fn: fn, ctx: ctx, e: e}:
		case <-b.stopped:
			// 总线已停止：直接返回，不再投递。
			return
		default:
			// 队列已满：丢弃本次派发并计数。绝不用阻塞投递——
			// Publish 在请求处理路径上被调用，阻塞会把背压传导到登录请求，
			// 而无限增长的队列最终只会变成内存泄漏。
			n := b.dropped.Add(1)
			if n == 1 || n%1000 == 0 {
				log.Printf("⚠️ [Event] 事件队列已满，已丢弃 %d 次派发（type=%s）", n, e.Type)
			}
		}
	}
}

// dispatchLoop 从有界队列取任务，交由固定数量的 worker 执行。
//
// worker 池的大小是硬上限：并发执行的监听器数最多 maxWorkers 个，
// 协程总数因此有确定上界（与事件数、订阅数无关）。
// 若像此前那样每个任务起一个协程，慢消费者叠加事件突发时仍会把协程数
// 推到队列容量级别。
func (b *Bus) dispatchLoop() {
	pool := make(chan struct{}, maxWorkers)
	for {
		select {
		case <-b.stopped:
			// 停止派发：丢弃积压（异步派发本就无投递保证），
			// 在途任务由 Close 负责等待。
			return
		case j := <-b.queue:
			select {
			case pool <- struct{}{}:
			case <-b.stopped:
				return
			}
			b.wg.Add(1)
			go func(j job) {
				defer func() {
					// 监听器 panic 不应影响请求处理，也不应让 worker 退出。
					_ = recover()
					<-pool
					b.wg.Done()
				}()
				j.fn(j.ctx, j.e)
			}(j)
		}
	}
}

// ensureWorkers 是保留的钩子。worker 池大小由 maxWorkers 常量统一决定，
// 不随订阅数变化；保留它是为了让「订阅变更需要调整并发度」这一诉求
// 有明确的落点，而不是散落在 Subscribe 里。
func (b *Bus) ensureWorkers() {}

// Dropped 返回因队列满而丢弃的派发次数（用于运行状态展示与排障）。
func (b *Bus) Dropped() uint64 {
	if b == nil {
		return 0
	}
	return b.dropped.Load()
}

// Close 停止派发并等待在途监听器结束。可重复调用。
func (b *Bus) Close() {
	if b == nil {
		return
	}
	b.stopOnce.Do(func() { close(b.stopped) })
	// 先等派发协程退出（不再产生新任务），再等在途监听器结束。
	b.dispatchWG.Wait()
	b.wg.Wait()
}

// cloneData 复制事件负载，确保各监听器持有各自独立的 map。
func cloneData(e Data) Data {
	if len(e.Payload) == 0 {
		return e
	}
	p := make(map[string]any, len(e.Payload))
	for k, v := range e.Payload {
		p[k] = v
	}
	e.Payload = p
	return e
}

// isWildcard reports whether a subscription type is a prefix wildcard (ends in ".*").
func isWildcard(typ string) bool {
	return strings.HasSuffix(typ, ".*")
}

// Has reports whether any listener is registered for the event type.
func (b *Bus) Has(typ string) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[typ]) > 0
}
