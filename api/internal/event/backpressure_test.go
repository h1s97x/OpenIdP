package event

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestPublishDoesNotSpawnUnboundedGoroutines 验证派发协程数量有上限。
//
// 背景：此前 Publish 对「每个事件 × 每个监听器」各起一个 goroutine，
// 没有队列也没有上限。慢消费者（Webhook 投递卡住）叠加安全事件突发时，
// goroutine 会线性堆积，实测 1000 事件 × 5 监听器即产生 5000 个协程。
// 现在改为有界队列 + 按需派生：协程数不会超过队列容量。
func TestPublishDoesNotSpawnUnboundedGoroutines(t *testing.T) {
	release := make(chan struct{})
	b := New()
	defer b.Close()

	// 5 个监听器，全部阻塞，模拟下游变慢。
	for i := 0; i < 5; i++ {
		b.Subscribe("security.*", func(_ context.Context, _ Data) {
			<-release
		})
	}

	base := runtime.NumGoroutine()
	for i := 0; i < 2000; i++ {
		b.Publish(context.Background(), Data{Type: "security.auth.login"})
	}
	// 给派发协程一点启动时间。
	time.Sleep(100 * time.Millisecond)
	peak := runtime.NumGoroutine()

	// 上限是 worker 池大小，绝不可能等于「事件数 × 监听器数」（= 10000）。
	if peak-base > maxWorkers+32 {
		t.Fatalf("派发协程无上限：base=%d peak=%d（上限 %d）", base, peak, maxWorkers)
	}
	close(release)
	b.Close()
}

// TestPublishDropsWhenQueueFull 验证队列满时是「丢弃并计数」，而不是阻塞调用方。
// Publish 在登录等请求路径上被调用，阻塞会把背压传导到用户请求。
func TestPublishDropsWhenQueueFull(t *testing.T) {
	release := make(chan struct{})
	b := New()
	b.Subscribe("x", func(_ context.Context, _ Data) { <-release })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < defaultQueueSize*4; i++ {
			b.Publish(context.Background(), Data{Type: "x"})
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("队列满时 Publish 阻塞了调用方")
	}
	if b.Dropped() == 0 {
		t.Fatal("队列打满却没有任何丢弃计数，说明没有背压保护")
	}
	close(release)
	b.Close()
}

// TestPublishClonesPayload 验证各监听器拿到的是各自的 map 副本，
// 任一监听器（或调用方在 Publish 返回后）修改负载都不会污染其它监听器。
func TestPublishClonesPayload(t *testing.T) {
	b := New()
	defer b.Close()
	var mu sync.Mutex
	seen := map[string]string{}

	for i := 0; i < 2; i++ {
		name := "l" + string(rune('a'+i))
		b.Subscribe("e", func(_ context.Context, e Data) {
			mu.Lock()
			seen[name] = e.Payload["k"].(string)
			mu.Unlock()
		})
	}
	payload := map[string]any{"k": "before"}
	b.Publish(context.Background(), Data{Type: "e", Payload: payload})
	// 发布后立刻修改原 map：不应影响任何监听器。
	payload["k"] = "after"

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) == 2
	})
	mu.Lock()
	defer mu.Unlock()
	for k, v := range seen {
		if v != "before" {
			t.Fatalf("监听器 %s 观察到被外部修改的负载: %q", k, v)
		}
	}
}

// TestPublishAfterCloseIsSafe 关闭后继续 Publish 不应 panic 或阻塞。
func TestPublishAfterCloseIsSafe(t *testing.T) {
	b := New()
	b.Subscribe("x", func(_ context.Context, _ Data) {})
	b.Close()
	b.Publish(context.Background(), Data{Type: "x"})
	b.Close()
}

// TestSubscribedListenerStillReceivesEvents 保证改造后正常派发语义不变。
func TestSubscribedListenerStillReceivesEvents(t *testing.T) {
	b := New()
	defer b.Close()
	var n int
	var mu sync.Mutex
	b.Subscribe("a", func(_ context.Context, _ Data) { mu.Lock(); n++; mu.Unlock() })
	for i := 0; i < 50; i++ {
		b.Publish(context.Background(), Data{Type: "a"})
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return n == 50 })
}
